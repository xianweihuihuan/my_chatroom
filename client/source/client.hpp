#pragma once
#include <arpa/inet.h>
#include <gflags/gflags.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/eventfd.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include "Buffer.h"
#include "Socket.h"
#include "chat.pb.h"
#include "file.pb.h"

#define Tail "\033[m"
#define Cyan "\033[0m\033[1;36m"
#define Yellow "\033[0m\033[1;33m"
#define Green "\033[0m\033[1;32m"
#define Red "\033[0m\033[1;31m"

Xianwei::Buffer buffer;
SSL_CTX* ctx;
bool ifrunning = true;
int vcodefd;
int selfefd;
int friendefd;
int groupefd;
bool vsuccess;
bool groupsuccess;
bool friendsuccess;
bool selfsuccess;
SSL* ssl;
bool deletefriend = false;
bool cancelgroup = false;
std::string vid;
std::string vcode;
std::string uid;
std::string uemail;
std::mutex iolock;
std::mutex sendfileidlock;
std::mutex getfilelock;
std::string send_file_id;
std::string get_file_id;
std::string file_ip;
bool filexist;
std::string file_dir;
std::atomic<bool> running{true};
std::vector<Xianwei::UserInfo> friend_apply;
std::vector<Xianwei::UserInfo> session_apply;
std::vector<Xianwei::UserInfo> friend_list;
std::vector<Xianwei::GroupInfo> group_list;
std::vector<Xianwei::MemberInfo> member_list;
namespace Xianwei {
bool Check_nickname(const std::string& nickname) {
  return nickname.size() < 22;
}

bool Check_password(const std::string& password) {
  return (password.size() > 6 && password.size() < 15);
}

bool Check_email(const std::string& address) {
  std::regex reg(R"(^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$)");
  std::smatch mat;
  return std::regex_match(address, mat, reg);
}

void SendToServer(const std::string body) {
  std::string message = std::to_string(body.size()) + "\r\n" + body;
  int i = SSL_write(ssl, message.c_str(), message.size());
}

void Print() {
  std::cout << "\033[0m\033[1;36m"
            << "    __  ____  _____    _   __   __  ____  __   _  ____  _____  "
               "  _   __"
            << std::endl;
  std::cout << "   / / / / / / /   |  / | / /   \\ \\/ / / / /  | |/ / / / /   "
               "|  / | / /"

            << std::endl;
  std::cout << "  / /_/ / / / / /| | /  |/ /     \\  / / / /   |   / / / / /| "
               "| /  |/ / "
            << std::endl;
  std::cout << " / __  / /_/ / ___ |/ /|  /      / / /_/ /   /   / /_/ / ___ "
               "|/ /|  / "
            << std::endl;
  std::cout << "/_/ /_/\\____/_/  |_/_/ |_/      /_/\\____/   /_/|_\\____/_/  "
               "|_/_/ |_/ "
            << "\033[0m" << std::endl;
}

void WakeUpEventFd(int event_fd) {
  uint64_t one = 1;
  ssize_t n = write(event_fd, &one, sizeof(one));
  if (n != sizeof(one)) {
    LOG_ERROR("写入 eventfd 失败，应写 {} 字节，实际写了 {}", sizeof(one), n);
  }
}

void ReadEventfd(int event_fd) {
  uint64_t one = 0;
  ssize_t n = read(event_fd, &one, sizeof(one));
  if (n != sizeof(one)) {
    LOG_ERROR("读取 eventfd 失败，应读 {} 字节，实际读了 {}", sizeof(one), n);
  }
}

void UserRegister() {
  std::string nickname;
  std::string password;
  std::string email;
  std::cout << Yellow << "请输入你的昵称：";
  std::cin.clear();
  std::cin >> nickname;
  std::cout << Tail;
  while (!Check_nickname(nickname)) {
    nickname.clear();
    std::cout << Red << "用户名过长，请重新输入：" << Tail << Yellow;
    std::cin.clear();
    std::cin >> nickname;
    std::cout << Tail;
  }
  std::cout << Yellow << "请输入密码(7~14位)：";
  std::cin.clear();
  std::cin >> password;
  std::cout << Tail;
  while (!Check_password(password)) {
    password.clear();
    std::cout << Red << "密码不在要求范围内，请重新输入：" << Tail << Yellow;
    std::cin.clear();
    std::cin >> password;
    std::cout << Tail;
  }
  std::cout << Yellow << "请输入邮箱：";
  std::cin.clear();
  std::cin >> email;
  std::cout << Tail;
  while (!Check_email(email)) {
    email.clear();
    std::cout << Red << "邮箱不合法，请重新输入：" << Tail << Yellow;
    std::cin.clear();
    std::cin >> email;
    std::cout << Tail;
  }
  Xianwei::ServerMessage req;
  req.set_type(ServerMessageType::EmailVcodeReqType);
  req.mutable_email_verify_code_req()->set_email(email);
  SendToServer(req.SerializeAsString());
  while (true) {
    char buf[10000];
    int sz = SSL_read(ssl, buf, sizeof(buf));
    buffer.WriteAndPush(buf, sz);
    // 1) 尝试获取一行（包含 "\r\n"）；若没有完整行则退出
    std::string lenLine = buffer.GetLine();
    if (lenLine.empty()) {
      // 缓冲区中还没读到 CRLF 结束的长度行
      continue;
    }
    // lenLine 形如 "123\r\n"，长度 = lenLine.size()
    // 2) 解析消息体长度（去掉末尾 "\r\n"）
    int bodyLen = 0;
    try {
      bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
    } catch (...) {
      // 非法长度，直接断开连接
      buffer.Clear();

      return;
    }
    // 3) 若缓冲区中还没收到完整消息体，则保留长度行，等待更多数据
    if (buffer.ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen)) {
      continue;
    }
    // 4) 消费掉长度行
    buffer.MoveReadIndex(lenLine.size());
    // 5) 读取并弹出 bodyLen 字节的 protobuf 数据
    std::string data = buffer.ReadAsStringAndPop(bodyLen);
    // 6) 反序列化并分发
    ClientMessage msg;
    if (!msg.ParseFromString(data)) {
      // 解析失败，丢弃并继续
      continue;
    }
    if (msg.type() != ClientMessageType::EmailVcodeRspType) {
      continue;
    }
    auto& vcode_rsp = msg.email_verify_code_rsp();
    if (!vcode_rsp.success()) {
      std::cout << Red << vcode_rsp.errmsg() << "退出" << Tail << std::endl;
      return;
    }
    vid = vcode_rsp.verify_code_id();
    break;
  }
  std::cout << Yellow << "请输入验证码：";
  std::cin.clear();
  std::cin >> vcode;
  std::cout << Tail;
  Xianwei::ServerMessage regreq;
  regreq.set_type(ServerMessageType::UserRegisterReqType);
  regreq.mutable_user_register_req()->set_nickname(nickname);
  regreq.mutable_user_register_req()->set_password(password);
  regreq.mutable_user_register_req()->set_email(email);
  regreq.mutable_user_register_req()->set_verify_code_id(vid);
  regreq.mutable_user_register_req()->set_verify_code(vcode);
  SendToServer(regreq.SerializeAsString());
  while (true) {
    char buf[10000];
    int sz = SSL_read(ssl, buf, sizeof(buf));
    buffer.WriteAndPush(buf, sz);
    std::string lenLine = buffer.GetLine();
    if (lenLine.empty()) {
      continue;
    }
    int bodyLen = 0;
    try {
      bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
    } catch (...) {
      buffer.Clear();
      return;
    }
    if (buffer.ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen)) {
      continue;
    }
    buffer.MoveReadIndex(lenLine.size());
    std::string data = buffer.ReadAsStringAndPop(bodyLen);
    ClientMessage regmsg;
    if (!regmsg.ParseFromString(data)) {
      continue;
    }
    if (regmsg.type() != ClientMessageType::UserRegisterRspType) {
      continue;
    }
    auto& rsp = regmsg.user_register_rsp();
    if (rsp.success()) {
      std::cout << Green << "注册成功" << Tail << std::endl;
      vid.clear();
      vcode.clear();
      std::this_thread::sleep_for(std::chrono::seconds(1));
    } else {
      if (rsp.errmsg() == "验证码错误") {
        vcode.clear();
        std::cout << Red << "验证码错误，请重新输入：" << Tail << Yellow;
        std::cin.clear();
        std::cin >> vcode;
        std::cout << Tail;
        regreq.mutable_user_register_req()->set_verify_code(vcode);
        SendToServer(regreq.SerializeAsString());
        continue;
      } else {
        std::cout << Red << rsp.errmsg() << "，失败退出\n" << Tail;
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    }
    break;
  }
}

void HandleMessage(const ClientMessage& msg) {
  switch (msg.type()) {
    case ClientMessageType::SetNicknameRspType:
      if (msg.set_user_nickname_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "修改昵称成功\n" << Tail;
        }
      }
      if (!msg.set_user_nickname_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "修改失败，原因："
                    << msg.set_user_nickname_rsp().errmsg() << Tail
                    << std::endl;
        }
      }
      WakeUpEventFd(selfefd);
      break;
    case ClientMessageType::GetUserInfoRspType:
      if (msg.get_user_info_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "获取个人信息成功\n" << Tail;
          std::cout << Yellow << "uid："
                    << msg.get_user_info_rsp().user_info().user_id()
                    << std::endl
                    << "昵称："
                    << msg.get_user_info_rsp().user_info().nickname()
                    << std::endl
                    << "邮箱：" << msg.get_user_info_rsp().user_info().email()
                    << Tail << std::endl;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "获取个人信息失败，原因："
                    << msg.get_user_info_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(selfefd);
      break;
    case ClientMessageType::FriendLoginNoticeType: {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow << "[通知]：你的好友"
                << msg.friend_login_notice().name() << "已上线" << Tail
                << std::endl;
    } break;
    case ClientMessageType::EmailVcodeRspType:
      if (!msg.email_verify_code_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << msg.email_verify_code_rsp().errmsg() << "退出"
                    << Tail << std::endl;
          vsuccess = false;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "获取验证码成功" << Tail << std::endl;
        }
        vid = msg.email_verify_code_rsp().verify_code_id();
        vsuccess = true;
      }
      WakeUpEventFd(vcodefd);
      break;
    case ClientMessageType::SetEmailRspType:
      if (msg.set_user_email_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "修改邮箱成功\n" << Tail;
        }
        vsuccess = true;
        selfsuccess = true;
        WakeUpEventFd(selfefd);
      } else {
        if (msg.set_user_email_rsp().errmsg() == "验证码错误") {
          vsuccess = false;
          selfsuccess = false;
          WakeUpEventFd(selfefd);
        } else {
          {
            std::unique_lock<std::mutex> mtx(iolock);
            std::cout << Red << "修改邮箱信息失败，原因："
                      << msg.set_user_email_rsp().errmsg() << Tail << std::endl;
          }
          vsuccess = true;
          selfsuccess = false;
          WakeUpEventFd(selfefd);
        }
      }
      break;
    case ClientMessageType::SetPasswordRspType:
      if (msg.set_user_password_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "修改密码成功\n" << Tail;
        }
        vsuccess = true;
        selfsuccess = true;
        WakeUpEventFd(selfefd);
      } else {
        if (msg.set_user_password_rsp().errmsg() == "验证码错误") {
          vsuccess = false;
          selfsuccess = false;
          WakeUpEventFd(selfefd);
        } else {
          {
            std::unique_lock<std::mutex> mtx(iolock);
            std::cout << Red << "修改密码信息失败，原因："
                      << msg.set_user_password_rsp().errmsg() << Tail
                      << std::endl;
          }
          vsuccess = true;
          selfsuccess = false;
          WakeUpEventFd(selfefd);
        }
      }
      break;
    case ClientMessageType::EmailFriendAddRspType:
      if (msg.email_friend_add_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "发送好友申请成功" << Tail << std::endl;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "发送好友申请失败，原因："
                    << msg.email_friend_add_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::NicknameFriendAddRspType:
      if (msg.nickname_friend_add_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "发送好友申请成功" << Tail << std::endl;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "发送好友申请失败，原因："
                    << msg.nickname_friend_add_rsp().errmsg() << Tail
                    << std::endl;
        }
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::GetFriendApplyRsptype:
      if (msg.get_friend_apply_rsp().success()) {
        friend_apply.clear();
        for (int i = 0; i < msg.get_friend_apply_rsp().user_info_size(); ++i) {
          friend_apply.emplace_back(msg.get_friend_apply_rsp().user_info(i));
        }
        friendsuccess = true;
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << msg.get_friend_apply_rsp().errmsg() << Tail
                    << std::endl;
        }
        friendsuccess = false;
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::GetFriendListRspType:
      if (msg.get_friend_list_rsp().success()) {
        friend_list.clear();
        for (int i = 0; i < msg.get_friend_list_rsp().friend_list_size(); ++i) {
          friend_list.emplace_back(msg.get_friend_list_rsp().friend_list(i));
        }
        friendsuccess = true;
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << msg.get_friend_list_rsp().errmsg() << Tail
                    << std::endl;
        }
        friendsuccess = false;
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::SovelFriendApplyRspType:
      if (msg.sovel_friend_apply_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "处理好友申请事件成功" << Tail << std::endl;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "处理好友申请事件失败，原因："
                    << msg.sovel_friend_apply_rsp().errmsg() << Tail
                    << std::endl;
        }
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::IgnoreFriendRspType:
      if (msg.ignore_friend_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "屏蔽好友成功" << Tail << std::endl;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "屏蔽好友失败，原因："
                    << msg.ignore_friend_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::UnIgnoreFriendRspType:
      if (msg.unignore_friend_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "解除好友屏蔽成功" << Tail << std::endl;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "解除好友屏蔽失败，原因："
                    << msg.unignore_friend_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::GetFriendInfoRepType:
      if (msg.get_friend_info_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "获取好友信息成功\n" << Tail;
          std::cout << Yellow << "uid："
                    << msg.get_friend_info_rsp().friend_info().user_id()
                    << std::endl
                    << "昵称："
                    << msg.get_friend_info_rsp().friend_info().nickname()
                    << std::endl
                    << "邮箱："
                    << msg.get_friend_info_rsp().friend_info().email() << Tail
                    << std::endl;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "获取好友信息失败，原因："
                    << msg.get_friend_info_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::FriendSendMessageRspType:
      if (msg.friend_send_message_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "发送成功" << Tail << std::endl;
        }
      } else {
        {
          if (msg.friend_send_message_rsp().errmsg() == "这不是你的好友") {
            deletefriend = true;
          }
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "发送失败，原因："
                    << msg.friend_send_message_rsp().errmsg() << Tail
                    << std::endl;
        }
      }
      // WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::FriendMessageNoticeType: {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow;
      printf("[好友][%10s]", msg.friend_message_notice().friend_name().c_str());
      if (msg.friend_message_notice().message_type() == MessageType::file) {
        printf("[文件]:%s", msg.friend_message_notice().body().c_str());
      } else if (msg.friend_message_notice().message_type() ==
                 MessageType::string) {
        printf("[消息]:%s", msg.friend_message_notice().body().c_str());
      }
      std::cout << Tail << std::endl;
    } break;
    case ClientMessageType::DeleteFriendRspType:
      if (msg.delete_friend_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "删除好友成功" << Tail << std::endl;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "删除好友失败，原因："
                    << msg.delete_friend_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::FriendHistoryMessageRspType:
      if (msg.friend_history_message_rsp().success()) {
        {
          {
            std::unique_lock<std::mutex> mtx(iolock);
            std::cout << Green << "获取历史消息成功" << Tail << std::endl;
            for (int i = 0; i < msg.friend_history_message_rsp().message_size();
                 ++i) {
              std::cout << Yellow;
              printf("[好友][%10s]", msg.friend_history_message_rsp()
                                         .message(i)
                                         .friend_name()
                                         .c_str());
              if (msg.friend_history_message_rsp().message(i).message_type() ==
                  MessageType::file) {
                printf(
                    "[文件]:%s\n",
                    msg.friend_history_message_rsp().message(i).body().c_str());
              } else if (msg.friend_history_message_rsp()
                             .message(i)
                             .message_type() == MessageType::string) {
                printf(
                    "[消息]:%s\n",
                    msg.friend_history_message_rsp().message(i).body().c_str());
              }
            }
          }
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "获取好友历史消息失败，原因："
                    << msg.friend_history_message_rsp().errmsg() << Tail
                    << std::endl;
        }
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::FriendSendFileRspType:
      if (msg.friend_send_file_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(sendfileidlock);
          send_file_id = msg.friend_send_file_rsp().file_id();
          filexist = msg.friend_send_file_rsp().ifexist();
        }
        friendsuccess = true;
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "上传文件失败，原因："
                    << msg.friend_send_file_rsp().errmsg() << Tail << std::endl;
        }
        friendsuccess = false;
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::FriendGetFileRspType:
      if (msg.friend_get_file_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(getfilelock);
          get_file_id = msg.friend_get_file_rsp().file_id();
        }
        friendsuccess = true;
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "下载文件失败，原因"
                    << msg.friend_get_file_rsp().errmsg() << Tail << std::endl;
        }
        friendsuccess = false;
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::CreateGroupRspType:
      if (msg.create_group_rsp().success()) {
        if (msg.create_group_rsp().errmsg().empty()) {
          {
            std::unique_lock<std::mutex> mtx(iolock);
            std::cout << Green << "创建群聊成功\n" << Tail;
          }
        } else {
          {
            std::unique_lock<std::mutex> mtx(iolock);
            std::cout << Green << "创建群聊成功,但存在非好友关系\n" << Tail;
          }
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "创建群聊失败，原因："
                    << msg.create_group_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::GetGroupListRspType:
      if (msg.get_group_list_rsp().success()) {
        group_list.clear();
        for (int i = 0; i < msg.get_group_list_rsp().group_list_size(); ++i) {
          group_list.emplace_back(msg.get_group_list_rsp().group_list(i));
        }
        groupsuccess = true;
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "获取群聊信息失败，原因："
                    << msg.get_group_list_rsp().errmsg() << Tail << std::endl;
        }
        groupsuccess = false;
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::UserAddGroupRspType:
      if (msg.user_add_group_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "发送入群申请成功\n" << Tail;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "发送入群申请失败，原因："
                    << msg.user_add_group_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::FriendApplyNoticeType: {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow << "[好友申请]：" << msg.friend_apply_notice().name()
                << Tail << std::endl;
    } break;
    case ClientMessageType::GetSessionApplyRspType:
      if (msg.get_session_apply_rsp().success()) {
        session_apply.clear();
        for (int i = 0; i < msg.get_session_apply_rsp().user_info_size(); ++i) {
          session_apply.emplace_back(msg.get_session_apply_rsp().user_info(i));
        }
        groupsuccess = true;
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "获取入群申请失败，原因："
                    << msg.get_session_apply_rsp().errmsg() << Tail
                    << std::endl;
        }
        groupsuccess = false;
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::GroupApplyNoticeType: {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow << "[入群申请]" << "["
                << msg.group_apply_notice().session_name()
                << "]: " << msg.group_apply_notice().user_name() << Tail
                << std::endl;
    } break;
    case ClientMessageType::SovelGroupApplyRspType:
      if (msg.sovel_group_apply_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "处理入群申请成功\n" << Tail;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "处理入群申请失败，原因："
                    << msg.sovel_group_apply_rsp().errmsg() << Tail
                    << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::GetMemberListRspType:
      if (msg.get_member_list_rsp().success()) {
        member_list.clear();
        for (int i = 0; i < msg.get_member_list_rsp().member_info_size(); ++i) {
          if (msg.get_member_list_rsp().member_info(i).type() == owner) {
            member_list.emplace_back(msg.get_member_list_rsp().member_info(i));
            break;
          }
        }
        for (int i = 0; i < msg.get_member_list_rsp().member_info_size(); ++i) {
          if (msg.get_member_list_rsp().member_info(i).type() == admin) {
            member_list.emplace_back(msg.get_member_list_rsp().member_info(i));
          }
        }
        for (int i = 0; i < msg.get_member_list_rsp().member_info_size(); ++i) {
          if (msg.get_member_list_rsp().member_info(i).type() == person) {
            member_list.emplace_back(msg.get_member_list_rsp().member_info(i));
          }
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "获取群聊成员列表失败,原因："
                    << msg.get_member_list_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::SetGroupAdminRspType:
      if (msg.set_group_admin_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "设置群聊管理员成功\n" << Tail;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "设置群聊管理员失败，原因："
                    << msg.set_group_admin_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::CancelGroupAdminRspType:
      if (msg.cancel_group_admin_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "解除群聊管理员成功\n" << Tail;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "设置群聊管理员失败，原因："
                    << msg.cancel_group_admin_rsp().errmsg() << Tail
                    << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::GroupAddFriendRspType:
      if (msg.group_add_friend_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "邀请好友进群成功\n" << Tail;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "邀请好友进群失败，原因："
                    << msg.group_add_friend_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::GroupDelMemberRspType:
      if (msg.group_del_member_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "踢出群聊成员成功\n" << Tail;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "踢出群聊成员失败，原因："
                    << msg.group_del_member_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::OwnerCancelGroupRspType:
      if (msg.owner_cancel_group_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "解散群聊成功\n" << Tail;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "解散群聊失败，原因："
                    << msg.owner_cancel_group_rsp().errmsg() << Tail
                    << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::MemberExitGroupRspType:
      if (msg.member_exit_group_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "退出群聊成功\n" << Tail;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "退出群聊失败，原因："
                    << msg.member_exit_group_rsp().errmsg() << Tail
                    << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::GroupSendMessageRspType:
      if (msg.group_send_message_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "发送群聊消息成功" << Tail << std::endl;
        }
      } else {
        if (msg.group_send_message_rsp().errmsg() == "此群聊已经不存在" ||
            msg.group_send_message_rsp().errmsg() == "你已经不是群聊的成员") {
          cancelgroup = true;
        }
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "发送群聊消息失败，原因："
                    << msg.group_send_message_rsp().errmsg() << Tail
                    << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::GroupMessageNoticeType: {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow;
      printf("[群聊:%s][%10s]",
             msg.group_message_notice().session_name().c_str(),
             msg.group_message_notice().member_name().c_str());
      if (msg.group_message_notice().message_type() == MessageType::file) {
        printf("[文件]:%s", msg.group_message_notice().body().c_str());
      } else if (msg.group_message_notice().message_type() ==
                 MessageType::string) {
        printf("[消息]:%s", msg.group_message_notice().body().c_str());
      }
      std::cout << Tail << std::endl;
    } break;
    case ClientMessageType::GroupSendFileRspType:
      if (msg.group_send_file_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(sendfileidlock);
          send_file_id = msg.group_send_file_rsp().file_id();
          filexist = msg.group_send_file_rsp().ifexist();
        }
        groupsuccess = true;
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "上传文件失败，原因："
                    << msg.group_send_file_rsp().errmsg() << Tail << std::endl;
        }
        groupsuccess = false;
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::GroupGetFileRspType:
      if (msg.group_get_file_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(getfilelock);
          get_file_id = msg.group_get_file_rsp().file_id();
        }
        groupsuccess = true;
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "下载文件失败，原因"
                    << msg.group_get_file_rsp().errmsg() << Tail << std::endl;
        }
        groupsuccess = false;
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::GroupHistoryMessageRspType:
      if (msg.group_history_message_rsp().success()) {
        {
          {
            std::unique_lock<std::mutex> mtx(iolock);
            std::cout << Green << "获取历史消息成功" << Tail << std::endl;
            for (int i = 0; i < msg.group_history_message_rsp().message_size();
                 ++i) {
              std::cout << Yellow;
              printf("[群聊：%s][%10s]",
                     msg.group_history_message_rsp()
                         .message(i)
                         .session_name()
                         .c_str(),
                     msg.group_history_message_rsp()
                         .message(i)
                         .sender_name()
                         .c_str());
              if (msg.group_history_message_rsp().message(i).message_type() ==
                  MessageType::file) {
                printf(
                    "[文件]:%s\n",
                    msg.group_history_message_rsp().message(i).body().c_str());
              } else if (msg.group_history_message_rsp()
                             .message(i)
                             .message_type() == MessageType::string) {
                printf(
                    "[消息]:%s\n",
                    msg.group_history_message_rsp().message(i).body().c_str());
              }
            }
          }
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "获取群聊历史消息失败，原因："
                    << msg.group_history_message_rsp().errmsg() << Tail
                    << std::endl;
        }
      }
      WakeUpEventFd(groupefd);
      break;
    case ClientMessageType::FriendOffNoticeType: {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow << "[通知]: 你的好友"
                << msg.friend_off_notice().name() << "已下线" << Tail
                << std::endl;
    } break;
    case ClientMessageType::UserDelSelfRspType:
      if (msg.user_del_self_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "注销账号成功" << Tail << std::endl;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "注销账号失败，原因："
                    << msg.user_del_self_rsp().errmsg() << Tail << std::endl;
        }
      }
      WakeUpEventFd(selfefd);
      break;
  }
}

void Recv() {
  char buf[10000];
  while (running) {
    int sz = SSL_read(ssl, buf, sizeof(buf));
    if (sz <= 0) {
      // 连接断开或出错
      std::cout << "服务器断开连接或读取出错" << std::endl;
      running = false;
      break;
    }
    buffer.WriteAndPush(buf, sz);
    // 处理所有完整消息
    while (true) {
      std::string lenLine = buffer.GetLine();
      if (lenLine.empty())
        break;
      int bodyLen = 0;
      try {
        bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
      } catch (...) {
        buffer.Clear();
        break;
      }
      if (buffer.ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen))
        break;
      buffer.MoveReadIndex(lenLine.size());
      std::string data = buffer.ReadAsStringAndPop(bodyLen);
      ClientMessage msg;
      if (!msg.ParseFromString(data))
        continue;
      HandleMessage(msg);
    }
  }
}

void UpdateNickname() {
  std::string nickname;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "请输入你的新昵称\n";
    std::cout << Tail;
  }
  std::cin >> nickname;
  while (!Check_nickname(nickname)) {
    nickname.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "用户名过长，请重新输入\n" << Tail << Yellow;
      std::cout << Tail;
    }
    std::cin >> nickname;
  }
  ServerMessage req;
  req.set_type(ServerMessageType::SetNicknameReqType);
  req.mutable_set_user_nickname_req()->set_user_id(uid);
  req.mutable_set_user_nickname_req()->set_nickname(nickname);
  SendToServer(req.SerializeAsString());
  ReadEventfd(selfefd);
}

void GetUserInfo() {
  ServerMessage req;
  req.set_type(ServerMessageType::GetUserInfoReqType);
  req.mutable_get_user_info_req()->set_user_id(uid);
  SendToServer(req.SerializeAsString());
  ReadEventfd(selfefd);
}

void UpdateEmail() {
  std::string newemail;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow;
    std::cout << "请输入你的新邮箱\n";
    std::cout << Tail;
  }
  std::cin >> newemail;
  while (!Check_email(newemail)) {
    newemail.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "邮箱不合法，请重新输入\n" << Tail << Yellow;
      std::cout << Tail;
    }
    std::cin >> newemail;
  }
  std::string ensure;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow;
    std::cout << "现在开始获取验证码(y/n)\n";
    std::cout << Tail;
  }
  std::cin >> ensure;
  while (true) {
    if (ensure == "n" || ensure == "no") {
      return;
    }
    if (ensure == "y" || ensure == "yes") {
      break;
    }
    ensure.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "未知操作，请重新输入\n";
      std::cout << Tail;
    }
    std::cin >> ensure;
  }
  Xianwei::ServerMessage req;
  req.set_type(ServerMessageType::EmailVcodeReqType);
  req.mutable_email_verify_code_req()->set_email(newemail);
  SendToServer(req.SerializeAsString());
  ReadEventfd(vcodefd);
  if (!vsuccess) {
    return;
  }
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "请输入验证码\n";
    std::cout << Tail;
  }
  std::cin >> vcode;
  ServerMessage sreq;
  sreq.set_type(ServerMessageType::SetEmailReqType);
  sreq.mutable_set_user_email_req()->set_email(newemail);
  sreq.mutable_set_user_email_req()->set_user_id(uid);
  sreq.mutable_set_user_email_req()->set_email_verify_code_id(vid);
  sreq.mutable_set_user_email_req()->set_email_verify_code(vcode);
  SendToServer(sreq.SerializeAsString());
  while (true) {
    ReadEventfd(selfefd);
    if (!selfsuccess && !vsuccess) {
      vcode.clear();
      {
        std::unique_lock<std::mutex> mtx(iolock);
        std::cout << Red << "验证码错误，请重新输入\n";
        std::cout << Tail;
      }
      std::cin >> vcode;
      sreq.mutable_set_user_email_req()->set_email_verify_code(vcode);
      SendToServer(sreq.SerializeAsString());
      continue;
    } else if (!selfsuccess && vsuccess) {
      return;
    } else {
      uemail = newemail;
      return;
    }
  }
}

void UpdatePassword() {
  std::string password;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "请输入你的新密码(7~14位)\n";
    std::cout << Tail;
  }
  std::cin >> password;
  while (!Check_password(password)) {
    password.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "密码不在要求范围内，请重新输入\n";
      std::cout << Tail;
    }
    std::cin >> password;
  }
  std::string ensure;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow;
    std::cout << "现在开始获取验证码(y/n)\n";
    std::cout << Tail;
  }
  std::cin >> ensure;
  while (true) {
    if (ensure == "n" || ensure == "no") {
      return;
    }
    if (ensure == "y" || ensure == "yes") {
      break;
    }
    ensure.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "未知操作，请重新输入\n";
      std::cout << Tail;
    }
    std::cin >> ensure;
  }
  Xianwei::ServerMessage req;
  req.set_type(ServerMessageType::EmailVcodeReqType);
  req.mutable_email_verify_code_req()->set_email(uemail);
  SendToServer(req.SerializeAsString());
  ReadEventfd(vcodefd);
  if (!vsuccess) {
    return;
  }
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "请输入验证码\n";
    std::cout << Tail;
  }
  std::cin >> vcode;
  ServerMessage sreq;
  sreq.set_type(ServerMessageType::SetPassword);
  sreq.mutable_set_user_password_req()->set_password(password);
  sreq.mutable_set_user_password_req()->set_user_id(uid);
  sreq.mutable_set_user_password_req()->set_email_verify_code_id(vid);
  sreq.mutable_set_user_password_req()->set_email_verify_code(vcode);
  SendToServer(sreq.SerializeAsString());
  while (true) {
    ReadEventfd(selfefd);
    if (!selfsuccess && !vsuccess) {
      vcode.clear();
      {
        std::unique_lock<std::mutex> mtx(iolock);
        std::cout << Red << "验证码错误，请重新输入\n";
        std::cout << Tail;
      }
      std::cin >> vcode;
      sreq.mutable_set_user_password_req()->set_email_verify_code(vcode);
      SendToServer(sreq.SerializeAsString());
      continue;
    } else if (!selfsuccess && vsuccess) {
      return;
    } else {
      return;
    }
  }
}

void EmailAddFriend() {
  std::string email;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow;
    std::cout << "请输入对方的邮箱\n";
    std::cout << Tail;
  }
  std::cin >> email;
  while (!Check_email(email)) {
    email.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "邮箱不合法，请重新输入\n";
      std::cout << Tail;
    }
    std::cin >> email;
  }
  ServerMessage req;
  req.set_type(ServerMessageType::EmailFriendAddReqType);
  req.mutable_email_friend_add_req()->set_email(email);
  req.mutable_email_friend_add_req()->set_user_id(uid);
  SendToServer(req.SerializeAsString());
  ReadEventfd(friendefd);
}

void NicknameAddFriend() {
  std::string nickname;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "请输入对方的昵称\n";
    std::cout << Tail;
  }
  std::cin >> nickname;
  while (!Check_nickname(nickname)) {
    nickname.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "用户名过长，请重新输入\n";
      std::cout << Tail;
    }
    std::cin >> nickname;
  }
  ServerMessage rsp;
  rsp.set_type(ServerMessageType::NicknameFriendAddReqType);
  rsp.mutable_nickname_friend_add_req()->set_nickname(nickname);
  rsp.mutable_nickname_friend_add_req()->set_user_id(uid);
  SendToServer(rsp.SerializeAsString());
  ReadEventfd(friendefd);
}

void AddFriend() {
  int flag = 0;
  while (true) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Cyan;
      std::cout << " ______________________________________________________\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                   (1) 通过邮箱添加                   |\n"
                << "|                   (2) 通过昵称添加                   |\n"
                << "|                   (3) 返回上级                       |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << " ——————————————————————————————————————————————————————\n"
                << Tail;
      std::cout << Yellow << "请输入您要进行的操作\n";
      std::cout << Tail;
    }
    std::cin >> flag;
    switch (flag) {
      case 1:
        EmailAddFriend();
        return;
      case 2:
        NicknameAddFriend();
        return;
      case 3:
        return;
      default: {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "无效的操作" << Tail << std::endl;
        }
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        break;
      }
    }
  }
}

void SovelApply() {
  int flag = 0;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "请输入你要处理的好友申请编号\n" << Tail;
  }
  while (!(std::cin >> flag) || flag < 1 || flag > friend_apply.size()) {
    std::cin.clear();  // 清除错误标志位
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                    '\n');  // 丢弃错误输入
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Red << "不存在编号为此的好友申请，请重新输入\n" << Tail;
  }
  ServerMessage req;
  req.set_type(ServerMessageType::SovelFriendApplyReqType);
  std::string agree;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "是否同意该条好友申请(y/n)\n";
    std::cout << Tail;
  }
  std::cin >> agree;
  while (true) {
    if (agree == "n" || agree == "no") {
      req.mutable_sovel_friend_apply_req()->set_agree(false);
      break;
    }
    if (agree == "y" || agree == "yes") {
      req.mutable_sovel_friend_apply_req()->set_agree(true);
      break;
    }
    agree.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "未知操作，请重新输入\n";
      std::cout << Tail;
    }
    std::cin >> agree;
  }
  req.mutable_sovel_friend_apply_req()->set_user_id(uid);
  req.mutable_sovel_friend_apply_req()->set_peer_id(
      friend_apply[flag - 1].user_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(friendefd);
}

void GetFriendApply() {
  ServerMessage req;
  req.set_type(ServerMessageType::GetFriendApplyReqtype);
  req.mutable_get_friend_apply()->set_user_id(uid);
  SendToServer(req.SerializeAsString());
  ReadEventfd(friendefd);
  if (!friendsuccess) {
    return;
  }
  int flag = 0;
  while (true) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow;
      for (int i = 0; i < friend_apply.size(); ++i) {
        std::cout << "(" << i + 1 << ") " << friend_apply[i].nickname()
                  << " —————— " << friend_apply[i].email() << std::endl;
      }
      std::cout << Tail;
      std::cout << Cyan;
      std::cout << " ______________________________________________________\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                   (1) 处理好友申请                   |\n"
                << "|                   (2) 返回上级                       |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << " ——————————————————————————————————————————————————————\n"
                << Tail;
      std::cout << Yellow << "请输入您要进行的操作\n";
      std::cout << Tail;
    }
    std::cin >> flag;
    switch (flag) {
      case 1:
        SovelApply();
        return;
      case 2:
        return;
      default: {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "无效的操作" << Tail << std::endl;
        }
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        break;
      }
    }
  }
}

void GetFriendList() {
  friend_list.clear();
  ServerMessage req;
  req.set_type(ServerMessageType::GetFriendListReqType);
  req.mutable_get_friend_list_req()->set_user_id(uid);
  SendToServer(req.SerializeAsString());
  ReadEventfd(friendefd);
  int flag = 0;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow;
    for (int i = 0; i < friend_list.size(); ++i) {
      std::cout << "(" << i + 1 << ") " << friend_list[i].nickname()
                << " —————— " << friend_list[i].email() << " —————— ";
      if (friend_list[i].iflogin()) {
        std::cout << "在线" << std::endl;
      } else {
        std::cout << "不在线" << std::endl;
      }
    }
    std::cout << Tail;
  }
}

void IgnoreFriend(const int& num) {
  ServerMessage req;
  req.set_type(ServerMessageType::IgnoreFriendReqType);
  req.mutable_ignore_friend_req()->set_user_id(uid);
  req.mutable_ignore_friend_req()->set_peer_id(friend_list[num - 1].user_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(friendefd);
}

void UnIgnoreFriend(const int& num) {
  ServerMessage req;
  req.set_type(ServerMessageType::UnIgnoreFriendReqType);
  req.mutable_unignore_friend_req()->set_user_id(uid);
  req.mutable_unignore_friend_req()->set_peer_id(
      friend_list[num - 1].user_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(friendefd);
}

void GetFriendInfo(const int& num) {
  ServerMessage req;
  req.set_type(ServerMessageType::GetFriendInfoReqType);
  req.mutable_get_friend_info_req()->set_user_id(uid);
  req.mutable_get_friend_info_req()->set_peer_id(
      friend_list[num - 1].user_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(friendefd);
}

void SendString(const int& num) {
  ServerMessage req;
  req.set_type(ServerMessageType::FriendSendMessageReqType);
  req.mutable_friend_send_message_req()->set_user_id(uid);
  req.mutable_friend_send_message_req()->set_peer_id(
      friend_list[num - 1].user_id());
  std::string body;
  std::cout << Cyan << "输入quit以结束\n" << Tail;
  while (true) {
    body.clear();
    std::getline(std::cin, body);
    if (body == "quit") {
      break;
    }
    if (body.empty()) {
      continue;
    }
    auto tme = req.mutable_friend_send_message_req()->mutable_message();
    tme->set_message_type(MessageType::string);
    tme->set_body(body);
    SendToServer(req.SerializeAsString());
    // ReadEventfd(friendefd);
    if (deletefriend) {
      return;
    }
  }
}

void DeleteFriend(const int& num) {
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "您确定要删除这个好友吗？(y/n)" << Tail << std::endl;
  }
  std::string ensure;
  std::cin >> ensure;
  while (true) {
    if (ensure == "n" || ensure == "no") {
      return;
    }
    if (ensure == "y" || ensure == "yes") {
      break;
    }
    ensure.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "未知操作，请重新输入\n";
      std::cout << Tail;
    }
    std::cin >> ensure;
  }
  ServerMessage req;
  req.set_type(ServerMessageType::DeleteFriendReqType);
  req.mutable_delete_friend_req()->set_user_id(uid);
  req.mutable_delete_friend_req()->set_peer_id(friend_list[num - 1].user_id());
  SendToServer(req.SerializePartialAsString());
  ReadEventfd(friendefd);
}

void Message(const int& num) {
  ServerMessage req;
  req.set_type(ServerMessageType::FriendHistoryMessageReqType);
  req.mutable_friend_history_message_req()->set_user_id(uid);
  req.mutable_friend_history_message_req()->set_peer_id(
      friend_list[num - 1].user_id());
  int sum = 0;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "请输入你要获取的历史聊天记录条数" << Tail
              << std::endl;
  }
  while (!(std::cin >> sum) || sum <= 0) {
    std::cin.clear();  // 清除错误标志位
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                    '\n');  // 丢弃错误输入
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "请输入大于0的有效的数字" << Tail << std::endl;
    }
  }
  req.mutable_friend_history_message_req()->set_message_size(sum);
  SendToServer(req.SerializeAsString());
  ReadEventfd(friendefd);
}

void FriendSendFile(const int& num) {
  std::string file_name;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "请输入你要上传的文件\n" << Tail;
  }
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  std::getline(std::cin, file_name);
  while (!std::filesystem::exists(file_name)) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "文件不存在，请重新输入\n" << Tail;
    }
    std::getline(std::cin, file_name);
  }
  std::filesystem::path p(file_name);
  ServerMessage req;
  req.set_type(ServerMessageType::FriendSendFileReqType);
  req.mutable_friend_send_file_req()->set_user_id(uid);
  req.mutable_friend_send_file_req()->set_peer_id(
      friend_list[num - 1].user_id());
  req.mutable_friend_send_file_req()->set_file_name(p.filename().string());
  SendToServer(req.SerializeAsString());
  std::string tmp_file_id;
  bool tmp_file_exist;
  ReadEventfd(friendefd);
  if (!friendsuccess) {
    return;
  }
  {
    std::unique_lock<std::mutex> mtx(sendfileidlock);
    tmp_file_id = send_file_id;
    tmp_file_exist = filexist;
  }
  bool ifcontinue;
  if (tmp_file_exist) {
    int flag = 0;
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow << "你曾经上传过该文件,请选择\n"
                << Tail << Cyan << "(1)继续上传\n"
                << "(2)重新上传\n"
                << "(3)放弃上传\n"
                << Tail;
    }
    while (!(std::cin >> flag) || flag < 1 || flag > 3) {
      std::cin.clear();  // 清除错误标志位
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                      '\n');  // 丢弃错误输入
      {
        std::unique_lock<std::mutex> mtx(iolock);
        std::cout << Red << "不存在编号为此的操作，请重新输入\n" << Tail;
      }
    }
    switch (flag) {
      case 1:
        ifcontinue = true;
        break;
      case 2:
        ifcontinue = false;
        break;
      case 3:
        return;
    }
  } else {
    ifcontinue = false;
  }
  std::thread send_file([file_name, tmp_file_id, ifcontinue, num, p]() {
    Socket fs;
    fs.CreateClient(8085, file_ip);
    FileServer req;
    req.set_type(FileServerType::FileSendReqType);
    if (ifcontinue) {
      req.mutable_file_send_req()->set_send_type(FileSendContinue);
    } else {
      req.mutable_file_send_req()->set_send_type(FileSendFromBegin);
    }
    req.mutable_file_send_req()->set_file_id(tmp_file_id);
    std::string sreq = req.SerializeAsString();
    std::string body = std::to_string(sreq.size()) + "\r\n" + sreq;
    fs.Send(body.c_str(), body.size());
    char buff[65535];
    Buffer buf;
    while (true) {
      int ssz = fs.Recv(buff, sizeof(buff));
      buf.WriteAndPush(buff, ssz);
      std::string lenLine = buf.GetLine();
      if (lenLine.empty()) {
        break;
      }
      int bodyLen = 0;
      try {
        bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
      } catch (...) {
        buf.Clear();
        fs.Close();
        return;
      }
      if (buf.ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen)) {
        break;
      }
      buf.MoveReadIndex(lenLine.size());
      std::string data = buf.ReadAsStringAndPop(bodyLen);
      FileClient msg;
      if (!msg.ParseFromString(data)) {
        continue;
      }
      auto rsp = msg.file_send_rsp();
      if (!rsp.success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "文件上传失败,原因：" << rsp.errmsg() << Tail
                    << std::endl;
        }
        fs.Close();
        return;
      } else {
        auto sz = rsp.file_sz();
        auto tsz = std::filesystem::file_size(file_name);
        int file_fd = open(file_name.c_str(), O_RDONLY);
        if (file_fd == -1) {
          {
            std::unique_lock<std::mutex> mtx(iolock);
            std::cout << Red << "打开文件失败：" << file_name << Tail
                      << std::endl;
          }
          fs.Close();
          return;
        }
        size_t step = 60000;
        off_t offset = sz;
        while (offset < tsz) {
          auto count = std::min(step,
                                tsz - offset);  // 计算剩余数据大小
          ssize_t ret =
              sendfile(fs.Fd(), file_fd, &offset, count);  // 发送文件部分
          if (ret == -1) {
            if (errno == EAGAIN || errno == EINTR) {
              continue;
            }
            {
              std::unique_lock<std::mutex> mtx(iolock);
              std::cout << Red << "发送文件出错" << std::endl << Tail;
            }
            break;
          }
        }
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "文件已全部发送完毕" << Tail << std::endl;
        }
        close(file_fd);
        break;
      }
    }
    fs.Close();
    ServerMessage creq;
    creq.set_type(ServerMessageType::FriendSendMessageReqType);
    creq.mutable_friend_send_message_req()->set_user_id(uid);
    creq.mutable_friend_send_message_req()->set_peer_id(
        friend_list[num - 1].user_id());
    auto me = creq.mutable_friend_send_message_req()->mutable_message();
    me->set_message_type(MessageType::file);
    me->set_body(p.filename());
    SendToServer(creq.SerializeAsString());
  });
  send_file.detach();
}

void FriendGetFile(const int& num) {
  int flag = 0;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "(1) 我方文件\n"
              << "(2) 对方文件\n"
              << "请输入你要获取文件的归属:\n"
              << Tail;
  }
  while (!(std::cin >> flag) || flag < 1 || flag > 3) {
    std::cin.clear();  // 清除错误标志位
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                    '\n');  // 丢弃错误输入
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "不存在编号为此的操作，请重新输入\n" << Tail;
    }
  }
  ServerMessage req;
  req.set_type(ServerMessageType::FriendGetFileReqType);
  req.mutable_friend_get_file_req()->set_user_id(uid);
  req.mutable_friend_get_file_req()->set_peer_id(
      friend_list[num - 1].user_id());
  if (flag == 1) {
    req.mutable_friend_get_file_req()->set_send_id(uid);
  } else {
    req.mutable_friend_get_file_req()->set_send_id(
        friend_list[num - 1].user_id());
  }
  std::string file_name;
  {
    std::cout << Yellow << "请输入你要获取的文件名:\n" << Tail;
  }
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  std::getline(std::cin, file_name);
  req.mutable_friend_get_file_req()->set_file_name(file_name);
  SendToServer(req.SerializeAsString());
  ReadEventfd(friendefd);
  if (!friendsuccess) {
    return;
  }
  std::string tmp_file_id;
  {
    std::unique_lock<std::mutex> mtx(getfilelock);
    tmp_file_id = get_file_id;
  }
  std::thread get_file([tmp_file_id, file_name]() {
    Socket fg;
    fg.CreateClient(8085, file_ip);
    FileServer req;
    req.set_type(FileServerType::FileGetReqType);
    req.mutable_file_get_req()->set_file_id(tmp_file_id);
    std::string sreq = req.SerializeAsString();
    std::string body = std::to_string(sreq.size()) + "\r\n" + sreq;
    fg.Send(body.c_str(), body.size());
    char buff[65535];
    Buffer buf;
    while (true) {
      int ssz = fg.Recv(buff, sizeof(buff));
      buf.WriteAndPush(buff, ssz);
      std::string lenLine = buf.GetLine();
      if (lenLine.empty()) {
        break;
      }
      int bodyLen = 0;
      try {
        bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
      } catch (...) {
        buf.Clear();
        fg.Close();
        return;
      }
      if (buf.ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen)) {
        break;
      }
      buf.MoveReadIndex(lenLine.size());
      std::string data = buf.ReadAsStringAndPop(bodyLen);
      FileClient msg;
      if (!msg.ParseFromString(data)) {
        continue;
      }
      auto rsp = msg.file_get_rsp();
      if (!rsp.success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "文件下载失败,原因：" << rsp.errmsg() << Tail
                    << std::endl;
        }
        fg.Close();
        return;
      } else {
        std::ofstream out;
        out.open(file_dir + file_name,
                 std::ios::out | std::ios::trunc | std::ios::binary);
        while (true) {
          ssize_t sz = fg.Recv(buff, sizeof(buff));
          if (sz == 0) {
            std::cout << Green << "文件下载成功" << Tail << std::endl;
            out.close();
            break;
          } else if (sz < 0) {
            if (sz < 0 && ((errno == EAGAIN || errno == EINTR))) {
              continue;
            }
            out.close();
            return;
          }
          out.write(buff, sz);
        }
        break;
      }
    }
    fg.Close();
  });
  get_file.detach();
}

void ToFriend() {
  int flag = 0;
  int i = 0;
  while (true) {
    GetFriendList();
    if (!friendsuccess) {
      return;
    }
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Cyan << "请输入你要进行操作的对象编号\n" << Tail;
    }
    while (!(std::cin >> i) || i <= 0 || i > friend_list.size()) {
      std::cin.clear();  // 清除错误标志位
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                      '\n');  // 丢弃错误输入
      {
        std::unique_lock<std::mutex> mtx(iolock);
        std::cout << Red << "请输入有效的好友编号" << Tail << std::endl;
      }
    }
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Cyan;
      std::cout << " ______________________________________________________\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                   (1) 发送消息                       |\n"
                << "|                   (2) 发送文件                       |\n"
                << "|                   (3) 下载文件                       |\n"
                << "|                   (4) 屏蔽好友                       |\n"
                << "|                   (5) 解除屏蔽                       |\n"
                << "|                   (6) 删除好友                       |\n"
                << "|                   (7) 获取历史消息                  |\n"
                << "|                   (8) 查看好友信息                  |\n"
                << "|                   (9) 返回上级                       |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << " ——————————————————————————————————————————————————————\n"
                << Tail;
      std::cout << Yellow << "请输入您要进行的操作:\n";
      std::cout << Tail;
    }
    std::cin >> flag;
    switch (flag) {
      case 1:
        SendString(i);
        return;
      case 2:
        FriendSendFile(i);
        return;
      case 3:
        FriendGetFile(i);
        return;
      case 4:
        IgnoreFriend(i);
        return;
      case 5:
        UnIgnoreFriend(i);
        return;
      case 6:
        DeleteFriend(i);
        return;
      case 7:
        Message(i);
        return;
      case 8:
        GetFriendInfo(i);
        return;
      case 9:
        return;
      default: {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << "无效的操作" << std::endl;
        }
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        break;
      }
    }
  }
}

void Friend() {
  int flag = 0;
  while (true) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Cyan;
      std::cout << " ______________________________________________________\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                   (1) 查看好友列表                   |\n"
                << "|                   (2) 查看好友申请                   |\n"
                << "|                   (3) 添加好友                       |\n"
                << "|                   (4) 选择好友                       |\n"
                << "|                   (5) 返回上级                       |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << " ——————————————————————————————————————————————————————\n"
                << Tail;
      std::cout << Yellow << "请输入您要进行的操作:\n";
      std::cout << Tail;
    }
    std::cin >> flag;
    switch (flag) {
      case 1:
        GetFriendList();
        break;
      case 2:
        GetFriendApply();
        break;
      case 3:
        AddFriend();
        break;
      case 4:
        ToFriend();
        break;
      case 5:
        return;
      default: {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "无效的操作" << std::endl << Tail;
        }
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        break;
      }
    }
  }
}

void DelSelf() {
  std::string agree;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "你确定注销账号吗(y/n)\n";
    std::cout << Tail;
  }
  std::cin >> agree;
  while (true) {
    if (agree == "n" || agree == "no") {
      return;
    }
    if (agree == "y" || agree == "yes") {
      ServerMessage req;
      req.set_type(ServerMessageType::UserDelSelfReqType);
      req.mutable_user_del_self_req()->set_user_id(uid);
      SendToServer(req.SerializeAsString());
      ReadEventfd(selfefd);
      exit(0);
    }
    agree.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "未知操作，请重新输入\n";
      std::cout << Tail;
    }
    std::cin >> agree;
  }
}

void about() {
  while (true) {
    int flag = 0;
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Cyan;
      std::cout << " ______________________________________________________\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                   (1) 查看个人信息                   |\n"
                << "|                   (2) 修改昵称                       |\n"
                << "|                   (3) 修改邮箱                       |\n"
                << "|                   (4) 修改密码                       |\n"
                << "|                   (5) 注销账号                       |\n"
                << "|                   (6) 返回上级                       |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << " ——————————————————————————————————————————————————————\n"
                << Tail;
      std::cout << Yellow << "请输入您要进行的操作\n";
      std::cout << Tail;
    }
    std::cin >> flag;
    switch (flag) {
      case 1:
        GetUserInfo();
        break;
      case 2:
        UpdateNickname();
        break;
      case 3:
        UpdateEmail();
        break;
      case 4:
        UpdatePassword();
        break;
      case 5:
        DelSelf();
        break;
      case 6:
        return;
      default: {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "无效的操作" << Tail << std::endl;
        }
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        break;
      }
    }
  }
}

void CreateGroup() {
  ServerMessage req;
  req.set_type(ServerMessageType::CreateGroupReqType);
  std::string session_name;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "请输入群聊名字:\n" << Tail;
  }
  std::cin >> session_name;
  while (!Check_nickname(session_name)) {
    session_name.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "群聊名过长，请重新输入\n";
      std::cout << Tail;
    }
    std::cin >> session_name;
  }
  req.mutable_create_group_req()->set_session_name(session_name);
  req.mutable_create_group_req()->set_user_id(uid);
  GetFriendList();
  int num = 0;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "请输入你要选择作为群员的好友编号(输入0以结束)\n"
              << Tail;
  }
  std::unordered_set<std::string> member_uid_list;
  while (true) {
    if (!(std::cin >> num) || num < 0 || num > friend_list.size()) {
      std::cin.clear();
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
      {
        std::unique_lock<std::mutex> mtx(iolock);
        std::cout << Red << "请输入有效的好友编号：\n" << Tail;
      }
      continue;
    }
    if (num == 0) {
      break;
    }
    member_uid_list.emplace(friend_list[num - 1].user_id());
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow << "请继续输入：\n" << Tail;
    }
  }
  if (member_uid_list.empty()) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "群聊成员不能为空\n" << Tail;
    }
    return;
  }
  for (const auto& n : member_uid_list) {
    req.mutable_create_group_req()->add_member_id(n);
  }
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
}

void GetGroupList() {
  ServerMessage req;
  req.set_type(ServerMessageType::GetGroupListReqType);
  req.mutable_get_group_list_req()->set_user_id(uid);
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
  if (!groupsuccess) {
    return;
  }
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow;
    for (int i = 0; i < group_list.size(); ++i) {
      std::cout << "(" << i + 1 << ") " << group_list[i].session_name()
                << std::endl;
    }
    std::cout << Tail;
  }
}

void UserAddGroup() {
  ServerMessage req;
  req.set_type(ServerMessageType::UserAddGroupReqType);
  req.mutable_user_add_group_req()->set_user_id(uid);
  std::string session_name;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "请输入群聊名字:\n" << Tail;
  }
  std::cin >> session_name;
  while (!Check_nickname(session_name)) {
    session_name.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "群聊名过长，请重新输入\n";
      std::cout << Tail;
    }
    std::cin >> session_name;
  }
  req.mutable_user_add_group_req()->set_session_name(session_name);
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
}

void SovelGroupApply(const int& num) {
  int flag = 0;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "请输入你要处理的入群申请编号\n" << Tail;
  }
  while (!(std::cin >> flag) || flag < 1 || flag > session_apply.size()) {
    std::cin.clear();  // 清除错误标志位
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                    '\n');  // 丢弃错误输入
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Red << "不存在编号为此的好友申请，请重新输入\n" << Tail;
  }
  ServerMessage req;
  req.set_type(ServerMessageType::SovelGroupApplyReqType);
  std::string agree;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "是否同意该条入群申请(y/n)\n";
    std::cout << Tail;
  }
  std::cin >> agree;
  while (true) {
    if (agree == "n" || agree == "no") {
      req.mutable_sovel_group_apply_req()->set_agree(false);
      break;
    }
    if (agree == "y" || agree == "yes") {
      req.mutable_sovel_group_apply_req()->set_agree(true);
      break;
    }
    agree.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "未知操作，请重新输入\n";
      std::cout << Tail;
    }
    std::cin >> agree;
  }
  req.mutable_sovel_group_apply_req()->set_session_id(
      group_list[num - 1].session_id());
  req.mutable_sovel_group_apply_req()->set_user_id(uid);
  req.mutable_sovel_group_apply_req()->set_peer_id(
      session_apply[flag - 1].user_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
}

void GetSessionApply(const int& num) {
  ServerMessage req;
  req.set_type(ServerMessageType::GetSessionApplyReqType);
  req.mutable_get_session_apply_req()->set_user_id(uid);
  req.mutable_get_session_apply_req()->set_session_id(
      group_list[num - 1].session_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
  if (!groupsuccess) {
    return;
  }
  int flag = 0;
  while (true) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow;
      for (int i = 0; i < session_apply.size(); ++i) {
        std::cout << "(" << i + 1 << ") " << session_apply[i].nickname()
                  << " —————— " << session_apply[i].email() << std::endl;
      }
      std::cout << Tail;
      std::cout << Cyan;
      std::cout << " ______________________________________________________\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                   (1) 处理入群申请                   |\n"
                << "|                   (2) 返回上级                       |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << " ——————————————————————————————————————————————————————\n"
                << Tail;
      std::cout << Yellow << "请输入您要进行的操作\n";
      std::cout << Tail;
    }
    std::cin >> flag;
    switch (flag) {
      case 1:
        SovelGroupApply(num);
        return;
      case 2:
        return;
      default: {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "无效的操作" << Tail << std::endl;
        }
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        break;
      }
    }
  }
}

void PrintMember() {
  if (!groupsuccess) {
    return;
  }
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow;
    for (int i = 0; i < member_list.size(); ++i) {
      std::cout << "(" << i + 1 << ")";
      if (member_list[i].type() == owner) {
        std::cout << "群 主：";
      } else if (member_list[i].type() == admin) {
        std::cout << "管理员：";
      } else {
        std::cout << "成 员：";
      }
      std::cout << member_list[i].name() << std::endl;
    }
    std::cout << Tail << std::endl;
  }
}

void GetMemberList(const int& num) {
  ServerMessage req;
  req.set_type(ServerMessageType::GetMemberListReqType);
  req.mutable_get_member_list_req()->set_user_id(uid);
  req.mutable_get_member_list_req()->set_session_id(
      group_list[num - 1].session_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
}

void SetAdmin(const int& num) {
  GetMemberList(num);
  if (member_list[0].user_id() != uid) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "你不是群主，不能进行该操作\n" << Tail;
    }
    return;
  }
  PrintMember();
  int flag = 0;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "请输入你要设为管理员的群员编号\n" << Tail;
  }
  while (!(std::cin >> flag) || flag <= 1 || flag > member_list.size()) {
    std::cin.clear();  // 清除错误标志位
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                    '\n');  // 丢弃错误输入
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Red << "不存在编号为此的群员，请重新输入\n" << Tail;
  }
  if (member_list[flag - 1].type() == admin) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "此群员已经是管理员\n" << Tail;
    }
    return;
  }
  ServerMessage req;
  req.set_type(ServerMessageType::SetGroupAdminReqType);
  req.mutable_set_group_admin_req()->set_user_id(uid);
  req.mutable_set_group_admin_req()->set_session_id(
      group_list[num - 1].session_id());
  req.mutable_set_group_admin_req()->set_peer_id(
      member_list[flag - 1].user_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
}

void CancelAdmin(const int& num) {
  GetMemberList(num);
  if (member_list[0].user_id() != uid) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "你不是群主，不能进行该操作\n" << Tail;
    }
    return;
  }
  PrintMember();
  int flag = 0;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "请输入你要解除管理员的群员编号\n" << Tail;
  }
  while (!(std::cin >> flag) || flag <= 1 || flag > member_list.size()) {
    std::cin.clear();  // 清除错误标志位
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                    '\n');  // 丢弃错误输入
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Red << "不存在编号为此的群员，请重新输入\n" << Tail;
  }
  if (member_list[flag - 1].type() != admin) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "此群员不是管理员\n" << Tail;
    }
    return;
  }
  ServerMessage req;
  req.set_type(ServerMessageType::CancelGroupAdminReqType);
  req.mutable_cancel_group_admin_req()->set_user_id(uid);
  req.mutable_cancel_group_admin_req()->set_session_id(
      group_list[num - 1].session_id());
  req.mutable_cancel_group_admin_req()->set_peer_id(
      member_list[flag - 1].user_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
}

void GroupAddFriend(const int& num) {
  GetFriendList();
  if (!friendsuccess) {
    return;
  }
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "请输入你要进行操作的对象编号\n" << Tail;
  }
  int i = 0;
  while (!(std::cin >> i) || i <= 0 || i > friend_list.size()) {
    std::cin.clear();  // 清除错误标志位
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                    '\n');  // 丢弃错误输入
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "请输入有效的好友编号" << Tail << std::endl;
    }
  }
  ServerMessage req;
  req.set_type(ServerMessageType::GroupAddFriendReqType);
  req.mutable_group_add_friend_req()->set_user_id(uid);
  req.mutable_group_add_friend_req()->set_peer_id(friend_list[i - 1].user_id());
  req.mutable_group_add_friend_req()->set_session_id(
      group_list[num - 1].session_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
}

void GroupDelMember(const int& num) {
  GetMemberList(num);
  if (!groupsuccess) {
    return;
  }
  PrintMember();
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "请输入你要进行操作的对象编号\n" << Tail;
  }
  int i = 0;
  while (!(std::cin >> i) || i <= 1 || i > member_list.size()) {
    std::cin.clear();  // 清除错误标志位
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                    '\n');  // 丢弃错误输入
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "请输入有效的成员编号" << Tail << std::endl;
    }
  }
  if (member_list[i - 1].user_id() == uid) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "你不能踢自己" << Tail << std::endl;
    }
    return;
  }
  ServerMessage req;
  req.set_type(ServerMessageType::GroupDelMemberReqType);
  req.mutable_group_del_member_req()->set_user_id(uid);
  req.mutable_group_del_member_req()->set_peer_id(member_list[i - 1].user_id());
  req.mutable_group_del_member_req()->set_session_id(
      group_list[num - 1].session_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
}

void OwnerCancelGroup(const int& num) {
  GetMemberList(num);
  if (!groupsuccess) {
    return;
  }
  if (uid != member_list[0].user_id()) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "你不是群主，无法进行此操作\n" << Tail;
    }
    return;
  }
  ServerMessage req;
  req.set_type(ServerMessageType::OwnerCancelGroupReqType);
  req.mutable_owner_cancel_group_req()->set_user_id(uid);
  req.mutable_owner_cancel_group_req()->set_session_id(
      group_list[num - 1].session_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
}

void MemberExitGroup(const int& num) {
  GetMemberList(num);
  if (!groupsuccess) {
    return;
  }
  if (uid == member_list[0].user_id()) {
    std::string agree;
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Cyan << "你是群主，这会使群聊解散(y/n)\n";
      std::cout << Tail;
    }
    std::cin >> agree;
    while (true) {
      if (agree == "n" || agree == "no") {
        return;
      }
      if (agree == "y" || agree == "yes") {
        OwnerCancelGroup(num);
        return;
      }
      agree.clear();
      {
        std::unique_lock<std::mutex> mtx(iolock);
        std::cout << Red << "未知操作，请重新输入\n";
        std::cout << Tail;
      }
      std::cin >> agree;
    }
  }
  ServerMessage req;
  req.set_type(ServerMessageType::MemberExitGroupReqType);
  req.mutable_member_exit_group_req()->set_user_id(uid);
  req.mutable_member_exit_group_req()->set_session_id(
      group_list[num - 1].session_id());
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
}

void GroupSendString(const int& num) {
  ServerMessage req;
  req.set_type(ServerMessageType::GroupSendMessageReqType);
  req.mutable_group_send_message_req()->set_user_id(uid);
  req.mutable_group_send_message_req()->set_session_id(
      group_list[num - 1].session_id());
  std::string body;
  std::cout << Cyan << "输入quit以结束\n" << Tail;
  while (true) {
    body.clear();
    std::getline(std::cin, body);
    if (body == "quit") {
      break;
    }
    if (body.empty()) {
      continue;
    }
    auto tme = req.mutable_group_send_message_req()->mutable_message();
    tme->set_message_type(MessageType::string);
    tme->set_body(body);
    SendToServer(req.SerializeAsString());
    if (cancelgroup) {
      return;
    }
  }
}

void GroupSendFile(const int& num) {
  std::string file_name;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "请输入你要上传的文件\n" << Tail;
  }
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  std::getline(std::cin, file_name);
  while (!std::filesystem::exists(file_name)) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "文件不存在，请重新输入\n" << Tail;
    }
    std::getline(std::cin, file_name);
  }
  std::filesystem::path p(file_name);
  ServerMessage req;
  req.set_type(ServerMessageType::GroupSendFileReqType);
  req.mutable_group_send_file_req()->set_user_id(uid);
  req.mutable_group_send_file_req()->set_session_id(
      group_list[num - 1].session_id());
  req.mutable_group_send_file_req()->set_file_name(p.filename().string());
  SendToServer(req.SerializeAsString());
  std::string tmp_file_id;
  bool tmp_file_exist;
  ReadEventfd(groupefd);
  if (!groupsuccess) {
    return;
  }
  {
    std::unique_lock<std::mutex> mtx(sendfileidlock);
    tmp_file_id = send_file_id;
    tmp_file_exist = filexist;
  }
  bool ifcontinue;
  if (tmp_file_exist) {
    int flag = 0;
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow << "你曾经上传过该文件,请选择\n"
                << Tail << Cyan << "(1)继续上传\n"
                << "(2)重新上传\n"
                << "(3)放弃上传\n"
                << Tail;
    }
    while (!(std::cin >> flag) || flag < 1 || flag > 3) {
      std::cin.clear();  // 清除错误标志位
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                      '\n');  // 丢弃错误输入
      {
        std::unique_lock<std::mutex> mtx(iolock);
        std::cout << Red << "不存在编号为此的操作，请重新输入\n" << Tail;
      }
    }
    switch (flag) {
      case 1:
        ifcontinue = true;
        break;
      case 2:
        ifcontinue = false;
        break;
      case 3:
        return;
    }
  } else {
    ifcontinue = false;
  }
  std::thread send_file([file_name, tmp_file_id, ifcontinue, num, p]() {
    Socket fs;
    fs.CreateClient(8085, file_ip);
    FileServer req;
    req.set_type(FileServerType::FileSendReqType);
    if (ifcontinue) {
      req.mutable_file_send_req()->set_send_type(FileSendContinue);
    } else {
      req.mutable_file_send_req()->set_send_type(FileSendFromBegin);
    }
    req.mutable_file_send_req()->set_file_id(tmp_file_id);
    std::string sreq = req.SerializeAsString();
    std::string body = std::to_string(sreq.size()) + "\r\n" + sreq;
    fs.Send(body.c_str(), body.size());
    char buff[65535];
    Buffer buf;
    while (true) {
      int ssz = fs.Recv(buff, sizeof(buff));
      buf.WriteAndPush(buff, ssz);
      std::string lenLine = buf.GetLine();
      if (lenLine.empty()) {
        break;
      }
      int bodyLen = 0;
      try {
        bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
      } catch (...) {
        buf.Clear();
        fs.Close();
        return;
      }
      if (buf.ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen)) {
        break;
      }
      buf.MoveReadIndex(lenLine.size());
      std::string data = buf.ReadAsStringAndPop(bodyLen);
      FileClient msg;
      if (!msg.ParseFromString(data)) {
        continue;
      }
      auto rsp = msg.file_send_rsp();
      if (!rsp.success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "文件上传失败,原因：" << rsp.errmsg() << Tail
                    << std::endl;
        }
        fs.Close();
        return;
      } else {
        auto sz = rsp.file_sz();
        auto tsz = std::filesystem::file_size(file_name);
        int file_fd = open(file_name.c_str(), O_RDONLY);
        if (file_fd == -1) {
          {
            std::unique_lock<std::mutex> mtx(iolock);
            std::cout << Red << "打开文件失败：" << file_name << Tail
                      << std::endl;
          }
          fs.Close();
          return;
        }
        size_t step = 60000;
        off_t offset = sz;
        while (offset < tsz) {
          auto count = std::min(step,
                                tsz - offset);  // 计算剩余数据大小
          ssize_t ret =
              sendfile(fs.Fd(), file_fd, &offset, count);  // 发送文件部分
          if (ret == -1) {
            if (errno == EAGAIN || errno == EINTR) {
              continue;
            }
            {
              std::unique_lock<std::mutex> mtx(iolock);
              std::cout << Red << "发送文件出错" << std::endl << Tail;
            }
            break;
          }
        }
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "文件已全部发送完毕" << Tail << std::endl;
        }
        close(file_fd);
        break;
      }
    }
    fs.Close();
    ServerMessage creq;
    creq.set_type(ServerMessageType::GroupSendMessageReqType);
    creq.mutable_group_send_message_req()->set_user_id(uid);
    creq.mutable_group_send_message_req()->set_session_id(
        group_list[num - 1].session_id());
    auto me = creq.mutable_group_send_message_req()->mutable_message();
    me->set_message_type(MessageType::file);
    me->set_body(p.filename());
    SendToServer(creq.SerializeAsString());
  });
  send_file.detach();
}

void GroupGetFile(const int& num) {
  GetMemberList(num);
  if (!groupsuccess) {
    return;
  }
  PrintMember();
  int flag = 0;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "请输入你要获取文件的归属:\n" << Tail;
  }
  while (!(std::cin >> flag) || flag < 1 || flag > member_list.size()) {
    std::cin.clear();  // 清除错误标志位
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                    '\n');  // 丢弃错误输入
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "不存在编号为此的成员，请重新输入\n" << Tail;
    }
  }
  ServerMessage req;
  req.set_type(ServerMessageType::GroupGetFileReqType);
  req.mutable_group_get_file_req()->set_user_id(uid);
  req.mutable_group_get_file_req()->set_session_id(
      group_list[num - 1].session_id());
  req.mutable_group_get_file_req()->set_send_id(
      member_list[flag - 1].user_id());
  std::string file_name;
  {
    std::cout << Yellow << "请输入你要获取的文件名:\n" << Tail;
  }
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
  std::getline(std::cin, file_name);
  req.mutable_group_get_file_req()->set_file_name(file_name);
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
  if (!groupsuccess) {
    return;
  }
  std::string tmp_file_id;
  {
    std::unique_lock<std::mutex> mtx(getfilelock);
    tmp_file_id = get_file_id;
  }
  std::thread get_file([tmp_file_id, file_name]() {
    Socket fg;
    fg.CreateClient(8085, file_ip);
    FileServer req;
    req.set_type(FileServerType::FileGetReqType);
    req.mutable_file_get_req()->set_file_id(tmp_file_id);
    std::string sreq = req.SerializeAsString();
    std::string body = std::to_string(sreq.size()) + "\r\n" + sreq;
    fg.Send(body.c_str(), body.size());
    char buff[65535];
    Buffer buf;
    while (true) {
      int ssz = fg.Recv(buff, sizeof(buff));
      buf.WriteAndPush(buff, ssz);
      std::string lenLine = buf.GetLine();
      if (lenLine.empty()) {
        break;
      }
      int bodyLen = 0;
      try {
        bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
      } catch (...) {
        buf.Clear();
        fg.Close();
        return;
      }
      if (buf.ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen)) {
        break;
      }
      buf.MoveReadIndex(lenLine.size());
      std::string data = buf.ReadAsStringAndPop(bodyLen);
      FileClient msg;
      if (!msg.ParseFromString(data)) {
        continue;
      }
      auto rsp = msg.file_get_rsp();
      if (!rsp.success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "文件下载失败,原因：" << rsp.errmsg() << Tail
                    << std::endl;
        }
        fg.Close();
        return;
      } else {
        std::ofstream out;
        out.open(file_dir + file_name,
                 std::ios::out | std::ios::trunc | std::ios::binary);
        while (true) {
          ssize_t sz = fg.Recv(buff, sizeof(buff));
          if (sz == 0) {
            std::cout << Green << "文件下载成功" << Tail << std::endl;
            out.close();
            break;
          } else if (sz < 0) {
            if (sz < 0 && ((errno == EAGAIN || errno == EINTR))) {
              continue;
            }
            out.close();
            return;
          }
          out.write(buff, sz);
        }
        break;
      }
    }
    fg.Close();
  });
  get_file.detach();
}

void GroupHistoryMessage(const int& num) {
  ServerMessage req;
  req.set_type(ServerMessageType::GroupHistoryMessageReqType);
  req.mutable_group_history_message_req()->set_user_id(uid);
  req.mutable_group_history_message_req()->set_session_id(
      group_list[num - 1].session_id());
  int sum = 0;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow << "请输入你要获取的历史聊天记录条数" << Tail
              << std::endl;
  }
  while (!(std::cin >> sum) || sum <= 0) {
    std::cin.clear();  // 清除错误标志位
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                    '\n');  // 丢弃错误输入
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "请输入大于0的有效的数字" << Tail << std::endl;
    }
  }
  req.mutable_group_history_message_req()->set_message_size(sum);
  SendToServer(req.SerializeAsString());
  ReadEventfd(groupefd);
}

void ToGroup() {
  int flag = 0;
  int i = 0;
  while (true) {
    GetGroupList();
    if (!groupsuccess) {
      return;
    }
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Cyan << "请输入你要进行操作的对象编号\n" << Tail;
    }
    while (!(std::cin >> i) || i <= 0 || i > group_list.size()) {
      std::cin.clear();  // 清除错误标志位
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(),
                      '\n');  // 丢弃错误输入
      {
        std::unique_lock<std::mutex> mtx(iolock);
        std::cout << Red << "请输入有效的群聊编号" << Tail << std::endl;
      }
    }
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Cyan;
      std::cout << " ______________________________________________________\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                   (1) 发送消息                       |\n"
                << "|                   (2) 发送文件                       |\n"
                << "|                   (3) 下载文件                       |\n"
                << "|                   (4) 邀请好友                       |\n"
                << "|                   (5) 退出群聊                       |\n"
                << "|                   (6) 清除成员                       |\n"
                << "|                   (7) 设置管理员                     |\n"
                << "|                   (8) 解除管理员                     |\n"
                << "|                   (9) 获取历史消息                   |\n"
                << "|                   (10) 查看群聊成员                  |\n"
                << "|                   (11) 查看入群申请                  |\n"
                << "|                   (12) 解散群聊                      |\n"
                << "|                   (13) 返回上级                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << " ——————————————————————————————————————————————————————\n"
                << Tail;
      std::cout << Yellow << "请输入您要进行的操作:\n";
      std::cout << Tail;
    }
    std::cin >> flag;
    switch (flag) {
      case 1:
        GroupSendString(i);
        return;
      case 2:
        GroupSendFile(i);
        return;
      case 3:
        GroupGetFile(i);
        return;
      case 4:
        GroupAddFriend(i);
        return;
      case 5:
        MemberExitGroup(i);
        return;
      case 6:
        GroupDelMember(i);
        return;
      case 7:
        SetAdmin(i);
        return;
      case 8:
        CancelAdmin(i);
        return;
      case 9:
        GroupHistoryMessage(i);
        return;
      case 10:
        GetMemberList(i);
        PrintMember();
        return;
      case 11:
        GetSessionApply(i);
        return;
      case 12:
        OwnerCancelGroup(i);
        return;
      case 13:
        return;
      default: {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << "无效的操作" << std::endl;
        }
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        break;
      }
    }
  }
}

void Group() {
  int flag = 0;
  while (true) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Cyan;
      std::cout << " ______________________________________________________\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                   (1) 查看群聊列表                   |\n"
                << "|                   (2) 创建群聊                       |\n"
                << "|                   (3) 选择群聊                       |\n"
                << "|                   (4) 加入群聊                       |\n"
                << "|                   (5) 返回上级                       |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << " ——————————————————————————————————————————————————————\n"
                << Tail;
      std::cout << Yellow << "请输入您要进行的操作:\n";
      std::cout << Tail;
    }
    std::cin >> flag;
    switch (flag) {
      case 1:
        GetGroupList();
        break;
      case 2:
        CreateGroup();
        break;
      case 3:
        ToGroup();
        break;
      case 4:
        UserAddGroup();
        break;
      case 5:
        return;
      default: {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "无效的操作" << std::endl << Tail;
        }
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        break;
      }
    }
  }
}

void Menu() {
  int flag = 0;
  while (true) {
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Cyan;
      std::cout << " ______________________________________________________\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                   (1) 好友                           |\n"
                << "|                   (2) 群聊                           |\n"
                << "|                   (3) 我                             |\n"
                << "|                   (4) 退出                           |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << "|                                                      |\n"
                << " ——————————————————————————————————————————————————————\n"
                << Tail;
      std::cout << Yellow << "请输入您要进行的操作\n";
      std::cout << Tail;
    }
    std::cin >> flag;
    switch (flag) {
      case 1:
        Friend();
        break;
      case 2:
        Group();
        break;
      case 3:
        about();
        break;
      case 4:
        ifrunning = false;
        return;
      default: {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "无效的操作" << Tail << std::endl;
        }
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        break;
      }
    }
  }
}

void UserLogin() {
  std::string nickname;
  std::string password;
  std::cout << Yellow << "请输入你的昵称：";
  std::cin.clear();
  std::cin >> nickname;
  std::cout << Tail;
  while (!Check_nickname(nickname)) {
    nickname.clear();
    std::cout << Red << "用户名过长，请重新输入：" << Tail << Yellow;
    std::cin.clear();
    std::cin >> nickname;
    std::cout << Tail;
  }
  std::cout << Yellow << "请输入你的密码(7~14位)：";
  std::cin.clear();
  std::cin >> password;
  std::cout << Tail;
  while (!Check_password(password)) {
    password.clear();
    std::cout << Red << "密码不在要求范围内，请重新输入：" << Tail << Yellow;
    std::cin.clear();
    std::cin >> password;
    std::cout << Tail;
  }
  ServerMessage req;
  req.set_type(ServerMessageType::UserLoginReqType);
  req.mutable_user_login_req()->set_nickname(nickname);
  req.mutable_user_login_req()->set_password(password);
  SendToServer(req.SerializeAsString());
  while (true) {
    char buf[10000];
    int sz = SSL_read(ssl, buf, sizeof(buf));
    buffer.WriteAndPush(buf, sz);
    std::string lenLine = buffer.GetLine();
    if (lenLine.empty()) {
      continue;
    }
    int bodyLen = 0;
    try {
      bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
    } catch (...) {
      buffer.Clear();
      return;
    }
    if (buffer.ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen)) {
      continue;
    }
    buffer.MoveReadIndex(lenLine.size());
    std::string data = buffer.ReadAsStringAndPop(bodyLen);
    ClientMessage regmsg;
    if (!regmsg.ParseFromString(data)) {
      continue;
    }
    if (regmsg.type() != ClientMessageType::UserLoginRspType) {
      continue;
    }
    auto& rsp = regmsg.user_login_rsp();
    if (rsp.success()) {
      std::cout << Green << "登陆成功" << Tail << std::endl;
      uid = rsp.user_id();
      uemail = rsp.email();
      std::cout << Yellow;
      for (int i = 0; i < rsp.friend__size(); ++i) {
        printf("[好友][%10s]", rsp.friend_(i).friend_name().c_str());
        if (rsp.friend_(i).message_type() == MessageType::file) {
          printf("[文件]:%s\n", rsp.friend_(i).body().c_str());
        } else if (rsp.friend_(i).message_type() == MessageType::string) {
          printf("[消息]:%s\n", rsp.friend_(i).body().c_str());
        }
      }
      for (int i = 0; i < rsp.session_size(); ++i) {
        printf("[群聊：%10s][%10s]", rsp.session(i).session_name().c_str(),
               rsp.session(i).sender_name().c_str());
        if (rsp.session(i).message_type() == MessageType::file) {
          printf("[文件]:%s\n", rsp.session(i).body().c_str());
        } else if (rsp.session(i).message_type() == MessageType::string) {
          printf("[消息]:%s\n", rsp.session(i).body().c_str());
        }
      }
      std::cout << Tail;
      std::string start;
      std::cout << Yellow << "输入chat以开始：";
      std::cin.clear();
      std::cin >> start;
      std::cout << Tail;
      while (start != "chat") {
        start.clear();
        std::cout << Red << "请重新输入：" << Tail << Yellow;
        std::cin.clear();
        std::cin >> start;
      }
      std::thread recv(Recv);
      recv.detach();
      Menu();
      // std::this_thread::sleep_for(std::chrono::seconds(10));
    } else {
      std::cout << Red << rsp.errmsg() << "，失败退出\n" << Tail;
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    break;
  }
}

void EmailLogin() {
  std::string email;
  std::cout << Yellow;
  std::cout << "请输入邮箱：";
  std::cin.clear();
  std::cin >> email;
  std::cout << Tail;
  while (!Check_email(email)) {
    email.clear();
    std::cout << Red << "邮箱不合法，请重新输入：" << Tail << Yellow;
    std::cin.clear();
    std::cin >> email;
    std::cout << Tail;
  }
  Xianwei::ServerMessage req;
  req.set_type(ServerMessageType::EmailVcodeReqType);
  req.mutable_email_verify_code_req()->set_email(email);
  SendToServer(req.SerializeAsString());
  while (true) {
    char buf[10000];
    int sz = SSL_read(ssl, buf, sizeof(buf));
    buffer.WriteAndPush(buf, sz);
    std::string lenLine = buffer.GetLine();
    if (lenLine.empty()) {
      continue;
    }
    int bodyLen = 0;
    try {
      bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
    } catch (...) {
      buffer.Clear();
      return;
    }
    if (buffer.ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen)) {
      continue;
    }
    buffer.MoveReadIndex(lenLine.size());
    std::string data = buffer.ReadAsStringAndPop(bodyLen);
    ClientMessage msg;
    if (!msg.ParseFromString(data)) {
      continue;
    }
    if (msg.type() != ClientMessageType::EmailVcodeRspType) {
      continue;
    }
    auto& vcode_rsp = msg.email_verify_code_rsp();
    if (!vcode_rsp.success()) {
      std::cout << Red << vcode_rsp.errmsg() << "退出" << Tail << std::endl;
      return;
    }
    vid = vcode_rsp.verify_code_id();
    break;
  }
  std::cout << Yellow << "请输入验证码：";
  std::cin.clear();
  std::cin >> vcode;
  std::cout << Tail;
  Xianwei::ServerMessage regreq;
  regreq.set_type(ServerMessageType::EmailLoginReqType);
  regreq.mutable_email_login_req()->set_email(email);
  regreq.mutable_email_login_req()->set_verify_code_id(vid);
  regreq.mutable_email_login_req()->set_verify_code(vcode);
  SendToServer(regreq.SerializeAsString());
  while (true) {
    char buf[10000];
    int sz = SSL_read(ssl, buf, sizeof(buf));
    buffer.WriteAndPush(buf, sz);
    std::string lenLine = buffer.GetLine();
    if (lenLine.empty()) {
      continue;
    }
    int bodyLen = 0;
    try {
      bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
    } catch (...) {
      buffer.Clear();
      return;
    }
    if (buffer.ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen)) {
      continue;
    }
    buffer.MoveReadIndex(lenLine.size());
    std::string data = buffer.ReadAsStringAndPop(bodyLen);
    ClientMessage regmsg;
    if (!regmsg.ParseFromString(data)) {
      continue;
    }
    if (regmsg.type() != ClientMessageType::EmailLoginRspType) {
      continue;
    }
    auto& rsp = regmsg.email_login_rsp();
    if (rsp.success()) {
      std::cout << Green << "登陆成功" << Tail << std::endl;
      uid = rsp.user_id();
      uemail = rsp.email();
      std::cout << Yellow;
      for (int i = 0; i < rsp.friend__size(); ++i) {
        printf("[好友][%10s]", rsp.friend_(i).friend_name().c_str());
        if (rsp.friend_(i).message_type() == MessageType::file) {
          printf("[文件]:%s\n", rsp.friend_(i).body().c_str());
        } else if (rsp.friend_(i).message_type() == MessageType::string) {
          printf("[消息]:%s\n", rsp.friend_(i).body().c_str());
        }
      }
      for (int i = 0; i < rsp.session_size(); ++i) {
        printf("[群聊：%10s][%10s]", rsp.session(i).session_name().c_str(),
               rsp.session(i).sender_name().c_str());
        if (rsp.session(i).message_type() == MessageType::file) {
          printf("[文件]:%s\n", rsp.session(i).body().c_str());
        } else if (rsp.session(i).message_type() == MessageType::string) {
          printf("[消息]:%s\n", rsp.session(i).body().c_str());
        }
      }
      std::cout << Tail;
      std::string start;
      std::cout << Yellow << "输入chat以开始：";
      std::cin.clear();
      std::cin >> start;
      std::cout << Tail;
      while (start != "chat") {
        start.clear();
        std::cout << Red << "请重新输入：" << Tail << Yellow;
        std::cin.clear();
        std::cin >> start;
      }
      std::thread recv(Recv);
      recv.detach();
      Menu();
    } else {
      if (rsp.errmsg() == "验证码错误") {
        vcode.clear();
        std::cout << Red << "验证码错误，请重新输入：" << Tail << Yellow;
        std::cin.clear();
        std::cin >> vcode;
        std::cout << Tail;
        regreq.mutable_email_login_req()->set_verify_code(vcode);
        SendToServer(regreq.SerializeAsString());
        continue;
      } else {
        std::cout << Red << rsp.errmsg() << "，失败退出\n" << Tail;
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    }
    break;
  }
}

void Login() {
  int flag = 0;
  while (true) {
    system("clear");
    std::cout << Cyan;
    std::cout << " ______________________________________________________\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                   (1) 账号密码登陆                   |\n"
              << "|                   (2) 邮箱登陆                       |\n"
              << "|                   (3) 退出                           |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << " ——————————————————————————————————————————————————————\n"
              << Tail;
    std::cout << Yellow << "请输入您要进行的操作: ";
    std::cin.clear();
    std::cin >> flag;
    std::cout << Tail;
    switch (flag) {
      case 1:
        UserLogin();
        return;
      case 2:
        EmailLogin();
        return;
      case 3:
        return;
      default:
        std::cout << Red << "无效的操作" << Tail << std::endl;
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::this_thread::sleep_for(std::chrono::seconds(1));
        break;
    }
  }
}

void Start() {
  int flag = 0;
  while (ifrunning) {
    system("clear");
    std::cout << Cyan;
    std::cout << " ______________________________________________________\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                   (1) 用户注册                       |\n"
              << "|                   (2) 用户登陆                       |\n"
              << "|                   (3) 退出                           |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << "|                                                      |\n"
              << " ——————————————————————————————————————————————————————\n"
              << Tail;
    std::cout << Yellow << "请输入您要进行的操作: ";
    std::cin.clear();
    std::cin >> flag;
    std::cout << Tail;
    switch (flag) {
      case 1:
        UserRegister();
        break;
      case 2:
        Login();
        break;
      case 3:
        return;
      default:
        std::cout << Red << "无效的操作" << Tail << std::endl;
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::this_thread::sleep_for(std::chrono::seconds(1));
        break;
    }
  }
}
}  // namespace Xianwei