#pragma once
#include <arpa/inet.h>
#include <gflags/gflags.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <cstdlib>
#include <iostream>
#include <regex>
#include "Buffer.h"
#include "Socket.h"
#include "chat.pb.h"

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
bool vsuccess;
bool friendsuccess;
bool selfsuccess;
SSL* ssl;
std::string vid;
std::string vcode;
std::string uid;
std::string uemail;
std::mutex iolock;
std::atomic<bool> running{true};
std::vector<Xianwei::UserInfo> friend_apply;
std::vector<Xianwei::UserInfo> friend_list;

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
  SSL_write(ssl, message.c_str(), message.size());
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
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
      if (!msg.set_user_nickname_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "修改失败，原因："
                    << msg.set_user_nickname_rsp().errmsg() << Tail
                    << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
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
        std::this_thread::sleep_for(std::chrono::seconds(3));
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "获取个人信息失败，原因："
                    << msg.get_user_info_rsp().errmsg() << Tail << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
      WakeUpEventFd(selfefd);
      break;
    case ClientMessageType::FriendLoginNoticeType: {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow << "[通知]：你的好友"
                << msg.friend_login_notice().name() << "已上线" << std::endl;
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
      std::this_thread::sleep_for(std::chrono::seconds(1));
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
        std::this_thread::sleep_for(std::chrono::seconds(1));
        WakeUpEventFd(selfefd);
      } else {
        if (msg.set_user_email_rsp().errmsg() == "验证码错误") {
          vsuccess = false;
          selfsuccess = true;
          WakeUpEventFd(selfefd);
        } else {
          {
            std::unique_lock<std::mutex> mtx(iolock);
            std::cout << Red << "修改邮箱信息失败，原因："
                      << msg.set_user_email_rsp().errmsg() << Tail << std::endl;
          }
          vsuccess = true;
          selfsuccess = false;
          std::this_thread::sleep_for(std::chrono::seconds(3));
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
        std::this_thread::sleep_for(std::chrono::seconds(1));
        WakeUpEventFd(selfefd);
      } else {
        if (msg.set_user_password_rsp().errmsg() == "验证码错误") {
          vsuccess = false;
          selfsuccess = true;
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
          std::this_thread::sleep_for(std::chrono::seconds(3));
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
        std::this_thread::sleep_for(std::chrono::seconds(1));
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "发送好友申请失败，原因："
                    << msg.email_friend_add_rsp().errmsg() << Tail << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::NicknameFriendAddRspType:
      if (msg.nickname_friend_add_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "发送好友申请成功" << Tail << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "发送好友申请失败，原因："
                    << msg.nickname_friend_add_rsp().errmsg() << Tail
                    << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
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
        std::this_thread::sleep_for(std::chrono::seconds(2));
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
        std::this_thread::sleep_for(std::chrono::seconds(2));
      }
      WakeUpEventFd(friendefd);
      break;
    case ClientMessageType::SovelFriendApplyRspType:
      if (msg.sovel_friend_apply_rsp().success()) {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Green << "处理好友申请事件成功" << Tail << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "处理好友申请事件失败，原因："
                    << msg.sovel_friend_apply_rsp().errmsg() << Tail
                    << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
      }
      WakeUpEventFd(friendefd);
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
    std::cout << Yellow << "请输入你的新昵称：";
    std::cin.clear();
    std::cin >> nickname;
    std::cout << Tail;
  }
  while (!Check_nickname(nickname)) {
    nickname.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "用户名过长，请重新输入：" << Tail << Yellow;
      std::cin.clear();
      std::cin >> nickname;
      std::cout << Tail;
    }
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
    std::cout << "请输入你的新邮箱：";
    std::cin.clear();
    std::cin >> newemail;
    std::cout << Tail;
  }
  while (!Check_email(newemail)) {
    newemail.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "邮箱不合法，请重新输入：" << Tail << Yellow;
      std::cin.clear();
      std::cin >> newemail;
      std::cout << Tail;
    }
  }
  std::string ensure;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow;
    std::cout << "现在开始获取验证码(y/n)：";
    std::cin.clear();
    std::cin >> ensure;
    std::cout << Tail;
  }
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
      std::cout << Red << "未知操作，请重新输入：" << Tail << Yellow;
      std::cin.clear();
      std::cin >> ensure;
      std::cout << Tail;
    }
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
    std::cout << Yellow << "请输入验证码：";
    std::cin.clear();
    std::cin >> vcode;
    std::cout << Tail;
  }
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
        std::cout << Red << "验证码错误，请重新输入：" << Tail << Yellow;
        std::cin.clear();
        std::cin >> vcode;
        std::cout << Tail;
      }
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
    std::cout << Yellow << "请输入你的新密码(7~14位)：";
    std::cin.clear();
    std::cin >> password;
    std::cout << Tail;
  }
  while (!Check_password(password)) {
    password.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "密码不在要求范围内，请重新输入：" << Tail << Yellow;
      std::cin.clear();
      std::cin >> password;
      std::cout << Tail;
    }
  }
  std::string ensure;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Yellow;
    std::cout << "现在开始获取验证码(y/n)：";
    std::cin.clear();
    std::cin >> ensure;
    std::cout << Tail;
  }
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
      std::cout << Red << "未知操作，请重新输入：" << Tail << Yellow;
      std::cin.clear();
      std::cin >> ensure;
      std::cout << Tail;
    }
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
    std::cout << Yellow << "请输入验证码：";
    std::cin.clear();
    std::cin >> vcode;
    std::cout << Tail;
  }
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
        std::cout << Red << "验证码错误，请重新输入：" << Tail << Yellow;
        std::cin.clear();
        std::cin >> vcode;
        std::cout << Tail;
      }
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
    std::cout << "请输入对方的邮箱：";
    std::cin.clear();
    std::cin >> email;
    std::cout << Tail;
  }
  while (!Check_email(email)) {
    email.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "邮箱不合法，请重新输入：" << Tail << Yellow;
      std::cin.clear();
      std::cin >> email;
      std::cout << Tail;
    }
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
    std::cout << Yellow << "请输入对方的昵称：";
    std::cin.clear();
    std::cin >> nickname;
    std::cout << Tail;
  }
  while (!Check_nickname(nickname)) {
    nickname.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Red << "用户名过长，请重新输入：" << Tail << Yellow;
      std::cin.clear();
      std::cin >> nickname;
      std::cout << Tail;
    }
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
    system("clear");
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
      std::cout << Yellow << "请输入您要进行的操作: ";
      std::cin.clear();
      std::cin >> flag;
      std::cout << Tail;
    }
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
        std::this_thread::sleep_for(std::chrono::seconds(1));
        break;
      }
    }
  }
}

void SovelApply() {
  int flag = 0;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "请输入你要处理的好友申请编号：" << Tail;
    std::cin.clear();
    std::cout << Yellow;
    std::cin >> flag;
    std::cout << Tail;
  }
  {
    std::unique_lock<std::mutex> mtx(iolock);
    while (flag < 1 || flag > friend_apply.size()) {
      std::cout << Red << "不存在编号为此的好友申请，请重新输入：" << Tail
                << Yellow;
      std::cin.clear();
      std::cin >> flag;
    }
  }
  ServerMessage req;
  req.set_type(ServerMessageType::SovelFriendApplyReqType);
  std::string agree;
  {
    std::unique_lock<std::mutex> mtx(iolock);
    std::cout << Cyan << "是否同意该条好友申请(y/n)：" << Tail << Yellow;
    std::cin.clear();
    std::cin >> agree;
    std::cout << Tail;
  }
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
      std::cout << Red << "未知操作，请重新输入：" << Tail << Yellow;
      std::cin.clear();
      std::cin >> agree;
      std::cout << Tail;
    }
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
    system("clear");
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
      std::cout << Yellow << "请输入您要进行的操作: ";
      std::cin.clear();
      std::cin >> flag;
      std::cout << Tail;
    }
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
        std::this_thread::sleep_for(std::chrono::seconds(1));
        break;
      }
    }
  }
}

void GetFriendList() {
  ServerMessage req;
  req.set_type(ServerMessageType::GetFriendListReqType);
  req.mutable_get_friend_list_req()->set_user_id(uid);
  SendToServer(req.SerializeAsString());
  ReadEventfd(friendefd);
  int flag = 0;
  while (true) {
    system("clear");
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow;
      for (int i = 0; i < friend_list.size(); ++i) {
        std::cout << "(" << i + 1 << ") " << friend_list[i].nickname()
                  << " —————— " << friend_list[i].email() << std::endl;
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
      std::cout << Yellow << "请输入您要进行的操作: ";
      std::cin.clear();
      std::cin >> flag;
      std::cout << Tail;
    }
    switch (flag) {
      case 1:
        
        
      case 2:
        return;
      default: {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "无效的操作" << Tail << std::endl;
        }
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::this_thread::sleep_for(std::chrono::seconds(1));
        break;
      }
    }
  }
}

void Friend() {
  while (true) {
    int flag = 0;
    system("clear");
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
                << "|                   (4) 删除好友                       |\n"
                << "|                   (5) 屏蔽好友                       |\n"
                << "|                   (6) 选择好友                       |\n"
                << "|                   (7) 返回上级                       |\n"
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
    }
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
        break;
      case 5:
        break;
      case 6:
        break;
      case 7:
        return;
      default: {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << "无效的操作" << std::endl;
        }
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::this_thread::sleep_for(std::chrono::seconds(1));
        break;
      }
    }
  }
}

void about() {
  while (true) {
    int flag = 0;
    system("clear");
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
      std::cout << Yellow << "请输入您要进行的操作: ";
      std::cin.clear();
      std::cin >> flag;
      std::cout << Tail;
    }
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
        std::this_thread::sleep_for(std::chrono::seconds(1));
        break;
      }
    }
  }
}

void Menu() {
  int flag = 0;
  while (true) {
    system("clear");
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
      std::cout << Yellow << "请输入您要进行的操作: ";
      std::cin.clear();
      std::cin >> flag;
      std::cout << Tail;
    }
    switch (flag) {
      case 1:
        Friend();
        break;
      case 2:
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
        std::this_thread::sleep_for(std::chrono::seconds(1));
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
        printf("[好友][%s]", rsp.friend_(i).friend_name().c_str());
        if (rsp.friend_(i).message_type() == MessageType::file) {
          printf("[文件]:%s\n", rsp.friend_(i).body().c_str());
        } else if (rsp.friend_(i).message_type() == MessageType::string) {
          printf("[消息]:%s\n", rsp.friend_(i).body().c_str());
        }
      }
      for (int i = 0; i < rsp.session_size(); ++i) {
        printf("[群聊][%s]", rsp.session(i).session_name().c_str());
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
        if (rsp.friend_(i).message_type() == MessageType::string) {
          printf("[文件]:%s\n", rsp.friend_(i).body().c_str());
        } else if (rsp.friend_(i).message_type() == MessageType::file) {
          printf("[消息]:%s\n", rsp.friend_(i).body().c_str());
        }
      }
      for (int i = 0; i < rsp.session_size(); ++i) {
        printf("[群聊][%10s]", rsp.session(i).session_name().c_str());
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
      // std::this_thread::sleep_for(std::chrono::seconds(1));
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