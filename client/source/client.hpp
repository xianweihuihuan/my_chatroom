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
int vcodefd;
int selfefd;
SSL* ssl;
std::string vid;
std::string vcode;
std::string uid;
std::mutex iolock;
std::atomic<bool> running{true};

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
  std::cin >> nickname;
  std::cout << Tail;
  while (!Check_nickname(nickname)) {
    nickname.clear();
    std::cout << Red << "用户名过长，请重新输入：" << Tail << Yellow;
    std::cin >> nickname;
    std::cout << Tail;
  }

  std::cout << Yellow << "请输入密码(7~14位)：";
  std::cin >> password;
  std::cout << Tail;
  while (!Check_password(password)) {
    password.clear();
    std::cout << Red << "密码不在要求范围内，请重新输入：" << Tail << Yellow;
    std::cin >> password;
    std::cout << Tail;
  }
  std::cout << Yellow << "请输入邮箱：";
  std::cin >> email;
  std::cout << Tail;
  while (!Check_email(email)) {
    email.clear();
    std::cout << Red << "邮箱不合法，请重新输入：" << Tail << Yellow;
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
      std::cout <<Red<< vcode_rsp.errmsg() <<"退出"<<Tail<< std::endl;
      return;
    }
    vid = vcode_rsp.verify_code_id();
    break;
  }
  std::cout << Yellow << "请输入验证码：";
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
          std::cout << Green << "修改成功\n" << Tail;
        }
      } else {
        {
          std::unique_lock<std::mutex> mtx(iolock);
          std::cout << Red << "修改失败，原因："
                    << msg.set_user_nickname_rsp().errmsg() << Tail;
        }
      }
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
    std::cout << Yellow << "请输入你的昵称：";
    std::cin >> nickname;
  }
  while (!Check_nickname(nickname)) {
    nickname.clear();
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << "用户名过长，请重新输入：";
      std::cin >> nickname;
    }
  }
  ServerMessage req;
  req.set_type(ServerMessageType::SetNicknameReqType);
  req.mutable_set_user_nickname_req()->set_user_id(uid);
  req.mutable_set_user_nickname_req()->set_nickname(nickname);
  SendToServer(req.SerializeAsString());
  ReadEventfd(selfefd);
}

void about() {
  while (true) {
    int flag = 0;
    system("clear");
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
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow << "请输入您要进行的操作: " << Tail;
      std::cin >> flag;
    }
    switch (flag) {
      case 1:
        break;
      case 2:
        UpdateNickname();
        break;
      case 3:
        break;
      case 4:
        break;
      case 5:
        break;
      case 6:
        return;
      default:
        std::cout << "无效的操作" << std::endl;
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::this_thread::sleep_for(std::chrono::seconds(1));
        break;
    }
  }
}

void Menu() {
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
    {
      std::unique_lock<std::mutex> mtx(iolock);
      std::cout << Yellow << "请输入您要进行的操作: " << Tail;
      std::cin >> flag;
    }
    switch (flag) {
      case 1:

        break;
      case 2:

        break;
      case 3:
        about();
        break;
      case 4:
        return;
      default:
        std::cout << "无效的操作" << std::endl;
        std::cin.clear();  // 清除错误标志位
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::this_thread::sleep_for(std::chrono::seconds(1));
        break;
    }
  }
}

void UserLogin() {
  std::string nickname;
  std::string password;
  std::cout << Yellow << "请输入你的昵称：";
  std::cin >> nickname;
  std::cout << Tail;
  while (!Check_nickname(nickname)) {
    nickname.clear();
    std::cout << Red << "用户名过长，请重新输入：" << Tail << Yellow;
    std::cin >> nickname;
    std::cout << Tail;
  }
  std::cout << Yellow << "请你的输入密码(7~14位)：";
  std::cin >> password;
  std::cout << Tail;
  while (!Check_password(password)) {
    password.clear();
    std::cout << Red << "密码不在要求范围内，请重新输入：" << Tail << Yellow;
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
      std::cout << Yellow;
      for (int i = 0; i < rsp.friend_name_size(); ++i) {
        printf("[好友][%10s]:离线消息\n", rsp.friend_name(i).c_str());
      }
      for (int i = 0; i < rsp.group_name_size(); ++i) {
        printf("[群聊][%10s]:离线消息\n", rsp.group_name(i).c_str());
      }
      std::cout << Tail;
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
  std::cin >> email;
  std::cout << Tail;
  while (!Check_email(email)) {
    email.clear();
    std::cout << Red << "邮箱不合法，请重新输入：" << Tail << Yellow;
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
      std::cout << Yellow;
      for (int i = 0; i < rsp.friend_name_size(); ++i) {
        printf("[好友][%10s]:离线消息\n", rsp.friend_name(i).c_str());
      }
      for (int i = 0; i < rsp.group_name_size(); ++i) {
        printf("[群聊][%10s]:离线消息\n", rsp.group_name(i).c_str());
      }
      std::cout << Tail;

      std::thread recv(Recv);
      recv.detach();
      Menu();
      // std::this_thread::sleep_for(std::chrono::seconds(10));
      // std::this_thread::sleep_for(std::chrono::seconds(1));
    } else {
      if (rsp.errmsg() == "验证码错误") {
        vcode.clear();
        std::cout << "验证码错误，请重新输入：";
        std::cin >> vcode;
        regreq.mutable_email_login_req()->set_verify_code(vcode);
        SendToServer(regreq.SerializeAsString());
        continue;
      } else {
        std::cout << rsp.errmsg() << "，失败退出\n" << Tail;
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    }
    break;
  }
}

void Login() {
  int flag = 0;
  do {
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
    std::cin >> flag;
    std::cout << Tail;
    switch (flag) {
      case 1:
        UserLogin();
        break;
      case 2:
        EmailLogin();
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
  } while (flag < 1 || flag > 3);
}

void Start() {
  int flag = 0;
  do {
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
  } while (true);
}

}  // namespace Xianwei