#pragma once
#include "TcpServer.h"
#include "chat.pb.h"
#include "conn.hpp"

namespace Xianwei {

Conn connle;

void Onclose(const PtrConnection& conn) {
  auto uid = connle.Uid(conn);
  if (!uid.empty()) {
    conn->GetOwner()->GetStatus()->Remove(uid);
  }
  connle.Remove(conn);
}

bool Check_email(const std::string& address) {
  std::regex reg(R"(^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$)");
  std::smatch mat;
  return std::regex_match(address, mat, reg);
}

void SendToClient(const PtrConnection& conn, const std::string& msg) {
  std::string body = std::to_string(msg.size()) + "\r\n" + msg;
  conn->Send(body.c_str(), body.size());
}

void SendVcode(const PtrConnection& conn, const EmailVerifyCodeReq& req);
void UserRegister(const PtrConnection& conn, const UserRegisterReq& req);
void UserLogin(const PtrConnection& conn, const UserLoginReq& req);
void EmailLogin(const PtrConnection& conn, const EmailLoginReq& req);

void HandleMessage(const PtrConnection& conn, ServerMessage& msg) {
  switch (msg.type()) {
    case ServerMessageType::UserRegisterReqType:
      LOG_DEBUG("收到用户注册请求");
      UserRegister(conn, msg.user_register_req());
      break;
    case ServerMessageType::UserLoginReqType:
      LOG_DEBUG("收到用户账号密码登陆请求");
      UserLogin(conn, msg.user_login_req());
      break;
    case ServerMessageType::EmailVcodeReqType:
      LOG_DEBUG("收到用户获取验证码请求");
      SendVcode(conn, msg.email_verify_code_req());
      break;
    case ServerMessageType::EmailLoginReqType:
      LOG_DEBUG("收到用户邮箱登陆请求");
      EmailLogin(conn, msg.email_login_req());
      break;
    case ServerMessageType::SetNicknameReqType:
      LOG_DEBUG("收到用户更改昵称请求");
      break;
  }
}

void OnMessage(const PtrConnection& conn, Buffer* buf) {
  while (true) {
    // 1) 尝试获取一行（包含 "\r\n"）；若没有完整行则退出
    std::string lenLine = buf->GetLine();
    if (lenLine.empty()) {
      // 缓冲区中还没读到 CRLF 结束的长度行
      break;
    }
    // lenLine 形如 "123\r\n"，长度 = lenLine.size()
    // 2) 解析消息体长度（去掉末尾 "\r\n"）
    int bodyLen = 0;
    try {
      bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
    } catch (...) {
      // 非法长度，直接断开连接
      buf->Clear();
      conn->Shutdown();
      return;
    }
    // 3) 若缓冲区中还没收到完整消息体，则保留长度行，等待更多数据
    if (buf->ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen)) {
      break;
    }
    // 4) 消费掉长度行
    buf->MoveReadIndex(lenLine.size());
    // 5) 读取并弹出 bodyLen 字节的 protobuf 数据
    std::string data = buf->ReadAsStringAndPop(bodyLen);
    // 6) 反序列化并分发
    ServerMessage msg;
    if (!msg.ParseFromString(data)) {
      // 解析失败，丢弃并继续
      continue;
    }
    HandleMessage(conn, msg);
  }
}

void SendVcode(const PtrConnection& conn, const EmailVerifyCodeReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::EmailVcodeRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_email_verify_code_rsp()->set_success(false);
    rsp.mutable_email_verify_code_rsp()->set_errmsg(msg);
    return;
  };
  std::string email = req.email();
  if (!Check_email(email)) {
    LOG_ERROR("用户邮箱地址不合法——{}", email);
    errfunc("用户邮箱地址不合法");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string code = generate_code();
  std::string code_id = uuid();
  VerificationCodeSend::ptr ver_client = conn->GetOwner()->GetVerClient();
  Codes::ptr redis_codes = conn->GetOwner()->GetCodes();
  if (!ver_client->Send(email, code)) {
    LOG_ERROR("{}：验证码发送失败", email);
    errfunc("验证码发送失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  redis_codes->Append(code_id, code);
  rsp.mutable_email_verify_code_rsp()->set_success(true);
  rsp.mutable_email_verify_code_rsp()->set_verify_code_id(code_id);
  rsp.mutable_email_verify_code_rsp()->set_verify_code(code);
  SendToClient(conn, rsp.SerializeAsString());
}

void UserRegister(const PtrConnection& conn, const UserRegisterReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::UserRegisterRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_user_register_rsp()->set_success(false);
    rsp.mutable_user_register_rsp()->set_errmsg(msg);
    return;
  };
  std::string nickname = req.nickname();
  std::string email = req.email();
  std::string password = req.password();
  auto user = conn->GetOwner()->GetUserTable()->Select_by_nickname(nickname);
  if (user) {
    LOG_ERROR("{}用户名已存在", nickname);
    errfunc("该用户名已存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  user = conn->GetOwner()->GetUserTable()->Select_by_email(email);
  if (user) {
    LOG_ERROR("{}，该邮箱已经注册过用户", email);
    errfunc("该邮箱已经注册过用户");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string vid = req.verify_code_id();
  std::string vcode = req.verify_code();
  auto rvcode = conn->GetOwner()->GetCodes()->Code(vid);
  if (!rvcode) {
    LOG_ERROR("{}不存在此验证码或该验证码已过期", vid);
    errfunc("不存在此验证码或该验证码已过期");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (vcode != rvcode) {
    LOG_ERROR("验证码错误 {}-{}", vid, vcode);
    errfunc("验证码错误");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  conn->GetOwner()->GetCodes()->Remove(vid);
  std::string uid = uuid();
  user = std::make_shared<User>(uid, nickname, password, email);
  if (!conn->GetOwner()->GetUserTable()->Insert(user)) {
    LOG_ERROR("Mysql添加用户失败");
    errfunc("Mysql添加用户失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_user_register_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void UserLogin(const PtrConnection& conn, const UserLoginReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::UserLoginRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_user_login_rsp()->set_success(false);
    rsp.mutable_user_login_rsp()->set_errmsg(msg);
    return;
  };
  std::string nickname = req.nickname();
  std::string password = req.password();
  auto user = conn->GetOwner()->GetUserTable()->Select_by_nickname(nickname);
  if (!user || password != user->Password()) {
    LOG_ERROR("用户名或密码错误：{} - {}", nickname, password);
    errfunc("用户名或密码错误");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (conn->GetOwner()->GetStatus()->Exists(user->UserId())) {
    LOG_ERROR("{} : 该用户已在别处登陆", user->UserId());
    errfunc("该用户已在别处登陆");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  conn->GetOwner()->GetStatus()->Append(user->UserId());
  connle.Insert(conn, user->UserId());
  conn->GetOwner()->GetOfflineMessage()->SingleAppend("11111111111111",
                                                      user->UserId());
  conn->GetOwner()->GetOfflineMessage()->SingleAppend("11111111111111",
                                                      user->UserId());
  auto user_id =
      conn->GetOwner()->GetOfflineMessage()->GetSingle(user->UserId());
  for (auto& n : user_id) {
    rsp.mutable_user_login_rsp()->add_friend_name(n);
  }
  auto group_id =
      conn->GetOwner()->GetOfflineMessage()->GetGroup(user->UserId());
  for (auto& n : group_id) {
    rsp.mutable_user_login_rsp()->add_group_name(n);
  }
  conn->GetOwner()->GetOfflineMessage()->Remove(user->UserId());
  rsp.mutable_user_login_rsp()->set_user_id(user->UserId());
  rsp.mutable_user_login_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void EmailLogin(const PtrConnection& conn, const EmailLoginReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::EmailLoginRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_email_login_rsp()->set_errmsg(msg);
    rsp.mutable_email_login_rsp()->set_success(false);
    return;
  };
  std::string email = req.email();
  std::string vcode = req.verify_code();
  std::string vid = req.verify_code_id();
  if (!Check_email(email)) {
    LOG_ERROR("用户邮箱地址不合法——{}", email);
    errfunc("用户邮箱地址不合法");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto user = conn->GetOwner()->GetUserTable()->Select_by_email(email);
  if (!user) {
    LOG_ERROR("{} 未注册用户", email);
    errfunc("该邮箱未注册用户");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto rvcode = conn->GetOwner()->GetCodes()->Code(vid);
  if (rvcode != vcode) {
    LOG_ERROR("验证码错误 {}-{}", vid, vcode);
    errfunc("验证码错误");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  conn->GetOwner()->GetCodes()->Remove(vid);
  if (conn->GetOwner()->GetStatus()->Exists(user->UserId())) {
    LOG_ERROR("{} : 该用户已在别处登陆", user->UserId());
    errfunc("该用户已在别处登陆");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  conn->GetOwner()->GetStatus()->Append(user->UserId());
  connle.Insert(conn, user->UserId());
  conn->GetOwner()->GetOfflineMessage()->SingleAppend("11111111111111",
                                                      user->UserId());
  conn->GetOwner()->GetOfflineMessage()->SingleAppend("11111111111111",
                                                      user->UserId());
  conn->GetOwner()->GetOfflineMessage()->GroupAppend("321321", user->UserId());
  auto user_id =
      conn->GetOwner()->GetOfflineMessage()->GetSingle(user->UserId());
  for (auto& n : user_id) {
    rsp.mutable_email_login_rsp()->add_friend_name(n);
  }
  auto group_id =
      conn->GetOwner()->GetOfflineMessage()->GetGroup(user->UserId());
  for (auto& n : group_id) {
    rsp.mutable_email_login_rsp()->add_group_name(n);
  }
  conn->GetOwner()->GetOfflineMessage()->Remove(user->UserId());
  rsp.mutable_email_login_rsp()->set_user_id(user->UserId());
  rsp.mutable_email_login_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}
}  // namespace Xianwei
