#pragma once
#include <json/json.h>
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
void SetNickname(const PtrConnection& conn, const SetUserNicknameReq& req);
void GetUserInfo(const PtrConnection& conn, const GetUserInfoReq& req);
void SetUserEmail(const PtrConnection& conn, const SetUserEmailReq& req);
void SetUserPassword(const PtrConnection& conn, const SetUserPasswordReq& req);
void EmailFriendAdd(const PtrConnection& conn, const EmailFriendAddReq& req);
void NicknameFriendAdd(const PtrConnection& conn,
                       const NicknameFriendAddReq& req);
void GetFriendApply(const PtrConnection& conn, const GetFriendApplyReq& req);
void GetFriendList(const PtrConnection& conn, const GetFriendListReq& req);
void SovelFriendApply(const PtrConnection& conn, const SovelFriendApplyReq& req);

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
      SetNickname(conn, msg.set_user_nickname_req());
      break;
    case ServerMessageType::GetUserInfoReqType:
      LOG_DEBUG("收到用户获取自身信息的请求");
      GetUserInfo(conn, msg.get_user_info_req());
      break;
    case ServerMessageType::SetEmailReqType:
      LOG_DEBUG("收到用户修改邮箱信息的请求");
      SetUserEmail(conn, msg.set_user_email_req());
      break;
    case ServerMessageType::SetPassword:
      LOG_DEBUG("收到用户修改密码信息的请求");
      SetUserPassword(conn, msg.set_user_password_req());
      break;
    case ServerMessageType::EmailFriendAddReqType:
      LOG_DEBUG("收到用户通过邮箱添加好友的请求");
      EmailFriendAdd(conn, msg.email_friend_add_req());
      break;
    case ServerMessageType::NicknameFriendAddReqType:
      LOG_DEBUG("收到用户通过昵称添加好友的请求");
      NicknameFriendAdd(conn, msg.nickname_friend_add_req());
      break;
    case ServerMessageType::GetFriendApplyReqtype:
      LOG_DEBUG("收到用户获取所有好友申请的请求");
      GetFriendApply(conn,msg.get_friend_apply());
      break;
    case ServerMessageType::GetFriendListReqType:
      LOG_DEBUG("收到用户获取好友列表的请求");
      GetFriendList(conn, msg.get_friend_list_req());
      break;
    case ServerMessageType::SovelFriendApplyReqType:
      LOG_DEBUG("收到用户处理好友申请的请求");
      SovelFriendApply(conn, msg.sovel_friend_apply_req());
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
  Json::StreamWriterBuilder wbd;
  Json::Value test;
  test["name"] = "QUMO";
  test["type"] = 1;
  test["body"] = "11111111111111111";
  std::string str = Json::writeString(wbd, test);
  Json::Value test1;
  test1["name"] = "QUMO";
  test1["type"] = 1;
  test1["body"] = "11111111111111111";
  std::string str1 = Json::writeString(wbd, test1);
  conn->GetOwner()->GetOfflineMessage()->SingleAppend(user->UserId(), str);
  conn->GetOwner()->GetOfflineMessage()->SingleAppend(user->UserId(), str1);
  Json::CharReaderBuilder bd;
  std::unique_ptr<Json::CharReader> reader(bd.newCharReader());
  auto user_body =
      conn->GetOwner()->GetOfflineMessage()->GetSingle(user->UserId());
  for (auto& n : user_body) {
    Json::Value body;
    if (reader->parse(n.c_str(), n.c_str() + n.size(), &body, nullptr)) {
      auto me = rsp.mutable_user_login_rsp()->add_friend_();
      me->set_friend_name(body["name"].asString());
      int ty = body["type"].asInt();
      if (ty == 1) {
        me->set_message_type(MessageType::string);
      } else if (ty == 2) {
        me->set_message_type(MessageType::file);
      }
      me->set_body(body["body"].asString());
    }
  }
  auto group_id =
      conn->GetOwner()->GetOfflineMessage()->GetGroup(user->UserId());
  for (auto& n : group_id) {
    Json::Value body;
    if (reader->parse(n.c_str(), n.c_str() + n.size(), &body, nullptr)) {
      auto me = rsp.mutable_user_login_rsp()->add_session();
      me->set_session_name(body["name"].asString());
      int ty = body["type"].asInt();
      if (ty == 1) {
        me->set_message_type(MessageType::string);
      } else if (ty == 2) {
        me->set_message_type(MessageType::file);
      }
      me->set_body(body["body"].asString());
    }
  }
  conn->GetOwner()->GetOfflineMessage()->Remove(user->UserId());
  rsp.mutable_user_login_rsp()->set_user_id(user->UserId());
  rsp.mutable_user_login_rsp()->set_email(user->Email());
  rsp.mutable_user_login_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
  std::string name = user->Nikename();
  auto fid_list = conn->GetOwner()->GetRelationTable()->Friends(user->UserId());
  ClientMessage Nrsp;
  Nrsp.set_type(ClientMessageType::FriendLoginNoticeType);
  Nrsp.mutable_friend_login_notice()->set_name(name);
  for (auto fid : fid_list) {
    auto fconn = connle.Connection(fid);
    if (fconn) {
      SendToClient(fconn, Nrsp.SerializeAsString());
    }
  }
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
  Json::CharReaderBuilder bd;
  std::unique_ptr<Json::CharReader> reader(bd.newCharReader());
  conn->GetOwner()->GetStatus()->Append(user->UserId());
  connle.Insert(conn, user->UserId());
  Json::StreamWriterBuilder wbd;
  Json::Value test;
  test["name"] = "QUMO";
  test["type"] = 1;
  test["body"] = "11111111111111111";
  std::string str = Json::writeString(wbd, test);
  conn->GetOwner()->GetOfflineMessage()->SingleAppend(user->UserId(), str);
  auto user_id =
      conn->GetOwner()->GetOfflineMessage()->GetSingle(user->UserId());
  for (auto& n : user_id) {
    Json::Value body;
    if (reader->parse(n.c_str(), n.c_str() + n.size(), &body, nullptr)) {
      auto me = rsp.mutable_email_login_rsp()->add_friend_();
      me->set_friend_name(body["name"].asString());
      int ty = body["type"].asInt();
      if (ty == 1) {
        me->set_message_type(MessageType::string);
      } else if (ty == 2) {
        me->set_message_type(MessageType::file);
      }
      me->set_body(body["body"].asString());
    }
  }
  auto group_id =
      conn->GetOwner()->GetOfflineMessage()->GetGroup(user->UserId());
  for (auto& n : group_id) {
    Json::Value body;
    if (reader->parse(n.c_str(), n.c_str() + n.size(), &body, nullptr)) {
      auto me = rsp.mutable_email_login_rsp()->add_session();
      me->set_session_name(body["name"].asString());
      int ty = body["type"].asInt();
      if (ty == 1) {
        me->set_message_type(MessageType::string);
      } else if (ty == 2) {
        me->set_message_type(MessageType::file);
      }
      me->set_body(body["body"].asString());
    }
  }
  conn->GetOwner()->GetOfflineMessage()->Remove(user->UserId());
  rsp.mutable_email_login_rsp()->set_user_id(user->UserId());
  rsp.mutable_email_login_rsp()->set_success(true);
  rsp.mutable_email_login_rsp()->set_email(user->Email());
  SendToClient(conn, rsp.SerializeAsString());
  std::string name = user->Nikename();
  auto fid_list = conn->GetOwner()->GetRelationTable()->Friends(user->UserId());
  ClientMessage Nrsp;
  Nrsp.set_type(ClientMessageType::FriendLoginNoticeType);
  Nrsp.mutable_friend_login_notice()->set_name(name);
  for (auto fid : fid_list) {
    auto fconn = connle.Connection(fid);
    if (!fconn) {
      SendToClient(fconn, Nrsp.SerializeAsString());
    }
  }
}

void SetNickname(const PtrConnection& conn, const SetUserNicknameReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::SetNicknameRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_set_user_nickname_rsp()->set_errmsg(msg);
    rsp.mutable_set_user_nickname_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string new_nickname = req.nickname();
  if (new_nickname.empty()) {
    errfunc("昵称不能为空");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto user =
      conn->GetOwner()->GetUserTable()->Select_by_nickname(new_nickname);
  if (user) {
    LOG_ERROR("{}用户名已存在", new_nickname);
    errfunc("该用户名已存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  user = conn->GetOwner()->GetUserTable()->Select_by_uid(uid);
  if (!user) {
    LOG_ERROR("未找到用户信息-{}", uid);
    errfunc("未找到用户信息");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  user->SetNickname(new_nickname);
  if (!conn->GetOwner()->GetUserTable()->Update(user)) {
    LOG_ERROR("Mysql：用户昵称更新失败");
    errfunc("Mysql用户昵称更新失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_set_user_nickname_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void GetUserInfo(const PtrConnection& conn, const GetUserInfoReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GetUserInfoRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_get_user_info_rsp()->set_errmsg(msg);
    rsp.mutable_get_user_info_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(uid);
  if (!user) {
    LOG_ERROR("未找到用户信息-{}", uid);
    errfunc("未找到用户信息");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  UserInfo* user_info = rsp.mutable_get_user_info_rsp()->mutable_user_info();
  user_info->set_user_id(user->UserId());
  user_info->set_nickname(user->Nikename());
  user_info->set_email(user->Email());
  rsp.mutable_get_user_info_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void SetUserEmail(const PtrConnection& conn, const SetUserEmailReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::SetEmailRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_set_user_email_rsp()->set_errmsg(msg);
    rsp.mutable_set_user_email_rsp()->set_success(false);
    return;
  };
  std::string email = req.email();
  std::string uid = req.user_id();
  std::string uvid = req.email_verify_code_id();
  std::string uvcode = req.email_verify_code();
  auto vcode = conn->GetOwner()->GetCodes()->Code(uvid);
  if (vcode != uvcode) {
    LOG_ERROR("验证码错误");
    errfunc("验证码错误");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto euser = conn->GetOwner()->GetUserTable()->Select_by_email(email);
  if (euser) {
    LOG_ERROR("邮箱{}已注册过账号", email);
    errfunc("该邮箱已注册过账号");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(uid);
  if (!user) {
    LOG_ERROR("未找到用户-{}的信息", uid);
    errfunc("未找到用户的信息");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  user->SetEmail(email);
  if (!conn->GetOwner()->GetUserTable()->Update(user)) {
    LOG_ERROR("Mysql：用户邮箱更新失败");
    errfunc("Mysql用户邮箱更新失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_set_user_email_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void SetUserPassword(const PtrConnection& conn, const SetUserPasswordReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::SetPasswordRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_set_user_password_rsp()->set_errmsg(msg);
    rsp.mutable_set_user_password_rsp()->set_success(false);
    return;
  };
  std::string password = req.password();
  std::string uid = req.user_id();
  std::string uvid = req.email_verify_code_id();
  std::string uvcode = req.email_verify_code();
  auto vcode = conn->GetOwner()->GetCodes()->Code(uvid);
  if (vcode != uvcode) {
    LOG_ERROR("验证码错误");
    errfunc("验证码错误");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(uid);
  if (!user) {
    LOG_ERROR("未找到用户-{}的信息", uid);
    errfunc("未找到用户的信息");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (user->Password() == password) {
    LOG_ERROR("新密码不能和旧密码一致");
    errfunc("新密码不能和旧密码一致");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  user->SetPassword(password);
  if (!conn->GetOwner()->GetUserTable()->Update(user)) {
    LOG_ERROR("Mysql：用户密码更新失败");
    errfunc("Mysql用户密码更新失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_set_user_password_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void EmailFriendAdd(const PtrConnection& conn, const EmailFriendAddReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::EmailFriendAddRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_email_friend_add_rsp()->set_errmsg(msg);
    rsp.mutable_email_friend_add_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string email = req.email();
  auto user = conn->GetOwner()->GetUserTable()->Select_by_email(email);
  if (!user) {
    LOG_ERROR("该用户不存在");
    errfunc("该用户不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (user->UserId() == uid) {
    LOG_ERROR("用户不能添加自己为好友");
    errfunc("不能添加自己为好友");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto re = conn->GetOwner()->GetRelationTable()->Exists(uid, user->UserId());
  if (re) {
    LOG_ERROR("两人已经是好友了");
    errfunc("你们已经是好友了");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  re = conn->GetOwner()->GetFriendApplyTable()->Exists(uid, user->UserId());
  if (re) {
    LOG_ERROR("已经发送过好友申请");
    errfunc("已经发送过好友申请");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  FriendApply ap(uuid(), uid, user->UserId());
  re = conn->GetOwner()->GetFriendApplyTable()->Insert(ap);
  if (!re) {
    LOG_ERROR("Mysql新增好友申请事件失败");
    errfunc("Mysql新增好友申请事件失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_email_friend_add_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void NicknameFriendAdd(const PtrConnection& conn,
                       const NicknameFriendAddReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::NicknameFriendAddRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_nickname_friend_add_rsp()->set_errmsg(msg);
    rsp.mutable_nickname_friend_add_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string nickname = req.nickname();
  auto user = conn->GetOwner()->GetUserTable()->Select_by_nickname(nickname);
  if (!user) {
    LOG_ERROR("该用户不存在");
    errfunc("该用户不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (user->UserId() == uid) {
    LOG_ERROR("用户不能添加自己为好友");
    errfunc("不能添加自己为好友");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto re = conn->GetOwner()->GetRelationTable()->Exists(uid, user->UserId());
  if (re) {
    LOG_ERROR("两人已经是好友了");
    errfunc("你们已经是好友了");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  re = conn->GetOwner()->GetFriendApplyTable()->Exists(uid, user->UserId());
  if (re) {
    LOG_ERROR("已经发送过好友申请");
    errfunc("已经发送过好友申请");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  FriendApply ap(uuid(), uid, user->UserId());
  re = conn->GetOwner()->GetFriendApplyTable()->Insert(ap);
  if (!re) {
    LOG_ERROR("Mysql新增好友申请事件失败");
    errfunc("Mysql新增好友申请事件失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_nickname_friend_add_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void GetFriendApply(const PtrConnection& conn, const GetFriendApplyReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GetFriendApplyRsptype);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_get_friend_apply_rsp()->set_errmsg(msg);
    rsp.mutable_get_friend_apply_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  auto aid_list = conn->GetOwner()->GetFriendApplyTable()->ApplyUsers(uid);
  if (aid_list.empty()) {
    LOG_ERROR("无好友申请或获取好友申请失败");
    errfunc("无好友申请或获取好友申请失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  for (const auto& x : aid_list) {
    auto auser = conn->GetOwner()->GetUserTable()->Select_by_uid(x);
    if (auser) {
      auto info = rsp.mutable_get_friend_apply_rsp()->add_user_info();
      info->set_email(auser->Email());
      info->set_nickname(auser->Nikename());
      info->set_user_id(auser->UserId());
    }
  }
  rsp.mutable_get_friend_apply_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializePartialAsString());
}

void GetFriendList(const PtrConnection& conn, const GetFriendListReq& req){
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GetFriendListRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_get_friend_list_rsp()->set_errmsg(msg);
    rsp.mutable_get_friend_list_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  auto friend_list = conn->GetOwner()->GetRelationTable()->Friends(uid);
  if(friend_list.empty()){
    LOG_ERROR("无好友或获取好友列表失败");
    errfunc("无好友或获取好友列表失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  for(const auto& n : friend_list){
    auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(n);
    if(user){
      auto info = rsp.mutable_get_friend_list_rsp()->add_friend_list();
      info->set_user_id(user->UserId());
      info->set_nickname(user->Nikename());
      info->set_email(user->Email());
    }
  }
  rsp.mutable_get_friend_list_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void SovelFriendApply(const PtrConnection& conn, const SovelFriendApplyReq& req){
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::SovelFriendApplyRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_sovel_friend_apply_rsp()->set_errmsg(msg);
    rsp.mutable_sovel_friend_apply_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  if(!conn->GetOwner()->GetFriendApplyTable()->Exists(pid, uid)){
    LOG_ERROR("不存在好友申请信息{}-{}",pid,uid);
    errfunc("不存在好友申请信息");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if(!conn->GetOwner()->GetFriendApplyTable()->Remove(pid,uid)){
    LOG_ERROR("Mysql好友申请事件删除失败");
    errfunc("Mysql好友申请事件删除失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if(req.agree()){
    if(!conn->GetOwner()->GetRelationTable()->Insert(uid,pid)){
      LOG_ERROR("Mysql添加好友关系失败");
      errfunc("Mysql添加好友关系失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
  }
  rsp.mutable_sovel_friend_apply_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

}  // namespace Xianwei
