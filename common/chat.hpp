#pragma once
#include <json/json.h>
#include "TcpServer.h"
#include "chat.pb.h"
#include "conn.hpp"
#include "file.pb.h"

namespace Xianwei {

Conn connle;

std::shared_ptr<MessageCache> cache;

void SendToClient(const PtrConnection& conn, const std::string& msg) {
  std::string body = std::to_string(msg.size()) + "\r\n" + msg;
  conn->Send(body.c_str(), body.size());
}

void Onclose(const PtrConnection& conn) {
  std::string uid;
  uid = connle.Uid(conn);
  if (!uid.empty()) {
    auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(uid);
    auto friends = conn->GetOwner()->GetRelationTable()->Friends(uid);
    ClientMessage no;
    no.set_type(ClientMessageType::FriendOffNoticeType);
    no.mutable_friend_off_notice()->set_name(user->Nikename());
    for (auto& n : friends) {
      auto pconn = connle.Connection(n);
      if (pconn) {
        SendToClient(pconn, no.SerializeAsString());
      }
    }
    conn->GetOwner()->GetStatus()->Remove(uid);
  }
  connle.Remove(conn);
}

bool Check_email(const std::string& address) {
  std::regex reg(R"(^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$)");
  std::smatch mat;
  return std::regex_match(address, mat, reg);
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
void SovelFriendApply(const PtrConnection& conn,
                      const SovelFriendApplyReq& req);
void IgnoreFriend(const PtrConnection& conn, const IgnoreFriendReq& req);
void UnIgnoreFriend(const PtrConnection& conn, const UnIgnoreFriendReq& req);
void GetFriendInfo(const PtrConnection& conn, const GetFriendInfoReq& req);
void FriendSendMessage(const PtrConnection& conn,
                       const FriendSendMessageReq& req);
void DeleteFriend(const PtrConnection& conn, const DeleteFriendReq& req);
void FriendHistoryMessage(const PtrConnection& conn,
                          const FriendHistoryMessageReq& req);
void FriendSendFile(const PtrConnection& conn, const FriendSendFileReq& req);
void FriendGetFile(const PtrConnection& conn, const FriendGetFileReq& req);
void CreateGroup(const PtrConnection& conn, const CreateGroupReq& req);
void GetGroupList(const PtrConnection& conn, const GetGroupListReq& req);
void UserAddGroup(const PtrConnection& conn, const UserAddGroupReq& req);
void GetSessionApply(const PtrConnection& conn, const GetSessionApplyReq& req);
void SovelGroupApply(const PtrConnection& conn, const SovelGroupApplyReq& req);
void GetMemberList(const PtrConnection& conn, const GetMemberListReq& req);
void SetGroupAdmin(const PtrConnection& conn, const SetGroupAdminReq& req);
void CancelGroupAdmin(const PtrConnection& conn,
                      const CancelGroupAdminReq& req);
void GroupAddFriend(const PtrConnection& conn, const GroupAddFriendReq& req);
void GroupDelFriend(const PtrConnection& conn, const GroupDelMemberReq& req);
void OwnerCancelGroup(const PtrConnection& conn,
                      const OwnerCancelGroupReq& req);
void MemberExitGroup(const PtrConnection& conn, const MemberExitGroupReq& req);
void GroupSendMessage(const PtrConnection& conn,
                      const GroupSendMessageReq& req);
void GroupSendFile(const PtrConnection& conn, const GroupSendFileReq& req);
void GroupGetFile(const PtrConnection& conn, const GroupGetFileReq& req);
void GroupHistoryMessage(const PtrConnection& conn,
                         const GroupHistoryMessageReq& req);
void UserDelSelf(const PtrConnection& conn, const UserDelSelfReq& req);

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
      GetFriendApply(conn, msg.get_friend_apply());
      break;
    case ServerMessageType::GetFriendListReqType:
      LOG_DEBUG("收到用户获取好友列表的请求");
      GetFriendList(conn, msg.get_friend_list_req());
      break;
    case ServerMessageType::SovelFriendApplyReqType:
      LOG_DEBUG("收到用户处理好友申请的请求");
      SovelFriendApply(conn, msg.sovel_friend_apply_req());
      break;
    case ServerMessageType::IgnoreFriendReqType:
      LOG_DEBUG("收到用户屏蔽好友的请求");
      IgnoreFriend(conn, msg.ignore_friend_req());
      break;
    case ServerMessageType::UnIgnoreFriendReqType:
      LOG_DEBUG("收到用户解除好友屏蔽的请求");
      UnIgnoreFriend(conn, msg.unignore_friend_req());
      break;
    case ServerMessageType::GetFriendInfoReqType:
      LOG_DEBUG("收到用户获取好友信息的请求");
      GetFriendInfo(conn, msg.get_friend_info_req());
      break;
    case ServerMessageType::FriendSendMessageReqType:
      LOG_DEBUG("收到用户向好友发送消息的请求");
      FriendSendMessage(conn, msg.friend_send_message_req());
      break;
    case ServerMessageType::DeleteFriendReqType:
      LOG_DEBUG("收到用户删除好友的请求");
      DeleteFriend(conn, msg.delete_friend_req());
      break;
    case ServerMessageType::FriendHistoryMessageReqType:
      LOG_DEBUG("收到用户获取好友历史消息的请求");
      FriendHistoryMessage(conn, msg.friend_history_message_req());
      break;
    case ServerMessageType::FriendSendFileReqType:
      LOG_DEBUG("收到用户上传文件的请求");
      FriendSendFile(conn, msg.friend_send_file_req());
      break;
    case ServerMessageType::FriendGetFileReqType:
      LOG_DEBUG("收到用户下载文件的请求");
      FriendGetFile(conn, msg.friend_get_file_req());
      break;
    case ServerMessageType::CreateGroupReqType:
      LOG_DEBUG("收到用户创建群聊的请求");
      CreateGroup(conn, msg.create_group_req());
      break;
    case ServerMessageType::GetGroupListReqType:
      LOG_DEBUG("收到用户获取群聊列表的请求");
      GetGroupList(conn, msg.get_group_list_req());
      break;
    case ServerMessageType::UserAddGroupReqType:
      LOG_DEBUG("收到用户加入群聊的请求");
      UserAddGroup(conn, msg.user_add_group_req());
      break;
    case ServerMessageType::GetSessionApplyReqType:
      LOG_DEBUG("收到获取加群申请的请求");
      GetSessionApply(conn, msg.get_session_apply_req());
      break;
    case ServerMessageType::SovelGroupApplyReqType:
      LOG_DEBUG("收到用户处理加群申请的请求");
      SovelGroupApply(conn, msg.sovel_group_apply_req());
      break;
    case ServerMessageType::GetMemberListReqType:
      LOG_DEBUG("收到用户获取群聊成员的请求");
      GetMemberList(conn, msg.get_member_list_req());
      break;
    case ServerMessageType::SetGroupAdminReqType:
      LOG_DEBUG("收到用户设置管理员的请求");
      SetGroupAdmin(conn, msg.set_group_admin_req());
      break;
    case ServerMessageType::CancelGroupAdminReqType:
      LOG_DEBUG("收到用户取消管理员的请求");
      CancelGroupAdmin(conn, msg.cancel_group_admin_req());
      break;
    case ServerMessageType::GroupAddFriendReqType:
      LOG_DEBUG("收到用户邀请好友进群的请求");
      GroupAddFriend(conn, msg.group_add_friend_req());
      break;
    case ServerMessageType::GroupDelMemberReqType:
      LOG_DEBUG("收到用户踢出群员的请求");
      GroupDelFriend(conn, msg.group_del_member_req());
      break;
    case ServerMessageType::OwnerCancelGroupReqType:
      LOG_DEBUG("收到用户解散群聊的请求");
      OwnerCancelGroup(conn, msg.owner_cancel_group_req());
      break;
    case ServerMessageType::MemberExitGroupReqType:
      LOG_DEBUG("收到用户退出群聊的请求");
      MemberExitGroup(conn, msg.member_exit_group_req());
      break;
    case ServerMessageType::GroupSendMessageReqType:
      LOG_DEBUG("收到用户发送群聊信息的请求");
      GroupSendMessage(conn, msg.group_send_message_req());
      break;
    case ServerMessageType::GroupSendFileReqType:
      LOG_DEBUG("收到用户上传群聊文件的请求");
      GroupSendFile(conn, msg.group_send_file_req());
      break;
    case ServerMessageType::GroupGetFileReqType:
      LOG_DEBUG("收到用户下载群文件的请求");
      GroupGetFile(conn, msg.group_get_file_req());
      break;
    case ServerMessageType::GroupHistoryMessageReqType:
      LOG_DEBUG("收到用户获取群聊历史消息的请求");
      GroupHistoryMessage(conn, msg.group_history_message_req());
      break;
    case ServerMessageType::UserDelSelfReqType:
      LOG_DEBUG("收到用户注销账号的请求");
      UserDelSelf(conn, msg.user_del_self_req());
      break;
    default:
      LOG_DEBUG("连接保活");
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
      me->set_sender_name(body["sender"].asString());
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
      me->set_sender_name(body["sender"].asString());
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
    if (fconn) {
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
  if (conn->GetOwner()->GetFriendApplyTable()->Exists(user->UserId(), uid)) {
    LOG_DEBUG("对方以发送过好友申请，建立好友关系");
    conn->GetOwner()->GetFriendApplyTable()->Remove(user->UserId(), uid);
    std::string sid = uuid();
    if (!conn->GetOwner()->GetRelationTable()->Insert(uid, user->UserId(),
                                                      sid)) {
      LOG_ERROR("Mysql添加好友关系失败");
      errfunc("Mysql添加好友关系失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
    std::vector<ChatSessionMember> tmp;
    tmp.emplace_back(sid, uid, Single);
    tmp.emplace_back(sid, user->UserId(), Single);
    if (!conn->GetOwner()->GetChatSessionMemberTable()->Append(tmp)) {
      LOG_ERROR("Mysql创建会话失败");
      errfunc("Mysql创建会话失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
    rsp.mutable_email_friend_add_rsp()->set_success(true);
    return SendToClient(conn, rsp.SerializeAsString());
  }
  FriendApply ap(uuid(), uid, user->UserId());
  re = conn->GetOwner()->GetFriendApplyTable()->Insert(ap);
  if (!re) {
    LOG_ERROR("Mysql新增好友申请事件失败");
    errfunc("Mysql新增好友申请事件失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto pconn = connle.Connection(user->UserId());
  if (pconn) {
    auto tmp = conn->GetOwner()->GetUserTable()->Select_by_uid(uid);
    if (tmp) {
      ClientMessage no;
      no.set_type(ClientMessageType::FriendApplyNoticeType);
      no.mutable_friend_apply_notice()->set_name(tmp->Nikename());
      SendToClient(pconn, no.SerializeAsString());
    }
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
  if (conn->GetOwner()->GetFriendApplyTable()->Exists(user->UserId(), uid)) {
    LOG_DEBUG("对方以发送过好友申请，建立好友关系");
    conn->GetOwner()->GetFriendApplyTable()->Remove(user->UserId(), uid);
    std::string sid = uuid();
    if (!conn->GetOwner()->GetRelationTable()->Insert(uid, user->UserId(),
                                                      sid)) {
      LOG_ERROR("Mysql添加好友关系失败");
      errfunc("Mysql添加好友关系失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
    std::vector<ChatSessionMember> tmp;
    tmp.emplace_back(sid, uid, Single);
    tmp.emplace_back(sid, user->UserId(), Single);
    if (!conn->GetOwner()->GetChatSessionMemberTable()->Append(tmp)) {
      LOG_ERROR("Mysql创建会话失败");
      errfunc("Mysql创建会话失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
    rsp.mutable_nickname_friend_add_rsp()->set_success(true);
    return SendToClient(conn, rsp.SerializeAsString());
  }
  FriendApply ap(uuid(), uid, user->UserId());
  re = conn->GetOwner()->GetFriendApplyTable()->Insert(ap);
  if (!re) {
    LOG_ERROR("Mysql新增好友申请事件失败");
    errfunc("Mysql新增好友申请事件失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto pconn = connle.Connection(user->UserId());
  if (pconn) {
    auto tmp = conn->GetOwner()->GetUserTable()->Select_by_uid(uid);
    if (tmp) {
      ClientMessage no;
      no.set_type(ClientMessageType::FriendApplyNoticeType);
      no.mutable_friend_apply_notice()->set_name(tmp->Nikename());
      SendToClient(pconn, no.SerializeAsString());
    }
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

void GetFriendList(const PtrConnection& conn, const GetFriendListReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GetFriendListRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_get_friend_list_rsp()->set_errmsg(msg);
    rsp.mutable_get_friend_list_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  auto friend_list = conn->GetOwner()->GetRelationTable()->Friends(uid);
  if (friend_list.empty()) {
    LOG_ERROR("无好友或获取好友列表失败");
    errfunc("无好友或获取好友列表失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  for (const auto& n : friend_list) {
    auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(n);
    if (user) {
      auto info = rsp.mutable_get_friend_list_rsp()->add_friend_list();
      info->set_user_id(user->UserId());
      info->set_nickname(user->Nikename());
      info->set_email(user->Email());
      if (conn->GetOwner()->GetStatus()->Exists(n)) {
        info->set_iflogin(true);
      } else {
        info->set_iflogin(false);
      }
    }
  }
  rsp.mutable_get_friend_list_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void SovelFriendApply(const PtrConnection& conn,
                      const SovelFriendApplyReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::SovelFriendApplyRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_sovel_friend_apply_rsp()->set_errmsg(msg);
    rsp.mutable_sovel_friend_apply_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  if (!conn->GetOwner()->GetFriendApplyTable()->Exists(pid, uid)) {
    LOG_ERROR("不存在好友申请信息{}-{}", pid, uid);
    errfunc("不存在好友申请信息");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetFriendApplyTable()->Remove(pid, uid)) {
    LOG_ERROR("Mysql好友申请事件删除失败");
    errfunc("Mysql好友申请事件删除失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (req.agree()) {
    std::string sid = uuid();
    if (!conn->GetOwner()->GetRelationTable()->Insert(uid, pid, sid)) {
      LOG_ERROR("Mysql添加好友关系失败");
      errfunc("Mysql添加好友关系失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
    ChatSession ss(sid, SINGLE);
    if (!conn->GetOwner()->GetChatSessionTable()->Insert(ss)) {
      LOG_ERROR("Mysql创建会话失败");
      errfunc("Mysql创建会话失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
    std::vector<ChatSessionMember> tmp;
    tmp.emplace_back(sid, uid, Single);
    tmp.emplace_back(sid, pid, Single);
    if (!conn->GetOwner()->GetChatSessionMemberTable()->Append(tmp)) {
      LOG_ERROR("Mysql创建会话成员信息失败");
      errfunc("Mysql创建会话成员信息失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
  }
  rsp.mutable_sovel_friend_apply_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void IgnoreFriend(const PtrConnection& conn, const IgnoreFriendReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::IgnoreFriendRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_ignore_friend_rsp()->set_errmsg(msg);
    rsp.mutable_ignore_friend_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  if (!conn->GetOwner()->GetRelationTable()->Exists(uid, pid)) {
    LOG_ERROR("不存在好友关系{} - {}", uid, pid);
    errfunc("这不是你的好友");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string errmsg;
  bool ret = conn->GetOwner()->GetRelationTable()->Ifignore(uid, pid, errmsg);
  if (ret) {
    LOG_ERROR("已经屏蔽了该好友");
    errfunc("已经屏蔽了该好友");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!errmsg.empty()) {
    LOG_ERROR("Mysql获取是否屏蔽失败");
    errfunc("Mysql获取是否屏蔽失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetRelationTable()->Ignore(uid, pid)) {
    LOG_ERROR("更改Mysql信息失败");
    errfunc("更改Mysql信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_ignore_friend_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}
void UnIgnoreFriend(const PtrConnection& conn, const UnIgnoreFriendReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::UnIgnoreFriendRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_unignore_friend_rsp()->set_errmsg(msg);
    rsp.mutable_unignore_friend_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  if (!conn->GetOwner()->GetRelationTable()->Exists(uid, pid)) {
    LOG_ERROR("不存在好友关系{} - {}", uid, pid);
    errfunc("这不是你的好友");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string errmsg;
  bool ret = conn->GetOwner()->GetRelationTable()->Ifignore(uid, pid, errmsg);
  if (!ret) {
    if (!errmsg.empty()) {
      LOG_ERROR("Mysql获取是否屏蔽失败");
      errfunc("Mysql获取是否屏蔽失败");
      return SendToClient(conn, rsp.SerializeAsString());
    } else {
      LOG_ERROR("未屏蔽该好友");
      errfunc("未屏蔽该好友");
      return SendToClient(conn, rsp.SerializeAsString());
    }
  }
  if (!conn->GetOwner()->GetRelationTable()->Unignore(uid, pid)) {
    LOG_ERROR("更改Mysql信息失败");
    errfunc("更改Mysql信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_unignore_friend_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void GetFriendInfo(const PtrConnection& conn, const GetFriendInfoReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GetFriendInfoRepType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_get_friend_info_rsp()->set_errmsg(msg);
    rsp.mutable_get_friend_info_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  if (!conn->GetOwner()->GetRelationTable()->Exists(uid, pid)) {
    LOG_ERROR("不存在好友关系{} - {}", uid, pid);
    errfunc("这不是你的好友");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(pid);
  if (!user) {
    LOG_ERROR("Mysql查询好友信息失败");
    errfunc("Mysql查询好友信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto info = rsp.mutable_get_friend_info_rsp()->mutable_friend_info();
  info->set_email(user->Email());
  info->set_user_id(user->UserId());
  info->set_nickname(user->Nikename());
  rsp.mutable_get_friend_info_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void FriendSendMessage(const PtrConnection& conn,
                       const FriendSendMessageReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::FriendSendMessageRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_friend_send_message_rsp()->set_errmsg(msg);
    rsp.mutable_friend_send_message_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  if (!conn->GetOwner()->GetRelationTable()->Exists(uid, pid)) {
    LOG_ERROR("不存在好友关系{} - {}", uid, pid);
    errfunc("这不是你的好友");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(uid);
  if (!user) {
    LOG_ERROR("获取个人信息失败");
    errfunc("获取个人信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string errmsg;
  bool iig = conn->GetOwner()->GetRelationTable()->Ifignore(pid, uid, errmsg);
  if (!errmsg.empty()) {
    LOG_ERROR("获取屏蔽关系失败");
    errfunc("发生了未知错误");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!iig && errmsg.empty()) {
    auto pConn = connle.Connection(pid);
    if (pConn) {
      ClientMessage noti;
      noti.set_type(ClientMessageType::FriendMessageNoticeType);
      noti.mutable_friend_message_notice()->set_friend_name(user->Nikename());
      noti.mutable_friend_message_notice()->set_body(req.message().body());
      noti.mutable_friend_message_notice()->set_message_type(
          req.message().message_type());
      LOG_DEBUG("向好友转发消息");
      SendToClient(pConn, noti.SerializeAsString());
    } else {
      Json::StreamWriterBuilder wbd;
      Json::Value test;
      test["name"] = user->Nikename();
      if (req.message().message_type() == MessageType::string) {
        test["type"] = 1;
      } else {
        test["type"] = 2;
      }
      test["body"] = req.message().body();
      std::string str = Json::writeString(wbd, test);
      conn->GetOwner()->GetOfflineMessage()->SingleAppend(pid, str);
    }
  }
  std::string sid = conn->GetOwner()->GetRelationTable()->SessionId(uid, pid);
  Message msg(uuid(), uid, sid, req.message().message_type() + 1,
              boost::posix_time::second_clock::local_time());
  msg.SetContent(req.message().body());
  cache->Append(msg);
  rsp.mutable_friend_send_message_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void DeleteFriend(const PtrConnection& conn, const DeleteFriendReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::DeleteFriendRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_delete_friend_rsp()->set_errmsg(msg);
    rsp.mutable_delete_friend_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  if (!conn->GetOwner()->GetRelationTable()->Exists(uid, pid)) {
    LOG_ERROR("不存在好友关系{} - {}", uid, pid);
    errfunc("你们不是好友");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto sid = conn->GetOwner()->GetRelationTable()->SessionId(uid, pid);
  if (sid.empty()) {
    LOG_ERROR("未找到会话信息");
    errfunc("未找到会话信息");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  ChatSessionMember s1(sid, uid, Single);
  ChatSessionMember s2(sid, pid, Single);
  if (!conn->GetOwner()->GetMessageTable()->Remove(sid)) {
    LOG_ERROR("删除会话历史消息失败");
    errfunc("删除会话历史消息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::thread del_file([&conn, &sid]() {
    Socket df;
    df.CreateClient(8085, "127.0.0.1");
    FileServer req;
    req.set_type(FileServerType::FileDelReqType);
    auto files = conn->GetOwner()->GetFileTable()->AllFileID(sid);
    for (auto& id : files) {
      req.mutable_file_del_req()->add_file_id(id);
    }
    std::string sreq = req.SerializeAsString();
    std::string body = std::to_string(sreq.size()) + "\r\n" + sreq;
    df.Send(body.c_str(), body.size());
    df.Close();
    conn->GetOwner()->GetFileTable()->RemoveAll(sid);
  });
  del_file.detach();
  bool ret = conn->GetOwner()->GetChatSessionMemberTable()->Remove(s1);
  if (!ret) {
    LOG_ERROR("删除会话成员失败");
    errfunc("删除会话成员失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  ret = conn->GetOwner()->GetChatSessionMemberTable()->Remove(s2);
  if (!ret) {
    LOG_ERROR("删除会话成员失败");
    errfunc("删除会话成员失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionTable()->Remove(sid)) {
    LOG_ERROR("删除会话信息失败");
    errfunc("删除会话信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetRelationTable()->Remove(uid, pid)) {
    LOG_ERROR("Mysql删除好友关系失败");
    errfunc("Mysql删除好友关系失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_delete_friend_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void FriendHistoryMessage(const PtrConnection& conn,
                          const FriendHistoryMessageReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::FriendHistoryMessageRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_friend_history_message_rsp()->set_errmsg(msg);
    rsp.mutable_friend_history_message_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  int sz = req.message_size();
  if (!conn->GetOwner()->GetRelationTable()->Exists(uid, pid)) {
    LOG_ERROR("不存在好友关系{} - {}", uid, pid);
    errfunc("你们不是好友");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto sid = conn->GetOwner()->GetRelationTable()->SessionId(uid, pid);
  if (sid.empty()) {
    LOG_ERROR("未找到会话信息");
    errfunc("未找到会话信息");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  cache->Flush();
  auto res = conn->GetOwner()->GetMessageTable()->Recent(sid, sz);
  if (res.empty()) {
    LOG_ERROR("无历史消息记录或Mysql查询失败");
    errfunc("无历史消息记录或Mysql查询失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(uid);
  auto peer = conn->GetOwner()->GetUserTable()->Select_by_uid(pid);
  if (!user || !peer) {
    LOG_ERROR("获取用户信息失败");
    errfunc("获取用户信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  for (int i = 0; i < res.size(); ++i) {
    auto me = rsp.mutable_friend_history_message_rsp()->add_message();
    auto n = res[i];
    if (n.UserId() == uid) {
      me->set_friend_name(user->Nikename());
    } else if (n.UserId() == pid) {
      me->set_friend_name(peer->Nikename());
    } else {
      continue;
    }
    if (n.MessageType() == 2) {
      me->set_message_type(MessageType::string);
      me->set_body(n.Content());
    } else if (n.MessageType() == 1) {
      me->set_message_type(MessageType::file);
      me->set_body(n.Content());
    }
  }
  rsp.mutable_friend_history_message_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void FriendSendFile(const PtrConnection& conn, const FriendSendFileReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::FriendSendFileRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_friend_send_file_rsp()->set_errmsg(msg);
    rsp.mutable_friend_send_file_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  if (!conn->GetOwner()->GetRelationTable()->Exists(uid, pid)) {
    LOG_ERROR("不存在好友关系{} - {}", uid, pid);
    errfunc("你们不是好友");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto sid = conn->GetOwner()->GetRelationTable()->SessionId(uid, pid);
  if (sid.empty()) {
    LOG_ERROR("未找到会话信息");
    errfunc("未找到会话信息");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string file_name = req.file_name();
  std::string file_id;
  if (conn->GetOwner()->GetFileTable()->Exist(sid, uid, file_name)) {
    file_id = conn->GetOwner()->GetFileTable()->FileId(sid, uid, file_name);
    rsp.mutable_friend_send_file_rsp()->set_ifexist(true);
  } else {
    file_id = uuid();
    rsp.mutable_friend_send_file_rsp()->set_ifexist(false);
    File f(uid, sid, file_name, file_id);
    if (!conn->GetOwner()->GetFileTable()->Insert(f)) {
      LOG_ERROR("Mysql创建文件信息失败");
      errfunc("Mysql创建文件信息失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
  }
  rsp.mutable_friend_send_file_rsp()->set_file_id(file_id);
  rsp.mutable_friend_send_file_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void FriendGetFile(const PtrConnection& conn, const FriendGetFileReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::FriendGetFileRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_friend_get_file_rsp()->set_errmsg(msg);
    rsp.mutable_friend_get_file_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  if (!conn->GetOwner()->GetRelationTable()->Exists(uid, pid)) {
    LOG_ERROR("不存在好友关系{} - {}", uid, pid);
    errfunc("你们不是好友");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto sid = conn->GetOwner()->GetRelationTable()->SessionId(uid, pid);
  if (sid.empty()) {
    LOG_ERROR("未找到会话信息");
    errfunc("未找到会话信息");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string file_name = req.file_name();
  std::string sender = req.send_id();
  if (!conn->GetOwner()->GetFileTable()->Exist(sid, sender, file_name)) {
    LOG_ERROR("不存在该文件");
    errfunc("不存在该文件");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string file_id =
      conn->GetOwner()->GetFileTable()->FileId(sid, sender, file_name);
  if (file_id.empty()) {
    LOG_ERROR("获取文件ID失败");
    errfunc("获取文件ID失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_friend_get_file_rsp()->set_success(true);
  rsp.mutable_friend_get_file_rsp()->set_file_id(file_id);
  SendToClient(conn, rsp.SerializeAsString());
}

void CreateGroup(const PtrConnection& conn, const CreateGroupReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::CreateGroupRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_create_group_rsp()->set_errmsg(msg);
    rsp.mutable_create_group_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string sname = req.session_name();
  if (conn->GetOwner()->GetChatSessionTable()->Exist(sname)) {
    LOG_ERROR("该群聊名称已被占用");
    errfunc("该群聊名称已被占用");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string sid = uuid();
  ChatSession ss(sid, GROUP);
  ss.SetSessionName(sname);
  ss.SetSessionOwner(uid);
  if (!conn->GetOwner()->GetChatSessionTable()->Insert(ss)) {
    LOG_ERROR("创建群聊会话失败");
    errfunc("创建群聊会话失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::vector<ChatSessionMember> mem;
  for (int i = 0; i < req.member_id_size(); ++i) {
    if (!conn->GetOwner()->GetRelationTable()->Exists(uid, req.member_id(i))) {
      LOG_DEBUG("存在非好友关系");
      rsp.mutable_create_group_rsp()->set_errmsg("存在非好友关系");
      continue;
    }
    mem.emplace_back(sid, req.member_id(i), Person);
  }
  mem.emplace_back(sid, uid, Owner);
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Append(mem)) {
    LOG_ERROR("Mysql建立会话成员信息失败");
    errfunc("Mysql建立会话成员信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_create_group_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void GetGroupList(const PtrConnection& conn, const GetGroupListReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GetGroupListRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_get_group_list_rsp()->set_errmsg(msg);
    rsp.mutable_get_group_list_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::cout << uid << std::endl;
  auto group_list = conn->GetOwner()->GetChatSessionTable()->GroupChat(uid);
  if (group_list.empty()) {
    LOG_ERROR("Mysql查询错误或无任何群聊");
    errfunc("Mysql查询错误或无任何群聊");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  for (const auto& n : group_list) {
    auto info = rsp.mutable_get_group_list_rsp()->add_group_list();
    info->set_session_id(n.session_id);
    info->set_session_name(n.session_name);
  }
  rsp.mutable_get_group_list_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void UserAddGroup(const PtrConnection& conn, const UserAddGroupReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::UserAddGroupRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_user_add_group_rsp()->set_errmsg(msg);
    rsp.mutable_user_add_group_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string sname = req.session_name();
  auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(uid);
  if (!user) {
    LOG_ERROR("获取个人信息失败");
    errfunc("获取个人信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionTable()->Exist(sname)) {
    LOG_ERROR("不存在此群聊");
    errfunc("不存在此群聊");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto sid = conn->GetOwner()->GetChatSessionTable()->Sid(sname);
  if (sid.empty()) {
    LOG_ERROR("Mysql获取群聊ID失败");
    errfunc("Mysql获取群聊ID失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("该成员已在群聊中了");
    errfunc("你已在群聊中了");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (conn->GetOwner()->GetSessionApplyTable()->Exists(sid, uid)) {
    LOG_ERROR("用户已经发送过入群申请了");
    errfunc("你已经发送过入群申请了");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  SessionApply ev(uuid(), sid, uid);
  if (!conn->GetOwner()->GetSessionApplyTable()->Insert(ev)) {
    LOG_ERROR("Mysql添加入群申请事件失败");
    errfunc("Mysql添加入群申请事件失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto mem = conn->GetOwner()->GetChatSessionMemberTable()->Members(sid);
  ClientMessage no;
  no.set_type(ClientMessageType::GroupApplyNoticeType);
  no.mutable_group_apply_notice()->set_session_name(sname);
  no.mutable_group_apply_notice()->set_user_name(user->Nikename());
  for (auto& n : mem) {
    if (n.Level() == group_level::Owner || n.Level() == group_level::Admin) {
      auto tmpconn = connle.Connection(n.UserId());
      if (tmpconn) {
        SendToClient(tmpconn, no.SerializeAsString());
      }
    }
  }
  rsp.mutable_user_add_group_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void GetSessionApply(const PtrConnection& conn, const GetSessionApplyReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GetSessionApplyRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_get_session_apply_rsp()->set_errmsg(msg);
    rsp.mutable_get_session_apply_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("此人不在群聊中");
    errfunc("你不在群聊中");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto mem = conn->GetOwner()->GetChatSessionMemberTable()->Select(sid, uid);
  if (!mem) {
    LOG_ERROR("Mysql查询会话成员信息失败");
    errfunc("Mysql查询会话成员信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (mem->Level() == Person) {
    LOG_ERROR("此人无权查看入群申请");
    errfunc("你无权查看入群申请");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto aid_list = conn->GetOwner()->GetSessionApplyTable()->ApplyUsers(sid);
  if (aid_list.empty()) {
    LOG_ERROR("无入群申请或获取入群申请失败");
    errfunc("无入群申请或获取入群申请失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  for (const auto& x : aid_list) {
    auto auser = conn->GetOwner()->GetUserTable()->Select_by_uid(x);
    if (auser) {
      auto info = rsp.mutable_get_session_apply_rsp()->add_user_info();
      info->set_email(auser->Email());
      info->set_nickname(auser->Nikename());
      info->set_user_id(auser->UserId());
    }
  }
  rsp.mutable_get_session_apply_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializePartialAsString());
}

void SovelGroupApply(const PtrConnection& conn, const SovelGroupApplyReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::SovelGroupApplyRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_sovel_group_apply_rsp()->set_errmsg(msg);
    rsp.mutable_sovel_group_apply_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("这个用户不是群聊的成员");
    errfunc("你不是群聊的成员");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto tmu = conn->GetOwner()->GetChatSessionMemberTable()->Select(sid, uid);
  if (!tmu) {
    LOG_ERROR("Mysql查询个人信息失败");
    errfunc("Mysql查询个人信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (tmu->Level() == Person) {
    LOG_ERROR("此人无权处理入群申请");
    errfunc("你无权处理入群申请");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetSessionApplyTable()->Remove(sid, pid)) {
    LOG_ERROR("Mysql删除入群申请事件失败");
    errfunc("Mysql删除入群申请事件失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (req.agree()) {
    ChatSessionMember csm(sid, pid, Person);
    if (!conn->GetOwner()->GetChatSessionMemberTable()->Append(csm)) {
      LOG_ERROR("Mysql新增会话成员信息失败");
      errfunc("Mysql新增会话成员信息失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
  }
  rsp.mutable_sovel_group_apply_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void GetMemberList(const PtrConnection& conn, const GetMemberListReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GetMemberListRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_get_member_list_rsp()->set_errmsg(msg);
    rsp.mutable_get_member_list_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("这个用户不是群聊的成员");
    errfunc("你不是群聊的成员");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto mem = conn->GetOwner()->GetChatSessionMemberTable()->Members(sid);
  for (auto& n : mem) {
    auto info = rsp.mutable_get_member_list_rsp()->add_member_info();
    auto tmpu = conn->GetOwner()->GetUserTable()->Select_by_uid(n.UserId());
    if (tmpu) {
      if (n.Level() == Owner) {
        info->set_type(owner);
      } else if (n.Level() == Admin) {
        info->set_type(admin);
      } else {
        info->set_type(person);
      }
      info->set_user_id(tmpu->UserId());
      info->set_name(tmpu->Nikename());
    }
  }
  rsp.mutable_get_member_list_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void SetGroupAdmin(const PtrConnection& conn, const SetGroupAdminReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::SetGroupAdminRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_set_group_admin_rsp()->set_errmsg(msg);
    rsp.mutable_set_group_admin_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, pid)) {
    LOG_ERROR("此人已经不在群聊或Mysql查询失败");
    errfunc("此人已经不在群聊或Mysql查询失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto pu = conn->GetOwner()->GetChatSessionMemberTable()->Select(sid, pid);
  if (!pu) {
    LOG_ERROR("获取对应群员的信息失败");
    errfunc("获取对应群员的信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  pu->SetLevel(Admin);
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Updata(pu)) {
    LOG_ERROR("更新对应群聊成员信息时失败");
    errfunc("更新对应群聊成员信息时失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_set_group_admin_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void CancelGroupAdmin(const PtrConnection& conn,
                      const CancelGroupAdminReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::CancelGroupAdminRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_cancel_group_admin_rsp()->set_errmsg(msg);
    rsp.mutable_cancel_group_admin_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, pid)) {
    LOG_ERROR("此人已经不在群聊或Mysql查询失败");
    errfunc("此人已经不在群聊或Mysql查询失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto pu = conn->GetOwner()->GetChatSessionMemberTable()->Select(sid, pid);
  if (!pu) {
    LOG_ERROR("获取对应群员的信息失败");
    errfunc("获取对应群员的信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  pu->SetLevel(Person);
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Updata(pu)) {
    LOG_ERROR("更新对应群聊成员信息时失败");
    errfunc("更新对应群聊成员信息时失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_cancel_group_admin_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void GroupAddFriend(const PtrConnection& conn, const GroupAddFriendReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GroupAddFriendRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_group_add_friend_rsp()->set_errmsg(msg);
    rsp.mutable_group_add_friend_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("这个用户不是群聊的成员");
    errfunc("你不是群聊的成员");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, pid)) {
    LOG_ERROR("此人已经在群聊");
    errfunc("此人已经在群聊");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(pid);
  if (!user) {
    LOG_ERROR("此用户已不存在");
    errfunc("此用户已不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  ChatSessionMember mem(sid, pid, Person);
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Append(mem)) {
    LOG_ERROR("新增会话成员信息失败");
    errfunc("新增会话成员信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_group_add_friend_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void GroupDelFriend(const PtrConnection& conn, const GroupDelMemberReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GroupDelMemberRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_group_del_member_rsp()->set_errmsg(msg);
    rsp.mutable_group_del_member_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string pid = req.peer_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("这个用户不是群聊的成员");
    errfunc("你不是群聊的成员");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, pid)) {
    LOG_ERROR("此人已经不在群聊");
    errfunc("此人已经不在群聊");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto mem1 = conn->GetOwner()->GetChatSessionMemberTable()->Select(sid, uid);
  auto mem2 = conn->GetOwner()->GetChatSessionMemberTable()->Select(sid, pid);
  if (!mem1 || !mem2) {
    LOG_ERROR("获取会话成员信息失败");
    errfunc("获取会话成员信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (mem1->Level() == Person) {
    LOG_ERROR("无权进行踢人操作");
    errfunc("你无权进行踢人操作");
    return SendToClient(conn, rsp.SerializeAsString());
  } else if (mem1->Level() == Admin && mem2->Level() != Person) {
    LOG_ERROR("只能踢出普通成员");
    errfunc("权限不足，你只能踢出普通成员");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Remove(*mem2.get())) {
    LOG_ERROR("Mysql删除会话成员信息失败");
    errfunc("Mysql删除会话成员信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_group_del_member_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void OwnerCancelGroup(const PtrConnection& conn,
                      const OwnerCancelGroupReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::OwnerCancelGroupRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_owner_cancel_group_rsp()->set_errmsg(msg);
    rsp.mutable_owner_cancel_group_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("这个用户不是群聊的成员");
    errfunc("你不是群聊的成员");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetMessageTable()->Remove(sid)) {
    LOG_ERROR("删除会话历史聊天记录失败");
    errfunc("删除会话历史聊天记录失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::thread del_file([&conn, &sid]() {
    Socket df;
    df.CreateClient(8085, "127.0.0.1");
    FileServer req;
    req.set_type(FileServerType::FileDelReqType);
    auto files = conn->GetOwner()->GetFileTable()->AllFileID(sid);
    for (auto& id : files) {
      req.mutable_file_del_req()->add_file_id(id);
    }
    std::string sreq = req.SerializeAsString();
    std::string body = std::to_string(sreq.size()) + "\r\n" + sreq;
    df.Send(body.c_str(), body.size());
    df.Close();
    conn->GetOwner()->GetFileTable()->RemoveAll(sid);
  });
  del_file.detach();
  if (!conn->GetOwner()->GetChatSessionMemberTable()->RemoveAll(sid)) {
    LOG_ERROR("删除所有群聊成员信息失败");
    errfunc("删除所有群聊成员信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionTable()->Remove(sid)) {
    LOG_ERROR("删除会话信息失败");
    errfunc("删除会话信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_owner_cancel_group_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void MemberExitGroup(const PtrConnection& conn, const MemberExitGroupReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::MemberExitGroupRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_member_exit_group_rsp()->set_errmsg(msg);
    rsp.mutable_member_exit_group_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("这个用户已经不是群聊的成员");
    errfunc("你已经不是群聊的成员");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto mem = conn->GetOwner()->GetChatSessionMemberTable()->Select(sid, uid);
  if (!mem) {
    LOG_ERROR("查询会话成员信息失败");
    errfunc("查询会话成员信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Remove(*mem.get())) {
    LOG_ERROR("删除会话成员信息失败");
    errfunc("删除会话成员信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_member_exit_group_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void GroupSendMessage(const PtrConnection& conn,
                      const GroupSendMessageReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GroupSendMessageRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_group_send_message_rsp()->set_errmsg(msg);
    rsp.mutable_group_send_message_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("这个用户已经不是群聊的成员");
    errfunc("你已经不是群聊的成员");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto user = conn->GetOwner()->GetUserTable()->Select_by_uid(uid);
  if (!user) {
    LOG_ERROR("获取个人信息失败");
    errfunc("获取个人信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  auto mem_list = conn->GetOwner()->GetChatSessionMemberTable()->Members(sid);
  if (mem_list.empty()) {
    LOG_ERROR("获取会话成员失败");
    errfunc("获取会话成员失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  Message msg(uuid(), uid, sid, req.message().message_type() + 1,
              boost::posix_time::second_clock::local_time());
  msg.SetContent(req.message().body());
  cache->Append(msg);
  ClientMessage no;
  no.set_type(ClientMessageType::GroupMessageNoticeType);
  no.mutable_group_message_notice()->set_member_name(user->Nikename());
  no.mutable_group_message_notice()->set_session_name(session->SessionName());
  no.mutable_group_message_notice()->set_message_type(
      req.message().message_type());
  no.mutable_group_message_notice()->set_body(req.message().body());
  Json::StreamWriterBuilder wbd;
  Json::Value test;
  test["name"] = session->SessionName();
  test["sender"] = user->Nikename();
  if (req.message().message_type() == MessageType::string) {
    test["type"] = 1;
  } else {
    test["type"] = 2;
  }
  test["body"] = req.message().body();
  std::string str = Json::writeString(wbd, test);
  for (auto& n : mem_list) {
    if (n.UserId() == uid) {
      continue;
    }
    auto pconn = connle.Connection(n.UserId());
    if (pconn) {
      SendToClient(pconn, no.SerializeAsString());
    } else {
      conn->GetOwner()->GetOfflineMessage()->GroupAppend(n.UserId(), str);
    }
  }
  rsp.mutable_group_send_message_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void GroupSendFile(const PtrConnection& conn, const GroupSendFileReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GroupSendFileRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_group_send_file_rsp()->set_errmsg(msg);
    rsp.mutable_group_send_file_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("这个用户已经不是群聊的成员");
    errfunc("你已经不是群聊的成员");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string file_name = req.file_name();
  std::string file_id;
  if (conn->GetOwner()->GetFileTable()->Exist(sid, uid, file_name)) {
    file_id = conn->GetOwner()->GetFileTable()->FileId(sid, uid, file_name);
    rsp.mutable_group_send_file_rsp()->set_ifexist(true);
  } else {
    file_id = uuid();
    rsp.mutable_group_send_file_rsp()->set_ifexist(false);
    File f(uid, sid, file_name, file_id);
    if (!conn->GetOwner()->GetFileTable()->Insert(f)) {
      LOG_ERROR("Mysql创建文件信息失败");
      errfunc("Mysql创建文件信息失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
  }
  rsp.mutable_group_send_file_rsp()->set_file_id(file_id);
  rsp.mutable_group_send_file_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void GroupGetFile(const PtrConnection& conn, const GroupGetFileReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GroupGetFileRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_group_get_file_rsp()->set_errmsg(msg);
    rsp.mutable_group_get_file_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("这个用户已经不是群聊的成员");
    errfunc("你已经不是群聊的成员");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string file_name = req.file_name();
  std::string sender = req.send_id();
  if (!conn->GetOwner()->GetFileTable()->Exist(sid, sender, file_name)) {
    LOG_ERROR("不存在该文件");
    errfunc("不存在该文件");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::string file_id =
      conn->GetOwner()->GetFileTable()->FileId(sid, sender, file_name);
  if (file_id.empty()) {
    LOG_ERROR("获取文件ID失败");
    errfunc("获取文件ID失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  rsp.mutable_group_get_file_rsp()->set_success(true);
  rsp.mutable_group_get_file_rsp()->set_file_id(file_id);
  SendToClient(conn, rsp.SerializeAsString());
}

void GroupHistoryMessage(const PtrConnection& conn,
                         const GroupHistoryMessageReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::GroupHistoryMessageRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_group_history_message_rsp()->set_errmsg(msg);
    rsp.mutable_group_history_message_rsp()->set_success(false);
    return;
  };
  std::string uid = req.user_id();
  std::string sid = req.session_id();
  auto session = conn->GetOwner()->GetChatSessionTable()->Select(sid);
  if (!session) {
    LOG_ERROR("此群聊已经不存在");
    errfunc("此群聊已经不存在");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  if (!conn->GetOwner()->GetChatSessionMemberTable()->Exist(sid, uid)) {
    LOG_ERROR("这个用户已经不是群聊的成员");
    errfunc("你已经不是群聊的成员");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  int sz = req.message_size();
  std::unordered_map<std::string, std::string> uid_name;
  auto mem_list = conn->GetOwner()->GetChatSessionMemberTable()->Members(sid);
  for (auto& mem : mem_list) {
    auto info = conn->GetOwner()->GetUserTable()->Select_by_uid(mem.UserId());
    if (info) {
      uid_name[mem.UserId()] = info->Nikename();
    }
  }
  cache->Flush();
  auto res = conn->GetOwner()->GetMessageTable()->Recent(sid, sz);
  if (res.empty()) {
    LOG_ERROR("无历史消息记录或Mysql查询失败");
    errfunc("无历史消息记录或Mysql查询失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  for (int i = 0; i < res.size(); ++i) {
    auto me = rsp.mutable_group_history_message_rsp()->add_message();
    auto n = res[i];
    auto pos = uid_name.find(n.UserId());
    if (pos != uid_name.end()) {
      me->set_sender_name(pos->second);
    } else {
      me->set_sender_name("未知人员");
    }
    if (n.MessageType() == 2) {
      me->set_message_type(MessageType::string);
      me->set_body(n.Content());
    } else if (n.MessageType() == 1) {
      me->set_message_type(MessageType::file);
      me->set_body(n.Content());
    }
  }
  rsp.mutable_group_history_message_rsp()->set_success(true);
  SendToClient(conn, rsp.SerializeAsString());
}

void UserDelSelf(const PtrConnection& conn, const UserDelSelfReq& req) {
  ClientMessage rsp;
  rsp.set_type(ClientMessageType::UserDelSelfRspType);
  auto errfunc = [&rsp](const std::string& msg) {
    rsp.mutable_user_del_self_rsp()->set_errmsg(msg);
    rsp.mutable_user_del_self_rsp()->set_success(false);
    return;
  };
  cache->Flush();
  std::string uid = req.user_id();
  std::vector<std::string> file_ids;
  auto friends = conn->GetOwner()->GetRelationTable()->Friends(uid);
  for (auto& f : friends) {
    auto tsid = conn->GetOwner()->GetRelationTable()->SessionId(uid, f);
    if (tsid.empty()) {
      LOG_ERROR("Mysql删除数据失败");
      errfunc("Mysql删除数据失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
    if (!conn->GetOwner()->GetMessageTable()->Remove(tsid)) {
      LOG_ERROR("Mysql删除数据失败");
      errfunc("Mysql删除数据失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
    auto files = conn->GetOwner()->GetFileTable()->AllFileID(tsid);
    for (auto& id : files) {
      file_ids.emplace_back(id);
    }
    if (!conn->GetOwner()->GetFileTable()->RemoveAll(tsid)) {
      LOG_ERROR("Mysql删除数据失败");
      errfunc("Mysql删除数据失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
    if (!conn->GetOwner()->GetChatSessionMemberTable()->RemoveAll(tsid)) {
      LOG_ERROR("Mysql删除数据失败");
      errfunc("Mysql删除数据失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
    if (!conn->GetOwner()->GetChatSessionTable()->Remove(tsid)) {
      LOG_ERROR("Mysql删除数据失败");
      errfunc("Mysql删除数据失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
    conn->GetOwner()->GetRelationTable()->Remove(uid, f);
  }
  auto groups = conn->GetOwner()->GetChatSessionTable()->GroupChat(uid);
  for (auto& g : groups) {
    auto mem = conn->GetOwner()->GetChatSessionMemberTable()->Select(
        g.session_id, uid);
    if (mem) {
      if (mem->Level() == Owner) {
        if (!conn->GetOwner()->GetMessageTable()->Remove(g.session_id)) {
          LOG_ERROR("Mysql删除数据失败");
          errfunc("Mysql删除数据失败");
          return SendToClient(conn, rsp.SerializeAsString());
        }
        auto files = conn->GetOwner()->GetFileTable()->AllFileID(g.session_id);
        for (auto& id : files) {
          file_ids.emplace_back(id);
        }
        if (!conn->GetOwner()->GetFileTable()->RemoveAll(g.session_id)) {
          LOG_ERROR("Mysql删除数据失败");
          errfunc("Mysql删除数据失败");
          return SendToClient(conn, rsp.SerializeAsString());
        }
        if (!conn->GetOwner()->GetChatSessionMemberTable()->RemoveAll(
                g.session_id)) {
          LOG_ERROR("Mysql删除数据失败");
          errfunc("Mysql删除数据失败");
          return SendToClient(conn, rsp.SerializeAsString());
        }
        if (!conn->GetOwner()->GetChatSessionTable()->Remove(g.session_id)) {
          LOG_ERROR("Mysql删除数据失败");
          errfunc("Mysql删除数据失败");
          return SendToClient(conn, rsp.SerializeAsString());
        }
      } else {
        conn->GetOwner()->GetChatSessionMemberTable()->Remove(*mem);
      }
    } else {
      LOG_ERROR("Mysql删除数据失败");
      errfunc("Mysql删除数据失败");
      return SendToClient(conn, rsp.SerializeAsString());
    }
  }
  if (!conn->GetOwner()->GetUserTable()->Remove(uid)) {
    LOG_ERROR("删除用户信息失败");
    errfunc("删除用户信息失败");
    return SendToClient(conn, rsp.SerializeAsString());
  }
  std::thread del_file([conn, file_ids]() {
    Socket df;
    df.CreateClient(8085, "127.0.0.1");
    FileServer req;
    req.set_type(FileServerType::FileDelReqType);
    for (auto& id : file_ids) {
      req.mutable_file_del_req()->add_file_id(id);
    }
    std::string sreq = req.SerializeAsString();
    std::string body = std::to_string(sreq.size()) + "\r\n" + sreq;
    df.Send(body.c_str(), body.size());
    df.Close();
  });
  del_file.detach();
  rsp.mutable_user_del_self_rsp()->set_success(true);
  conn->GetOwner()->GetStatus()->Remove(uid);
  connle.Remove(conn);
  SendToClient(conn, rsp.SerializeAsString());
}
}  // namespace Xianwei
