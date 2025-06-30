#pragma once
#include "chat_session-odb.hxx"
#include "chat_session.hxx"
#include "mysql.h"
#include "mysql_chat_session_member.hpp"

namespace Xianwei {
class ChatSessionTable {
 public:
  using ptr = std::shared_ptr<ChatSessionTable>;
  ChatSessionTable() {}
  ChatSessionTable(const std::shared_ptr<odb::core::database>& db) : _db(db) {}

  bool Insert(ChatSession& ev) {
    try {
      odb::transaction trans(_db->begin());
      _db->persist(ev);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("新增会话{}失败：{}", ev.SessionName(), e.what());
      return false;
    }
    return true;
  }

  bool Remove(const std::string& sid) {
    try {
      typedef odb::result<ChatSession> result;
      typedef odb::query<ChatSession> query;
      odb::transaction trans(_db->begin());
      _db->erase_query<ChatSession>(query::session_id == sid);
      typedef odb::query<ChatSessionMember> mquery;
      _db->erase_query<ChatSessionMember>(mquery::session_id == sid);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("删除会话{}失败：{}", sid, e.what());
      return false;
    }
    return true;
  }

  bool Remove(const std::string& uid, const std::string& pid) {
    try {
      typedef odb::result<SingleChatSession> sresult;
      typedef odb::query<SingleChatSession> squery;
      typedef odb::result<ChatSession> cresult;
      typedef odb::query<ChatSession> cquery;
      typedef odb::result<ChatSessionMember> mresult;
      typedef odb::query<ChatSessionMember> mquery;
      odb::transaction trans(_db->begin());
      auto res = _db->query_one<SingleChatSession>(
          squery::css::chat_type == ChatType::SINGLE &&
          squery::csm1::user_id == uid && squery::csm2::user_id == pid);
      _db->erase_query<ChatSession>(cquery::session_id == res->session_id);
      _db->erase_query<ChatSessionMember>(mquery::session_id ==
                                          res->session_id);

      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("删除单聊会话{}-{}失败：{}", uid, pid, e.what());
      return false;
    }
    return true;
  }

  std::shared_ptr<ChatSession> Select(const std::string& sid) {
    std::shared_ptr<ChatSession> res;
    try {
      typedef odb::result<ChatSession> result;
      typedef odb::query<ChatSession> query;
      odb::transaction trans(_db->begin());
      res.reset(_db->query_one<ChatSession>(query::session_id == sid));
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("通过会话id{}获取会话信息失败：{}", sid, e.what());
    }
    return res;
  }

  std::vector<SingleChatSession> SingleChat(const std::string& uid) {
    std::vector<SingleChatSession> res;
    try {
      typedef odb::result<SingleChatSession> result;
      typedef odb::query<SingleChatSession> query;
      result r(_db->query<SingleChatSession>(
          query::css::chat_type == ChatType::SINGLE &&
          query::csm1::user_id == uid && query::csm2::user_id != uid));
      res.reserve(r.size());
      for (auto& rr : r) {
        res.emplace_back(rr);
      }
    } catch (const std::exception& e) {
      LOG_ERROR("获取用户{}的群聊会话失败：{}", uid, e.what());
    }
    return std::move(res);
  }

  std::vector<GroupChatSession> GroupChat(const std::string& uid) {
    std::vector<GroupChatSession> res;
    try {
      typedef odb::result<GroupChatSession> result;
      typedef odb::query<GroupChatSession> query;
      result r(_db->query<GroupChatSession>(query::css::chat_type ==
                                                ChatType::GROUP &&
                                            query::csm::user_id == uid));
      res.reserve(r.size());
      for (auto& rr : r) {
        res.emplace_back(rr);
      }
    } catch (const std::exception& e) {
      LOG_ERROR("获取用户{}的单聊会话失败：{}", uid, e.what());
    }
    return std::move(res);
  }

 private:
  std::shared_ptr<odb::core::database> _db;
};
}  // namespace Xianwei
