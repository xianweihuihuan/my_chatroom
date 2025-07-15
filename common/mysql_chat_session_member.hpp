#pragma once
#include "chat_session_member-odb.hxx"
#include "chat_session_member.hxx"
#include "mysql.h"

namespace Xianwei {
class ChatSessionMemberTable {
 public:
  using ptr = std::shared_ptr<ChatSessionMemberTable>;
  ChatSessionMemberTable(const std::shared_ptr<odb::core::database> db)
      : _db(db) {}

  bool Append(ChatSessionMember& csm) {
    try {
      odb::transaction trans(_db->begin());
      _db->persist(csm);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("向会话{}新增成员{}失败：{}", csm.SessionId(), csm.UserId(),
                e.what());
      return false;
    }
    return true;
  }

  bool Append(std::vector<ChatSessionMember>& csm_list) {
    try {
      odb::transaction trans(_db->begin());
      for (auto& csm : csm_list) {
        _db->persist(csm);
      }
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("向会话{}新增多成员{}个失败：{}", csm_list[0].SessionId(),
                csm_list.size(), e.what());
      return false;
    }
    return true;
  }

  bool Remove(ChatSessionMember& csm) {
    try {
      odb::transaction trans(_db->begin());
      typedef odb::query<ChatSessionMember> query;
      typedef odb::result<ChatSessionMember> result;
      _db->erase_query<ChatSessionMember>(query::session_id ==
                                              csm.SessionId() &&
                                          query::user_id == csm.UserId());
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("向会话{}删除成员{}失败：{}", csm.SessionId(), csm.UserId(),
                e.what());
      return false;
    }
    return true;
  }

  bool RemoveAll(const std::string& session_id) {
    try {
      odb::transaction trans(_db->begin());
      typedef odb::query<ChatSessionMember> query;
      typedef odb::result<ChatSessionMember> result;
      _db->erase_query<ChatSessionMember>(query::session_id == session_id);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("删除会话{}所有成员失败：{}", session_id, e.what());
      return false;
    }
    return true;
  }

  std::shared_ptr<ChatSessionMember> Select(const std::string& sid,
                                            const std::string& uid) {
    std::shared_ptr<ChatSessionMember> ret;
    try {
      typedef odb::query<ChatSessionMember> query;
      typedef odb::result<ChatSessionMember> result;
      odb::transaction trans(_db->begin());
      auto res = _db->query<ChatSessionMember>(query::session_id == sid &&
                                               query::user_id == uid);
      if (!res.empty()) {
        ret = std::make_shared<ChatSessionMember>(*res.begin());
      }
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("获取会话成员信息{}-{}失败,{}", sid, uid, e.what());
      return nullptr;
    }
    return ret;
  }

  bool Exist(const std::string& sid, const std::string& uid) {
    bool flag;
    try {
      odb::transaction trans(_db->begin());
      typedef odb::query<ChatSessionMember> query;
      typedef odb::result<ChatSessionMember> result;
      result r(_db->query<ChatSessionMember>(query::user_id == uid &&
                                             query::session_id == sid));
      flag = !r.empty();
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("获取群聊申请{}-{}失败：{}", sid, uid, e.what());
      return false;
    }
    return flag;
  }

  std::vector<ChatSessionMember> Members(const std::string& session_id) {
    std::vector<ChatSessionMember> res;
    try {
      odb::transaction trans(_db->begin());
      typedef odb::query<ChatSessionMember> query;
      typedef odb::result<ChatSessionMember> result;
      result results(
          _db->query<ChatSessionMember>(query::session_id == session_id));
      res.reserve(results.size());
      for (auto& x : results) {
        res.emplace_back(x);
      }
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("查找会话{}所有成员失败：{}", session_id, e.what());
      return res;
    }
    return res;
  }

  bool Updata(std::shared_ptr<ChatSessionMember> ev) {
    try {
      odb::transaction trans(_db->begin());
      _db->update(*ev);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("更新会话成员失败：{}", e.what());
      return false;
    }
    return true;
  }

 private:
  const std::shared_ptr<odb::core::database> _db;
};
}  // namespace Xianwei
