#pragma once
#include "friend_apply-odb.hxx"
#include "friend_apply.hxx"
#include "session_apply.hxx"
#include "session_apply-odb.hxx"
#include "mysql.h"

namespace Xianwei {
class FriendApplyTable {
 public:
  using ptr = std::shared_ptr<FriendApplyTable>;
  FriendApplyTable(const std::shared_ptr<odb::core::database>& db) : db_(db) {}

  bool Insert(FriendApply& ev) {
    try {
      odb::transaction trans(db_->begin());
      db_->persist(ev);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("新增好友申请{}-{}失败：{}", ev.UserId(), ev.PeerId(),
                e.what());
      return false;
    }
    return true;
  }

  bool Exists(const std::string& uid, const std::string& pid) {
    bool flag;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<FriendApply> query;
      typedef odb::result<FriendApply> result;
      result r(db_->query<FriendApply>(query::user_id == uid &&
                                       query::peer_id == pid));
      flag = !r.empty();
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("获取好友申请事件{}-{}失败：{}", uid, pid, e.what());
      return false;
    }
    return flag;
  }

  bool Remove(const std::string& uid, const std::string& pid) {
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<FriendApply> query;
      db_->erase_query<FriendApply>(query::user_id == uid &&
                                    query::peer_id == pid);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("删除好友申请事件{}-{}失败：{}", uid, pid, e.what());
      return false;
    }
    return true;
  }


  std::vector<std::string> ApplyUsers(const std::string& uid){
    std::vector<std::string> res;
    try
    {
      odb::transaction trans(db_->begin());
      typedef odb::query<FriendApply> query;
      typedef odb::result<FriendApply> result;
      result r(db_->query<FriendApply>(query::peer_id == uid));
      res.reserve(r.size());
      for (auto& rr : r) {
        res.emplace_back(rr.UserId());
      }
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("查找用户的{}的好友申请失败：{}", uid, e.what());
    }
    return res;
  }

 private:
  std::shared_ptr<odb::core::database> db_;
};

class SessionApplyTable {
 public:
  using ptr = std::shared_ptr<SessionApplyTable>;
  SessionApplyTable(const std::shared_ptr<odb::core::database>& db) : db_(db) {}

  bool Insert(SessionApply& ev) {
    try {
      odb::transaction trans(db_->begin());
      db_->persist(ev);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("新增入群申请{}-{}失败：{}", ev.SessionId(), ev.UserId(),
                e.what());
      return false;
    }
    return true;
  }

  bool Exists(const std::string& sid, const std::string& uid) {
    bool flag;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<SessionApply> query;
      typedef odb::result<SessionApply> result;
      result r(db_->query<SessionApply>(query::session_id == sid &&
                                       query::user_id == uid));
      flag = !r.empty();
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("获取入群申请事件{}-{}失败：{}", sid, uid, e.what());
      return false;
    }
    return flag;
  }

  bool Remove(const std::string& sid, const std::string& uid) {
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<SessionApply> query;
      db_->erase_query<SessionApply>(query::session_id == sid &&
                                    query::user_id == uid);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("删除入群申请事件{}-{}失败：{}", sid, uid, e.what());
      return false;
    }
    return true;
  }


  std::vector<std::string> ApplyUsers(const std::string& sid){
    std::vector<std::string> res;
    try
    {
      odb::transaction trans(db_->begin());
      typedef odb::query<SessionApply> query;
      typedef odb::result<SessionApply> result;
      result r(db_->query<SessionApply>(query::session_id == sid));
      res.reserve(r.size());
      for (auto& rr : r) {
        res.emplace_back(rr.UserId());
      }
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("查找群聊的{}的好友申请失败：{}", sid, e.what());
    }
    return res;
  }

 private:
  std::shared_ptr<odb::core::database> db_;
};
}  // namespace Xianwei
