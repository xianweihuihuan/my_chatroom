#pragma once
#include "mysql.h"
#include "relation-odb.hxx"
#include "relation.hxx"
#include "utils.h"

namespace Xianwei {
class RelationTable {
 public:
  using ptr = std::shared_ptr<RelationTable>;
  RelationTable(const std::shared_ptr<odb::core::database>& db) : db_(db) {}

  bool Insert(const std::string& uid, const std::string& pid,const std::string& sid) {
    try {
      Relation r1(uid, pid, sid, level::unignore);
      Relation r2(pid, uid, sid, level::unignore);
      odb::transaction trans(db_->begin());
      db_->persist(r1);
      db_->persist(r2);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("新增好友关系{}-{}失败：{}", uid, pid, e.what());
      return false;
    }
    return true;
  }

  bool Remove(const std::string& uid, const std::string& pid) {
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<Relation> query;
      db_->erase_query<Relation>(query::user_id == uid &&
                                 query::peer_id == pid);
      db_->erase_query<Relation>(query::user_id == pid &&
                                 query::peer_id == uid);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("删除好友关系{}-{}失败：{}", uid, pid, e.what());
      return false;
    }
    return true;
  }

  bool Exists(const std::string& uid, const std::string& pid) {
    bool flag;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<Relation> query;
      typedef odb::result<Relation> result;
      result r(
          db_->query<Relation>(query::user_id == uid && query::peer_id == pid));
      flag = !r.empty();
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("获取好友关系{}-{}失败：{}", uid, pid, e.what());
      return false;
    }
    return flag;
  }

  bool Ifignore(const std::string& uid,
                const std::string& pid,
                std::string& errmsg) {
    std::shared_ptr<Relation> res;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<Relation> query;
      typedef odb::result<Relation> result;
      res.reset(db_->query_one<Relation>(query::user_id == uid &&
                                         query::peer_id == pid));
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("获取好友是否被屏蔽失败");
      errmsg = "获取好友是否被屏蔽失败";
      return false;
    }
    return res->Ifignore() == level::ignore;
  }

  bool Ignore(const std::string& uid, const std::string& pid) {
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<Relation> query;
      typedef odb::result<Relation> result;
      typedef odb::object_traits<Relation>::pointer_type relation_ptr;
      relation_ptr res = db_->query_one<Relation>(query::user_id == uid &&
                                         query::peer_id == pid);
      if (!res) {
        LOG_ERROR("未找到好友关系{}-{}", uid, pid);
        return false;
      }
      res->SetIfignore(level::ignore);
      db_->update(*res);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("屏蔽好友消息{}-{}失败：{}", uid, pid, e.what());
      return false;
    }
    return true;
  }

  bool Unignore(const std::string& uid, const std::string& pid) {
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<Relation> query;
      typedef odb::result<Relation> result;
      typedef odb::object_traits<Relation>::pointer_type relation_ptr;
      relation_ptr res = db_->query_one<Relation>(query::user_id == uid &&
                                         query::peer_id == pid);
      if (!res) {
        LOG_ERROR("未找到好友关系{}-{}", uid, pid);
        return false;
      }
      res->SetIfignore(level::unignore);
      db_->update(res);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("解除屏蔽好友消息{}-{}失败：{}", uid, pid, e.what());
      return false;
    }
    return true;
  }

  std::string SessionId(const std::string& uid,const std::string& pid){
    std::string ret;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<Relation> query;
      typedef odb::result<Relation> result;
      typedef odb::object_traits<Relation>::pointer_type relation_ptr;
      relation_ptr res = db_->query_one<Relation>(query::user_id == uid &&
                                         query::peer_id == pid);
      if (!res) {
        LOG_ERROR("未找到好友关系{}-{}", uid, pid);
        return std::string();
      }
      ret = res->SessionId();
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("查找好友关系{}-{}失败",uid,pid);
      return std::string();
    }
    return ret;
  }

  std::vector<std::string> Friends(const std::string& uid) {
    std::vector<std::string> res;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<Relation> query;
      typedef odb::result<Relation> result;
      result r(db_->query<Relation>(query::user_id == uid));
      res.reserve(r.size());
      for (auto& rr : r) {
        res.emplace_back(rr.PeerId());
      }
    } catch (const std::exception& e) {
      LOG_ERROR("通过uid:{}查找好友关系失败：{}", uid, e.what());
    }
    return res;
  }

 private:
  std::shared_ptr<odb::core::database> db_;
};
}  // namespace Xianwei
