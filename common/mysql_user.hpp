#pragma once
#include "mysql.h"
#include "user-odb.hxx"
#include "user.hxx"

namespace Xianwei {
class UserTable {
 public:
  using ptr = std::shared_ptr<UserTable>;
  UserTable(const std::shared_ptr<odb::core::database>& db) : db_(db) {}

  bool Insert(const std::shared_ptr<User>& user) {
    try {
      odb::transaction trans(db_->begin());
      db_->persist(*user);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("新增用户{}失败：{}", user->Nikename(), e.what());
      return false;
    }
    return true;
  }

  bool Update(const std::shared_ptr<User>& user) {
    try {
      odb::transaction trans(db_->begin());
      db_->update(*user);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("更新用户{}失败：{}", user->Nikename(), e.what());
      return false;
    }
    return true;
  }

  bool Remove(const std::string& uid){
    try {
      typedef odb::query<User> query;
      odb::transaction trans(db_->begin());
      db_->erase_query<User>(query::user_id == uid);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("删除用户{}失败：{}", uid, e.what());
      return false;
    }
    return true;
  }

  std::shared_ptr<User> Select_by_nickname(const std::string& name) {
    std::shared_ptr<User> res;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<User> query;
      typedef odb::result<User> result;
      res.reset(db_->query_one<User>(query::nickname == name));
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("根据昵称：{}查询用户失败：{}", name, e.what());
    }
    return res;
  }

  std::shared_ptr<User> Select_by_uid(const std::string& uid) {
    std::shared_ptr<User> res;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<User> query;
      typedef odb::result<User> result;
      res.reset(db_->query_one<User>(query::user_id == uid));
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("根据uid：{}查询用户失败：{}", uid, e.what());
    }
    return res;
  }

  std::shared_ptr<User> Select_by_email(const std::string& email) {
    std::shared_ptr<User> res;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<User> query;
      typedef odb::result<User> result;
      res.reset(db_->query_one<User>(query::email == email));
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("根据邮箱：{}查询用户失败：{}", email, e.what());
    }
    return res;
  }

  std::vector<User> Select_multi_users(
      const std::vector<std::string>& id_list) {
    if (id_list.empty()) {
      return std::vector<User>();
    }
    std::vector<User> res;
    try {
      std::string s;
      s += "user_id in(";
      for (const auto& id : id_list) {
        s += "'";
        s += id;
        s += "',";
      }
      s.pop_back();
      s += ")";
      odb::transaction trans(db_->begin());
      typedef odb::query<User> query;
      typedef odb::result<User> result;
      result r(db_->query<User>(s));
      for (const auto& x : r) {
        res.emplace_back(x);
      }
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("通过ID批量查找用户失败：{}", e.what());
    }
    return res;
  }

 private:
  std::shared_ptr<odb::core::database> db_;
};
}  // namespace Xianwei