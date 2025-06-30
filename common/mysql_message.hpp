#pragma once
#include "message-odb.hxx"
#include "message.hxx"
#include "mysql.h"

namespace Xianwei {
class MessageTable {
 public:
  using ptr = std::shared_ptr<MessageTable>;
  MessageTable(const std::shared_ptr<odb::core::database> db) : db_(db) {}
  bool Insert(Message& msg) {
    try {
      odb::transaction trans(db_->begin());
      db_->persist(msg);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("新增消息失败：{}", e.what());
      return false;
    }
    return true;
  }

  bool Remove(const std::string& sid) {
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<Message> query;
      typedef odb::result<Message> result;
      db_->erase_query<Message>(query::session_id == sid);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("删除会话{}所有信息失败：{}", sid, e.what());
      return false;
    }
    return true;
  }

  std::vector<Message> Recent(const std::string& sid, const int& count) {
    std::vector<Message> res;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<Message> query;
      typedef odb::result<Message> result;
      std::stringstream ss;
      ss << "session_id='" << sid << "'";
      ss << "order by create_time desc limit " << count;
      result r(db_->query<Message>(ss.str()));
      for (const auto& re : r) {
        res.emplace_back(re);
      }
      std::reverse(res.begin(), res.end());
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("查找会话{}的最近{}条信息失败：{}", sid, count, e.what());
    }
    return res;
  }

  std::vector<Message> Range(const std::string& ssid,
                             boost::posix_time::ptime& stime,
                             boost::posix_time::ptime& etime) {
    std::vector<Message> res;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<Message> query;
      typedef odb::result<Message> result;
      // 获取指定会话指定时间段的信息
      result r(db_->query<Message>(query::session_id == ssid &&
                                   query::create_time >= stime &&
                                   query::create_time <= etime));
      for (const auto& re : r) {
        res.emplace_back(re);
      }
      trans.commit();
    } catch (std::exception& e) {
      LOG_ERROR("获取区间消息失败:{}-{}:{}-{}！", ssid,
                boost::posix_time::to_simple_string(stime),
                boost::posix_time::to_simple_string(etime), e.what());
    }
    return res;
  }

 private:
  std::shared_ptr<odb::core::database> db_;
};
}  // namespace Xianwei
