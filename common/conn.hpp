#pragma once
#include <unordered_map>
#include "Connection.h"

namespace Xianwei {
class Conn {
 public:
  void Insert(const PtrConnection& conn, const std::string& uid) {
    std::unique_lock<std::mutex> mtx(lock_);
    conn_uid_.emplace(std::make_pair(conn, uid));
    uid_conn_.emplace(std::make_pair(uid, conn));
    LOG_ERROR("新增长链接{}", uid);
  }

  PtrConnection Connection(const std::string& uid) {
    std::unique_lock<std::mutex> mtx(lock_);
    auto it = uid_conn_.find(uid);
    if (it == uid_conn_.end()) {
      LOG_DEBUG("未找到{}长链接信息", uid);
      return nullptr;
    }
    return it->second;
  }

  std::string Uid(const PtrConnection& conn) {
    std::unique_lock<std::mutex> mtx(lock_);
    auto it = conn_uid_.find(conn);
    if (it == conn_uid_.end()) {
      LOG_DEBUG("未找到连接信息");
      return std::string();
    }
    return it->second;
  }


  void Remove(const PtrConnection& conn) {
    std::unique_lock<std::mutex> mtx(lock_);
    auto it = conn_uid_.find(conn);
    if (it == conn_uid_.end()) {
      LOG_ERROR("未找到连接信息");
      return;
    }
    LOG_ERROR("移除长链接信息");
    uid_conn_.erase(it->second);
    conn_uid_.erase(it);
  }

 private:
  std::mutex lock_;
  std::unordered_map<PtrConnection, std::string> conn_uid_;
  std::unordered_map<std::string, PtrConnection> uid_conn_;
};
}  // namespace Xianwei
