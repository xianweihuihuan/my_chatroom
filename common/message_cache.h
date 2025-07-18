#pragma once
#include <json/json.h>
#include <sw/redis++/redis.h>
#include <mutex>
#include <vector>
#include "mysql_message.hpp"

namespace Xianwei {
class MessageCache {
 public:
  using ptr = std::shared_ptr<MessageCache>;
  MessageCache(const std::shared_ptr<sw::redis::Redis>& client,
               const MessageTable::ptr& table,
               size_t threshold = 200);

  void Append(const Message& msg);

  void Flush();

 private:
  void FlushLocked();

  std::shared_ptr<sw::redis::Redis> client_;
  MessageTable::ptr table_;
  std::mutex mutex_;
  size_t threshold_;
  size_t count_ = 0;
};

}  // namespace Xianwei
