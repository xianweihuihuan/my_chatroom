#include "message_cache.h"
#include <boost/date_time/posix_time/posix_time.hpp>
#include "logger.h"
#include "utils.h"

namespace Xianwei {

MessageCache::MessageCache(const std::shared_ptr<sw::redis::Redis>& client,
                           const MessageTable::ptr& table,
                           size_t threshold)
    : client_(client), table_(table), threshold_(threshold) {}

void MessageCache::Append(const Message& msg) {
  Json::Value v;
  v["mid"] = msg.MessageId();
  v["sid"] = msg.SessionId();
  v["uid"] = msg.UserId();
  v["type"] = msg.MessageType();
  v["time"] = boost::posix_time::to_iso_string(msg.CreateTime());
  v["content"] = msg.Content();
  Json::StreamWriterBuilder wb;
  std::string data = Json::writeString(wb, v);
  try {
    std::unique_lock<std::mutex> lock(mutex_);
    client_->rpush("cache:messages", data);
    ++count_;
    if (count_ >= threshold_) {
      FlushLocked();
    }
  } catch (const std::exception& e) {
    LOG_ERROR("Redis 缓存消息失败:{}", e.what());
  }
}
void MessageCache::Flush()
{
  std::unique_lock<std::mutex> mtx(mutex_);
  FlushLocked();
}

void MessageCache::FlushLocked(){ 
  std::vector<std::string> all;
  try {
    client_->lrange("cache:messages", 0, -1, std::back_inserter(all));
    client_->del("cache:messages");
    count_ = 0;
  } catch (const std::exception& e) {
    LOG_ERROR("读取缓存消息失败:{}", e.what());
    return;
  }
  if (all.empty()) {
    return;
  }
  Json::CharReaderBuilder rb;
  std::vector<Message> msgs;
  for (const auto& item : all) {
    Json::Value v;
    std::string errs;
    std::unique_ptr<Json::CharReader> reader(rb.newCharReader());
    if (!reader->parse(item.c_str(), item.c_str() + item.size(), &v, &errs)) {
      LOG_ERROR("解析缓存消息失败:{}", errs);
      continue;
    }
    try {
      Message msg( v["mid"].asString(),v["uid"].asString(), v["sid"].asString(),
                  static_cast<unsigned char>(v["type"].asInt()),
                  boost::posix_time::from_iso_string(v["time"].asString()));
      msg.SetContent(v["content"].asString());
      msgs.emplace_back(std::move(msg));
    } catch (const std::exception& e) {
      LOG_ERROR("构造消息失败:{}", e.what());
    }
  }
  if (!msgs.empty()) {
    LOG_DEBUG("Redis向Mysql刷新消息");
    table_->InsertBatch(msgs);
  }
}

}  // namespace Xianwei
