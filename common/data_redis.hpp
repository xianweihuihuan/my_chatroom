#include <sw/redis++/redis.h>
#include <iostream>

namespace Xianwei {
class RedisClientFactory {
 public:
  static std::shared_ptr<sw::redis::Redis> Create(const std::string& host,
                                                  int port,
                                                  int db,
                                                  bool keep_alive) {
    sw::redis::ConnectionOptions opts;
    opts.host = host;
    opts.port = port;
    opts.db = db;
    opts.keep_alive = keep_alive;
    auto res = std::make_shared<sw::redis::Redis>(opts);
    return res;
  }
};

// class Session {
//  public:
//   Session(const std::shared_ptr<sw::redis::Redis>& client) : client_(client) {}

//   void Append(const std::string& sid, const std::string& uid) {
//     client_->set(sid, uid);
//   }

//   void Remove(const std::string& sid) { client_->del(sid); }

//   sw::redis::OptionalString Uid(const std::string& sid) {
//     return client_->get(sid);
//   }

//  private:
//   std::shared_ptr<sw::redis::Redis> client_;
// };

class Status {
 public:
  using ptr = std::shared_ptr<Status>;
  Status(const std::shared_ptr<sw::redis::Redis>& client) : client_(client) {}

  void Append(const std::string& uid) { client_->set(uid, ""); }

  void Remove(const std::string& uid) { client_->del(uid); }

  bool Exists(const std::string& uid) { return client_->exists(uid); }

 private:
  std::shared_ptr<sw::redis::Redis> client_;
};

class Codes {
 public:
  using ptr = std::shared_ptr<Codes>;
  Codes(const std::shared_ptr<sw::redis::Redis>& client) : client_(client) {}

  void Append(
      const std::string& vid,
      const std::string& code,
      const std::chrono::milliseconds& t = std::chrono::milliseconds(300000)) {
    client_->set(vid, code, t);
  }

  void Remove(const std::string& vid) { client_->del(vid); }

  sw::redis::OptionalString Code(const std::string& vid) {
    return client_->get(vid);
  }

 private:
  std::shared_ptr<sw::redis::Redis> client_;
};

class OfflineMessage {
 public:
  using ptr = std::shared_ptr<OfflineMessage>;
  OfflineMessage(const std::shared_ptr<sw::redis::Redis>& client)
      : client_(client) {
  }
  //uid为消息发送者，pid为离线的消息接受者
  void SingleAppend(const std::string& pid,const std::string& body){
    client_->rpush("offline:single:" + pid, body);
  }

  
  void GroupAppend(const std::string& uid,const std::string& body){
    client_->rpush("offline:group:" + uid, body);
  }

  std::vector<std::string> GetSingle(const std::string& uid){
    std::vector<std::string> result;
    client_->lrange("offline:single:" + uid, 0, -1, std::back_inserter(result));
    return result;
  }

  std::vector<std::string> GetGroup(const std::string& uid){
    std::vector<std::string> result;
    client_->lrange("offline:group:" + uid, 0, -1, std::back_inserter(result));
    return result;
  }

  void Remove(const std::string& uid){
    client_->del("offline:single:" + uid);
    client_->del("offline:group:" + uid);
  }

 private:
  std::shared_ptr<sw::redis::Redis> client_;
};

class OfflineApply {
 public:
  using ptr = std::shared_ptr<OfflineApply>;
  OfflineApply(const std::shared_ptr<sw::redis::Redis>& client)
      : client_(client) {
  }
  //uid为消息发送者，pid为离线的消息接受者
  void SingleAppend(const std::string& pid,const std::string& body){
    client_->rpush("offapply:single:" + pid, body);
  }

  
  void GroupAppend(const std::string& uid,const std::string& body){
    client_->rpush("offapply:group:" + uid, body);
  }

  std::vector<std::string> GetSingle(const std::string& uid){
    std::vector<std::string> result;
    client_->lrange("offapply:single:" + uid, 0, -1, std::back_inserter(result));
    return result;
  }

  std::vector<std::string> GetGroup(const std::string& uid){
    std::vector<std::string> result;
    client_->lrange("offapply:group:" + uid, 0, -1, std::back_inserter(result));
    return result;
  }

  void Remove(const std::string& uid){
    client_->del("offapply:single:" + uid);
    client_->del("offapply:group:" + uid);
  }

 private:
  std::shared_ptr<sw::redis::Redis> client_;
};

}  // namespace  Xianwei
