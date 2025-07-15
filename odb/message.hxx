#pragma once
#include <boost/date_time/posix_time/posix_time.hpp>
#include <cstddef>
#include <odb/nullable.hxx>
#include <string>

namespace Xianwei {
#pragma db object table("message")
class Message {
 public:
  Message() {}
  Message(const std::string& mid,
          const std::string& uid,
          const std::string& sid,
          const unsigned char& type,
          const boost::posix_time::ptime& time)
      : _message_id(mid),
        _session_id(sid),
        _user_id(uid),
        _message_type(type),
        _create_time(time) {}

  std::string MessageId() { return _message_id; }
  void SetMessageId(const std::string& mid) { _message_id = mid; }

  std::string SessionId() { return _session_id; }
  void SetSessioneId(const std::string& sid) { _session_id = sid; }

  std::string UserId() { return _user_id; }
  void SetUserId(const std::string& uid) { _user_id = uid; }

  unsigned char MessageType() { return _message_type; }
  void SetMessageType(const unsigned char& type) { _message_type = type; }

  boost::posix_time::ptime CreateTime() { return _create_time; }
  void SetCreateTime(const boost::posix_time::ptime& time) {
    _create_time = time;
  }

  std::string Content() {
    if (!_content) {
      return std::string();
    }
    return *_content;
  }
  void SetContent(const std::string& content) { _content = content; }

 private:
  friend class odb::access;
#pragma db id auto
  unsigned long _id;
#pragma db type("varchar(64)") index unique
  std::string _message_id;
#pragma db type("varchar(64)") index
  std::string _session_id;
#pragma db type("varchar(64)")
  std::string _user_id;
  unsigned char _message_type;
#pragma db type("TIMESTAMP")
  boost::posix_time::ptime _create_time;
  odb::nullable<std::string> _content;
};
}  // namespace Xianwei
   