#pragma once
#include <boost/date_time/posix_time/posix_time.hpp>
#include <cstddef>
#include <odb/nullable.hxx>
#include <string>


namespace Xianwei {
#pragma db object table("session_apply")
class SessionApply {
 public:
  SessionApply() {}
  SessionApply(const std::string& eid,
              const std::string& sid,
              const std::string& uid)
      : _event_id(eid), _session_id(sid), _user_id(uid) {}

  std::string EventId() { return _event_id; }
  void SetEventId(const std::string& eid) { _event_id = eid; }

  std::string SessionId() { return _session_id; }
  void SetSessionId(const std::string& sid) { _session_id = sid; }

  std::string UserId() { return _user_id; }
  void SetUserId(const std::string& uid) { _user_id = uid; }

 private:
  friend class odb::access;
#pragma db id auto
  unsigned long _id;
#pragma db type("varchar(64)") index unique
  std::string _event_id;
#pragma db type("varchar(64)") index
  std::string _session_id;
#pragma db type("varchar(64)") index
  std::string _user_id;
};
}