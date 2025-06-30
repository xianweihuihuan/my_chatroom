#pragma once
#include <boost/date_time/posix_time/posix_time.hpp>
#include <cstddef>
#include <odb/nullable.hxx>
#include <string>

namespace Xianwei {
enum level { unignore, ignore };
#pragma db object table("relation")
class Relation {
 public:
  Relation() {}
  Relation(const std::string& uid,
           const std::string& pid,
           const std::string& sid,
           const level& lel)
      : _user_id(uid), _peer_id(pid), _session_id(sid), _if_ignore(lel) {}

  std::string UserId() { return _user_id; }
  void SetUserId(const std::string& uid) { _user_id = uid; }

  std::string PeerId() { return _peer_id; }
  void SetPeerId(const std::string& pid) { _peer_id = pid; }

  std::string SessionId() { return _session_id; }
  void SetSessionId(const std::string& sid) { _session_id = sid; }

  level Ifignore() { return _if_ignore; }
  void SetIfignore(const level& lel) { _if_ignore = lel; }

 private:
  friend class odb::access;
#pragma db id auto
  unsigned long _id;
#pragma db type("varchar(64)") index
  std::string _user_id;
#pragma db type("varchar(64)") index
  std::string _peer_id;
#pragma db type("varchar(64)") index
  std::string _session_id;
#pragma db type("tinyint")
  level _if_ignore;
};
}  // namespace Xianwei
