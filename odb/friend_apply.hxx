#pragma once
#include <boost/date_time/posix_time/posix_time.hpp>
#include <cstddef>
#include <odb/nullable.hxx>
#include <string>

namespace Xianwei {
#pragma db object table("friend_apply")
class FriendApply {
 public:
  FriendApply() {}
  FriendApply(const std::string& eid,
              const std::string& uid,
              const std::string& pid)
      : _event_id(eid), _user_id(uid), _peer_id(pid) {}

  std::string EventId() { return _event_id; }
  void SetEventId(const std::string& eid) { _event_id = eid; }

  std::string UserId() { return _user_id; }
  void SetUserId(const std::string& uid) { _user_id = uid; }

  std::string PeerId() { return _peer_id; }
  void SetPeerId(const std::string& pid) { _peer_id = pid; }

 private:
  friend class odb::access;
#pragma db id auto
  unsigned long _id;
#pragma db type("varchar(64)") index unique
  std::string _event_id;
#pragma db type("varchar(64)") index
  std::string _user_id;
#pragma db type("varchar(64)") index
  std::string _peer_id;
};
}  // namespace Xianwei
