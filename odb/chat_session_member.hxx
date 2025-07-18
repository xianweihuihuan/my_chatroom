#pragma once
#include <boost/date_time/posix_time/posix_time.hpp>
#include <cstddef>
#include <odb/nullable.hxx>
#include <string>

namespace Xianwei {
enum group_level { Single, Owner, Admin, Person };
#pragma db object table("chat_session_member")
class ChatSessionMember {
 public:
  ChatSessionMember() {}
  ChatSessionMember(const std::string& session_id,
                    const std::string& user_id,
                    const group_level& level)
      : _session_id(session_id), _user_id(user_id), _level(level) {}

  std::string SessionId()const  { return _session_id; }
  void SetSessionId(const std::string& session_id) { _session_id = session_id; }

  std::string UserId()const { return _user_id; }
  void SetUserId(const std::string& user_id) { _user_id = user_id; }

  group_level Level()const { return _level; }
  void SetLevel(const group_level& level) { _level = level; }

 private:
  friend class odb::access;
#pragma db id auto
  unsigned long _id;
#pragma db type("varchar(60)") index
  std::string _session_id;
#pragma db type("varchar(60)") index
  std::string _user_id;
#pragma db type("tinyint")
  group_level _level;
};
}  // namespace Xianwei
