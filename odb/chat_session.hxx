#pragma once
#include <boost/date_time/posix_time/posix_time.hpp>
#include <cstddef>
#include <odb/nullable.hxx>
#include <string>
#include "chat_session_member.hxx"

namespace Xianwei {
enum ChatType { SINGLE = 1, GROUP = 2 };
#pragma db object table("chat_session")
class ChatSession {
 public:
  ChatSession() {}
  ChatSession(const std::string& sid, ChatType type)
      : _session_id(sid), _chat_type(type) {}

  std::string SessionId() { return _session_id; }
  void SetSessionId(const std::string& uid) { _session_id = uid; }

  std::string SessionName() {
    if (!_session_name) {
      return "";
    }
    return *_session_name;
  }
  void SetSessionName(const std::string& name) { _session_name = name; }

  ChatType ChatTypeF() { return _chat_type; }
  void SetChatType(ChatType type) { _chat_type = type; }

  std::string SessionOwner(){
    if(!_session_owner){
      return "";
    }
    return *_session_owner;
  }
  void SetSessionOwner(const std::string& session_owner){
    _session_owner = session_owner;
  }



 private:
  friend class odb::access;
#pragma db id auto
  unsigned long _id;
#pragma db type("varchar(60)") index unique
  std::string _session_id;
#pragma db type("tinyint")
  ChatType _chat_type;
#pragma db type("varchar(60)") index unique
  odb::nullable<std::string> _session_name;
#pragma db type("varchar(60)") index
  odb::nullable<std::string> _session_owner;
};

// css::chat_type == 1 && csm1::user_id == uid && scm2::user_id != uid
#pragma db view object(ChatSession = css)                                    \
    object(ChatSessionMember = csm1 : css::_session_id == csm1::_session_id) \
        object(ChatSessionMember =                                           \
                   csm2 : css::_session_id == csm2::_session_id) query((?))
struct SingleChatSession {
#pragma db column(css::_session_id)
  std::string session_id;
#pragma db column(csm2::_user_id)
  std::string friend_id;
};

// css::chat_type == 2 && csm::user_id == uid
#pragma db view object(ChatSession = css)                                  \
    object(ChatSessionMember = csm : css::_session_id == csm::_session_id) \
        query((?))
struct GroupChatSession {
#pragma db column(css::_session_id)
  std::string session_id;
#pragma db column(css::_session_name)
  std::string session_name;
};
}  // namespace Xianwei
