
#pragma once

#include <boost/date_time/posix_time/posix_time.hpp>
#include <cstddef>
#include <odb/nullable.hxx>
#include <string>

typedef boost::posix_time::ptime ptime;

namespace Xianwei {
#pragma db object table("user")
class User {
 public:
  User() {}
  User(const std::string& uid,
       const std::string& name,
       const std::string& passwd,
       const std::string& email)
      : _user_id(uid), _nickname(name), _passwd(passwd), _email(email) {}

  void SetUserId(const std::string& uid) { _user_id = uid; }
  std::string UserId() { return _user_id; }

  void SetPassword(const std::string& passwd) { _passwd = passwd; }
  std::string Password() { return _passwd; }

  void SetEmail(const std::string& email) { _email = email; }
  std::string Email() { return _email; }

  void SetNickname(const std::string& name) { _nickname = name; }
  std::string Nikename() { return _nickname; }

 private:
  friend class odb::access;
#pragma db id auto
  unsigned long _id;
#pragma db type("varchar(64)") unique index
  std::string _user_id;
#pragma db type("varchar(64)") unique index
  std::string _nickname;
#pragma db type("varchar(64)")
  std::string _passwd;
#pragma db type("varchar(64)") unique index
  std::string _email;
};
}  // namespace Xianwei