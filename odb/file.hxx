#pragma once
#include <cstddef>
#include <odb/nullable.hxx>
#include <string>

namespace Xianwei {
#pragma db object table("file")
class File {
 public:
  File() = default;
  File(const std::string& user_id,
       const std::string& session_id,
       const std::string& file_name,
       const std::string& file_id,
       const std::string& file_sum)
      : _user_id(user_id),
        _session_id(session_id),
        _file_name(file_name),
        _file_id(file_id),
        _file_sum(file_sum) {}

  const std::string& UserId() const { return _user_id; }
  const std::string& SessionId() const { return _session_id; }
  const std::string& FileName() const { return _file_name; }
  const std::string& FileId() const { return _file_id; }
  const std::string& FileSum() const { return _file_sum; }

  void SetUserId(const std::string& value) { _user_id = value; }
  void SetSessionId(const std::string& value) { _session_id = value; }
  void SetFileName(const std::string& value) { _file_name = value; }
  void SetFileId(const std::string& value) { _file_id = value; }
  void SetFileSum(const std::string& value) { _file_sum = value; }

 private:
  friend class odb::access;
#pragma db id auto
  unsigned long _id;
#pragma db type("varchar(60)") index
  std::string _user_id;
#pragma db type("varchar(60)") index
  std::string _session_id;
#pragma db type("varchar(60)") index
  std::string _file_name;
#pragma db type("varchar(60)") index
  std::string _file_id;
#pragma db type("varchar(255)") index
  std::string _file_sum;
};
}  // namespace Xianwei
