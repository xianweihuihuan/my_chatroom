#pragma once
#include "file-odb.hxx"
#include "file.hxx"
#include "mysql.h"

namespace Xianwei {
class FileTable {
 public:
  using ptr = std::shared_ptr<FileTable>;
  FileTable(const std::shared_ptr<odb::core::database>& db) : db_(db) {}

  bool Insert(File& file) {
    try {
      odb::transaction trans(db_->begin());
      db_->persist(file);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("新增文件信息失败{}:{} - {}", file.SessionId(), file.UserId(),
                file.FileName());
      return false;
    }
    return true;
  }

  std::string FileId(const std::string& sid,
                     const std::string& uid,
                     const std::string& file_name) {
    std::string ret;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<File> query;
      typedef odb::result<File> result;
      auto r = db_->query_one<File>(query::user_id == uid &&
                                    query::session_id == sid &&
                                    query::file_name == file_name);
      if (r) {
        ret = r->FileId();
      }
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("获取文件编号失败");
      return std::string();
    }
    return ret;
  }

  bool Exist(const std::string& sid,
             const std::string& uid,
             const std::string& file_name) {
    bool flag;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<File> query;
      typedef odb::result<File> result;
      result r(db_->query<File>(query::user_id == uid &&
                                query::session_id == sid &&
                                query::file_name == file_name));
      flag = !r.empty();
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("获取文件{}-{}存在消息失败：{}", uid, sid, e.what());
      return false;
    }
    return flag;
  }

  std::vector<std::string> AllFileID(const std::string& sid) {
    std::vector<std::string> ret;
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<File> query;
      typedef odb::result<File> result;
      result r(db_->query<File>(query::session_id == sid));
      for (auto id : r) {
        ret.emplace_back(id.FileId());
      }
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("获取文件消息失败：{}", e.what());
      return std::vector<std::string>();
    }
    return ret;
  }

  bool RemoveAll(const std::string& sid) {
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<File> query;
      db_->erase_query<File>(query::session_id == sid);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("删除文件信息失败：{}", e.what());
      return false;
    }
    return true;
  }

  bool Remove(const std::string& uid, const std::string& sid) {
    try {
      odb::transaction trans(db_->begin());
      typedef odb::query<File> query;
      db_->erase_query<File>(query::user_id == uid && query::session_id == sid);
      trans.commit();
    } catch (const std::exception& e) {
      LOG_ERROR("删除文件信息{}-{}失败：{}", uid, sid, e.what());
      return false;
    }
    return true;
  }

 private:
  std::shared_ptr<odb::core::database> db_;
};
}  // namespace Xianwei
