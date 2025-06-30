#pragma once
#include <cstdlib>  // std::exit
#include <iostream>
#include <memory>  // std::auto_ptr
#include <odb/database.hxx>
#include <odb/mysql/database.hxx>
#include <string>
#include "logger.h"

namespace Xianwei {
class ODBFactory {
 public:
  static std::shared_ptr<odb::core::database> Create(const std::string& user,
                                                     const std::string& pswd,
                                                     const std::string& host,
                                                     const std::string& db,
                                                     const std::string& cset,
                                                     int port,
                                                     int conn_pool_count);
};
}  // namespace Xianwei
