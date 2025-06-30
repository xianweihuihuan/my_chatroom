#pragma once
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <iostream>

namespace Xianwei {
extern std::shared_ptr<spdlog::logger> g_default_logger;
void init_logger(bool mode, const std::string& filename, int32_t level);
#define LOG_TRACE(format, ...)                                                 \
  Xianwei::g_default_logger->trace(std::string("[{},{}] ") + format, __FILE__, \
                                   __LINE__, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...)                                                 \
  Xianwei::g_default_logger->debug(std::string("[{},{}] ") + format, __FILE__, \
                                   __LINE__, ##__VA_ARGS__)
#define LOG_INFO(format, ...)                                                 \
  Xianwei::g_default_logger->info(std::string("[{},{}] ") + format, __FILE__, \
                                  __LINE__, ##__VA_ARGS__)
#define LOG_WARN(format, ...)                                                 \
  Xianwei::g_default_logger->warn(std::string("[{},{}] ") + format, __FILE__, \
                                  __LINE__, ##__VA_ARGS__)
#define LOG_ERROR(format, ...)                                                 \
  Xianwei::g_default_logger->error(std::string("[{},{}] ") + format, __FILE__, \
                                   __LINE__, ##__VA_ARGS__)
#define LOG_FATAL(format, ...)                                          \
  Xianwei::g_default_logger->critical(std::string("[{},{}] ") + format, \
                                      __FILE__, __LINE__, ##__VA_ARGS__)
}  // namespace Xianwei
