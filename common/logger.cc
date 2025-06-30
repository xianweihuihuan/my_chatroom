#include "logger.h"

namespace Xianwei {
std::shared_ptr<spdlog::logger> g_default_logger = nullptr;
void init_logger(bool mode, const std::string& filename, int32_t level) {
  if (mode == false) {
    g_default_logger = spdlog::stdout_color_mt("default-logger");
    g_default_logger->set_level(spdlog::level::level_enum::trace);
    g_default_logger->flush_on(spdlog::level::level_enum::trace);
  } else {
    g_default_logger = spdlog::basic_logger_mt("default-logger", filename);
    g_default_logger->set_level((spdlog::level::level_enum)level);
    g_default_logger->flush_on((spdlog::level::level_enum)level);
  }
  g_default_logger->set_pattern("[%Y-%02m-%02d][%H:%M:%S][thread:%t][%-8l]%v");
}
}  // namespace Xianwei
