#include "utils.h"

namespace Xianwei {
std::string uuid() {
  std::stringstream ss;
  std::random_device rd;
  std::mt19937 generator(rd());
  std::uniform_int_distribution<int> distribution(0, 255);
  for (int i = 0; i < 10; ++i) {
    ss << std::setw(2) << std::setfill('0') << std::hex
       << distribution(generator);
    if (i == 1) {
      ss << '-';
    }
  }
  ss << '-';
  static std::atomic<short> id(0);
  short tmp = id.fetch_add(1);
  ss << std::setw(4) << std::setfill('0') << std::hex << tmp;
  return ss.str();
}

bool ReadFile(const std::string& filename, std::string& body) {
  std::ifstream in(filename, std::ios_base::binary | std::ios::in);
  if (!in.is_open()) {
    LOG_ERROR("文件{}打开失败", filename);
    return false;
  }
  size_t sz = 0;
  in.seekg(0, in.end);
  sz = in.tellg();
  in.seekg(0, in.beg);
  body.resize(sz);
  in.read(&body[0], sz);
  if (!in.good()) {
    LOG_ERROR("读取文件{}失败", filename);
    in.close();
    return false;
  }
  in.close();
  return true;
}

bool WriteFile(const std::string& filename, const std::string& data) {
  std::ofstream out(
      filename, std::ios_base::trunc | std::ios_base::binary | std::ios::out);
  if (!out.is_open()) {
    LOG_ERROR("文件{}打开失败", filename);
    return false;
  }
  out.write(data.c_str(), data.size());
  if (!out.good()) {
    LOG_ERROR("写入文件{}失败", filename);
    out.close();
    return false;
  }
  out.close();
  return true;
}
}  // namespace Xianwei
