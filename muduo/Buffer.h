#pragma once

#include <unistd.h>
#include <vector>
#include <cassert>
#include <cstdint>
#include <string>
#include "logger.h"

namespace Xianwei {
#define BUFFER_DEFAULT_SIZE 4096
class Buffer {
 public:
  Buffer() : buffer_(BUFFER_DEFAULT_SIZE), read_index_(0), write_index_(0) {}

  char* Begin() { return &*buffer_.begin(); }
  char* ReadPosition() { return Begin() + read_index_; }
  char* WritePosition() { return Begin() + write_index_; }

  uint64_t TailFreeSize() { return buffer_.size() - write_index_; }
  uint64_t HeadFreeSize() { return read_index_; }
  uint64_t ReadAbleSize() { return write_index_ - read_index_; }

  void MoveReadIndex(uint64_t len);
  void MoveWriteIndex(uint64_t len);

  void EnsureWriteSpace(uint64_t len);

  void Write(const void* data, uint64_t len);

  void WriteAndPush(const void* data, uint64_t len);
  void WriteAndPush(const std::string& data);
  void WriteAndPush(Buffer& data);

  void Read(void* buf, uint64_t len);
  void ReadAndPop(void* buf, uint64_t len);
  std::string ReadAsString(uint64_t len);
  std::string ReadAsStringAndPop(uint64_t len);

  char* FindCRLF();

  std::string GetLine();
  std::string GetLineAndPop();

  void Clear() { read_index_ = write_index_ = 0; }

 private:
  std::vector<char> buffer_;
  uint64_t read_index_;
  uint64_t write_index_;
};
}  // namespace Xianwei
