#include "Buffer.h"

namespace Xianwei {
void Buffer::MoveReadIndex(uint64_t len) {
  if (len == 0) {
    return;
  }
  assert(len <= ReadAbleSize());
  read_index_ += len;
}

void Buffer::MoveWriteIndex(uint64_t len) {
  if (len == 0) {
    return;
  }
  assert(len <= TailFreeSize());
  write_index_ += len;
}

void Buffer::EnsureWriteSpace(uint64_t len) {
  if (TailFreeSize() >= len) {
    return;
  }
  if (len <= TailFreeSize() + HeadFreeSize()) {
    uint64_t sz = ReadAbleSize();
    std::copy(ReadPosition(), ReadPosition() + sz, Begin());
    read_index_ = 0;
    write_index_ = sz;
  } else {
    //LOG_DEBUG("对缓冲区进行扩容：{}", write_index_ + len);
    buffer_.resize(write_index_ + len);
  }
}

void Buffer::Write(const void* data, uint64_t len) {
  if (len == 0) {
    return;
  }
  EnsureWriteSpace(len);
  const char* d = (const char*)data;
  std::copy(d, d + len, WritePosition());
}

void Buffer::WriteAndPush(const void* data, uint64_t len) {
  Write(data, len);
  MoveWriteIndex(len);
}

void Buffer::WriteAndPush(const std::string& data) {
  Write(data.c_str(), data.size());
  MoveWriteIndex(data.size());
}

void Buffer::WriteAndPush(Buffer& data) {
  Write(data.ReadPosition(), data.ReadAbleSize());
  MoveWriteIndex(data.ReadAbleSize());
}

void Buffer::Read(void* buf, uint64_t len) {
  assert(len <= ReadAbleSize());
  std::copy(ReadPosition(), ReadPosition() + len, (char*)buf);
}

void Buffer::ReadAndPop(void* buf, uint64_t len) {
  Read(buf, len);
  MoveReadIndex(len);
}

std::string Buffer::ReadAsString(uint64_t len) {
  assert(len <= ReadAbleSize());
  std::string ret;
  ret.resize(len);
  Read(&ret[0], len);
  return std::move(ret);
}

std::string Buffer::ReadAsStringAndPop(uint64_t len) {
  std::string ret = ReadAsString(len);
  MoveReadIndex(len);
  return std::move(ret);
}

char* Buffer::FindCRLF() {
  return (char*)memchr(ReadPosition(), '\n', ReadAbleSize());
}

std::string Buffer::GetLine() {
  char* pos = FindCRLF();
  if (!pos) {
    return "";
  }
  return std::move(ReadAsString(pos - ReadPosition() + 1));
}
std::string Buffer::GetLineAndPop() {
  std::string ret = GetLine();
  MoveReadIndex(ret.size());
  return std::move(ret);
}
}  // namespace Xianwei
