#include "Socket.h"

namespace Xianwei {

Socket::Socket() : sockfd_(-1) {}

Socket::Socket(int fd) : sockfd_(fd) {}

Socket::~Socket() {
  Close();
}

int Socket::Fd() const {
  return sockfd_;
}

bool Socket::Create() {
  sockfd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd_ < 0) {
    LOG_ERROR("创建 socket 失败: {}", strerror(errno));
    return false;
  }
  return true;
}

bool Socket::Bind(const std::string& ip, uint16_t port) {
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip.c_str());

  int ret = bind(sockfd_, (struct sockaddr*)&addr, sizeof(addr));
  if (ret < 0) {
    LOG_ERROR("绑定地址失败: {}", strerror(errno));
    return false;
  }
  return true;
}

bool Socket::Listen(int backlog) {
  int ret = listen(sockfd_, backlog);
  if (ret < 0) {
    LOG_ERROR("监听失败: {}", strerror(errno));
    return false;
  }
  return true;
}

bool Socket::Connect(const std::string& ip, uint16_t port) {
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip.c_str());

  int ret = connect(sockfd_, (struct sockaddr*)&addr, sizeof(addr));
  if (ret < 0) {
    LOG_ERROR("连接服务器失败: {}", strerror(errno));
    return false;
  }
  return true;
}

int Socket::Accept() {
  int newfd = accept(sockfd_, nullptr, nullptr);
  if (newfd < 0) {
    LOG_ERROR("accept 失败: {}", strerror(errno));
    return -1;
  }
  return newfd;
}

ssize_t Socket::Recv(void* buf, size_t len, int flag) {
  ssize_t ret = recv(sockfd_, buf, len, flag);
  if (ret <= 0) {
    if (errno == EAGAIN || errno == EINTR) {
      return 0;
    }
    LOG_ERROR("socket接受数据失败");
    return -1;
  }
  return ret;
}

ssize_t Socket::NonBlockRecv(void* buf, size_t len) {
  return Recv(buf, len, MSG_DONTWAIT);
}

ssize_t Socket::Send(const void* buf, size_t len, int flag) {
  ssize_t ret = send(sockfd_, buf, len, flag);
  if (ret < 0) {
    if (errno == EAGAIN || errno == EINTR) {
      return 0;
    }
    LOG_ERROR("socket发送数据失败");
    return -1;
  }
  return ret;
}

ssize_t Socket::NonBlockSend(void* buf, size_t len) {
  if (len == 0)
    return 0;
  return Send(buf, len, MSG_DONTWAIT);
}

void Socket::Close() {
  if (sockfd_ != -1) {
    ::close(sockfd_);
    sockfd_ = -1;
  }
}

bool Socket::CreateServer(uint16_t port, const std::string& ip, bool nonblock) {
  if (!Create())
    return false;
  if (nonblock)
    NonBlock();
  ReuseAddress();
  if (!Bind(ip, port))
    return false;
  if (!Listen())
    return false;
  return true;
}

bool Socket::CreateClient(uint16_t port, const std::string& ip) {
  if (!Create())
    return false;
  if (!Connect(ip, port))
    return false;
  return true;
}

void Socket::ReuseAddress() {
  int val = 1;
  setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, (void*)&val, sizeof(val));
  val = 1;
  setsockopt(sockfd_, SOL_SOCKET, SO_REUSEPORT, (void*)&val, sizeof(val));
}

void Socket::NonBlock() {
  int flags = fcntl(sockfd_, F_GETFL, 0);
  fcntl(sockfd_, F_SETFL, flags | O_NONBLOCK);
}

}  // namespace Xianwei
