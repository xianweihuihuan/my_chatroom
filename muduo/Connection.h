// connection.hpp
#pragma once
#include <functional>
#include <memory>
#include "Buffer.h"
#include "Channel.h"
#include "EventLoop.h"
#include "Socket.h"

namespace Xianwei {

class Connection;
using PtrConnection = std::shared_ptr<Connection>;

// 连接状态枚举
enum ConnStatus { DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING };

class Connection : public std::enable_shared_from_this<Connection> {
 public:
  using ConnectedCallback = std::function<void(const PtrConnection&)>;
  using MessageCallback = std::function<void(const PtrConnection&, Buffer*)>;
  using ClosedCallback = std::function<void(const PtrConnection&)>;
  using AnyEventCallback = std::function<void(const PtrConnection&)>;

  // Connection(EventLoop* loop, uint64_t conn_id, int sockfd, SSL_CTX* ctx);
  Connection(EventLoop* loop,
             uint64_t conn_id,
             int sockfd);

  ~Connection();

  int Fd() const;
  int Id() const;
  bool Connected() const;

  void SetConnectedCallback(const ConnectedCallback& cb);
  void SetMessageCallback(const MessageCallback& cb);
  void SetClosedCallback(const ClosedCallback& cb);
  void SetAnyEventCallback(const AnyEventCallback& cb);
  void SetSrvClosedCallback(const ClosedCallback& cb);
  ssize_t Recv(void* buf, size_t len);

  void Established();
  void Send(const std::string& buf);
  void Shutdown();
  void Release();
  void EnableInactiveRelease(int sec);
  void CancelInactiveRelease();
  EventLoop* GetOwner();
  Socket GetSocket();

 private:
  void HandleRead();
  void HandleWrite();
  void HandleClose();
  void HandleError();
  void HandleEvent();
  void EstablishedInLoop();
  void ReleaseInLoop();
  void SendInLoop(const std::string& buf);
  void ShutdownInLoop();
  void EnableInactiveReleaseInLoop(int sec);
  void CancelInactiveReleaseInLoop();

 private:
  uint64_t conn_id_;
  int sockfd_;
  bool enable_inactive_release_;
  EventLoop* loop_;
  ConnStatus status_;
  Socket socket_;
  Channel channel_;
  Buffer input_buffer_;
  Buffer output_buffer_;

  std::mutex lock_;

  ConnectedCallback connected_cb_;
  MessageCallback message_cb_;
  ClosedCallback closed_cb_;
  AnyEventCallback event_cb_;
  ClosedCallback srv_closed_cb_;
};

}  // namespace Xianwei
