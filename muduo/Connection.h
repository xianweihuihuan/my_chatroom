// connection.hpp
#pragma once

#include <openssl/ssl.h>
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

  Connection(EventLoop* loop, uint64_t conn_id, int sockfd, SSL_CTX* ctx);
  ~Connection();

  int Fd() const;
  int Id() const;
  bool Connected() const;

  void SetConnectedCallback(const ConnectedCallback& cb);
  void SetMessageCallback(const MessageCallback& cb);
  void SetClosedCallback(const ClosedCallback& cb);
  void SetAnyEventCallback(const AnyEventCallback& cb);
  void SetSrvClosedCallback(const ClosedCallback& cb);

  void Established();
  void Send(const char* data, size_t len);
  void Shutdown();
  void Release();
  void EnableInactiveRelease(int sec);
  void CancelInactiveRelease();
  EventLoop* GetOwner();

 private:
  void HandleRead();
  void HandleWrite();
  void HandleClose();
  void HandleError();
  void HandleEvent();
  void EstablishedInLoop();
  void ReleaseInLoop();
  void SendInLoop(Buffer& buf);
  void ShutdownInLoop();
  void EnableInactiveReleaseInLoop(int sec);
  void CancelInactiveReleaseInLoop();
  void FreeSSL();
  void DoHandshake();

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

  SSL_CTX* ssl_ctx_;
  SSL* ssl_;

  ConnectedCallback connected_cb_;
  MessageCallback message_cb_;
  ClosedCallback closed_cb_;
  AnyEventCallback event_cb_;
  ClosedCallback srv_closed_cb_;
};

}  // namespace Xianwei
