#include "Connection.h"
#include "logger.h"

namespace Xianwei {

// Connection::Connection(EventLoop* loop,
//                        uint64_t conn_id,
//                        int sockfd,
//                        SSL_CTX* ctx)
//     : conn_id_(conn_id),
//       sockfd_(sockfd),
//       enable_inactive_release_(false),
//       loop_(loop),
//       status_(CONNECTING),
//       socket_(sockfd),
//       channel_(loop, sockfd),
//       ssl_ctx_(ctx) {
//   socket_.NonBlock();
//   ssl_ = SSL_new(ssl_ctx_);
//   SSL_set_fd(ssl_, sockfd_);
//   SSL_set_accept_state(ssl_);
//   channel_.SetCloseCallback([this]() { HandleClose(); });
//   channel_.SetEventCallback([this]() { HandleEvent(); });
//   channel_.SetReadCallback([this]() { HandleRead(); });
//   channel_.SetWriteCallback([this]() { HandleWrite(); });
//   channel_.SetErrorCallback([this]() { HandleError(); });
// }

Connection::Connection(EventLoop* loop,
                       uint64_t conn_id,
                       int sockfd,
                       SSL_CTX* ctx,
                       bool enable_ssl)
    : conn_id_(conn_id),
      sockfd_(sockfd),
      enable_inactive_release_(false),
      loop_(loop),
      status_(CONNECTING),
      socket_(sockfd),
      channel_(loop, sockfd),
      ssl_ctx_(ctx),
      ssl_(nullptr),
      enable_ssl_(enable_ssl) {
  socket_.NonBlock();
  if (enable_ssl_) {
    ssl_ = SSL_new(ssl_ctx_);
    SSL_set_fd(ssl_, sockfd_);
    SSL_set_accept_state(ssl_);
  }
  channel_.SetCloseCallback([this]() { HandleClose(); });
  channel_.SetEventCallback([this]() { HandleEvent(); });
  channel_.SetReadCallback([this]() { HandleRead(); });
  channel_.SetWriteCallback([this]() { HandleWrite(); });
  channel_.SetErrorCallback([this]() { HandleError(); });
}

Connection::~Connection() {
  FreeSSL();
}

int Connection::Fd() const {
  return sockfd_;
}
int Connection::Id() const {
  return conn_id_;
}
bool Connection::Connected() const {
  return status_ == CONNECTED;
}

void Connection::SetConnectedCallback(const ConnectedCallback& cb) {
  connected_cb_ = cb;
}
void Connection::SetMessageCallback(const MessageCallback& cb) {
  message_cb_ = cb;
}
void Connection::SetClosedCallback(const ClosedCallback& cb) {
  closed_cb_ = cb;
}
void Connection::SetAnyEventCallback(const AnyEventCallback& cb) {
  event_cb_ = cb;
}
void Connection::SetSrvClosedCallback(const ClosedCallback& cb) {
  srv_closed_cb_ = cb;
}

void Connection::Established() {
  loop_->RunInLoop([this]() { EstablishedInLoop(); });
}

void Connection::EstablishedInLoop() {
  // assert(status_ == CONNECTING);
  // status_ = CONNECTED;
  // channel_.EnableRead();
  // if (connected_cb_)
  //   connected_cb_(shared_from_this());
  assert(status_ == CONNECTING);
  // 不立刻标记 CONNECTED，也不回调 connected_cb_
  // 而是开启异步 TLS 握手流程
  if (enable_ssl_) {
    DoHandshake();
  } else {
    status_ = CONNECTED;
    channel_.EnableRead();
    if (connected_cb_) {
      connected_cb_(shared_from_this());
    }
  }
}

void Connection::HandleRead() {
  // char buf[65536];
  // ssize_t ret = SSL_read(ssl_, buf, sizeof(buf));
  // if (ret < 0)
  //   return ShutdownInLoop();
  // input_buffer_.WriteAndPush(buf, ret);
  // if (input_buffer_.ReadAbleSize() > 0 && message_cb_)
  //   message_cb_(shared_from_this(), &input_buffer_);
  if (status_ == CONNECTING && enable_ssl_) {
    DoHandshake();
    return;
  }
  char buf[65536];
  if (enable_ssl_) {
    ssize_t ret = SSL_read(ssl_, buf, sizeof(buf));
    if (ret > 0) {
      input_buffer_.WriteAndPush(buf, ret);
      if (input_buffer_.ReadAbleSize() > 0 && message_cb_)
        message_cb_(shared_from_this(), &input_buffer_);
      return;
    }
    int err = SSL_get_error(ssl_, ret);
    if (err == SSL_ERROR_WANT_READ) {
      channel_.EnableRead();
    } else if (err == SSL_ERROR_WANT_WRITE) {
      channel_.EnableWrite();
    } else if (err == SSL_ERROR_ZERO_RETURN) {
      ShutdownInLoop();
    } else {
      ShutdownInLoop();
    }
  } else {
    ssize_t ret = socket_.NonBlockRecv(buf, sizeof(buf));
    if (ret > 0) {
      input_buffer_.WriteAndPush(buf, ret);
      if (input_buffer_.ReadAbleSize() > 0 && message_cb_) {
        message_cb_(shared_from_this(), &input_buffer_);
      }
      return;
    }
    if(ret == 0){
      ShutdownInLoop();
      return;
    }
    if (errno == EAGAIN || errno == EINTR) {
      return;  
    }
    ShutdownInLoop();
  }
}

void Connection::HandleWrite() {
  // ssize_t ret = SSL_write(ssl_, output_buffer_.ReadPosition(),
  //                         output_buffer_.ReadAbleSize());
  // if (ret < 0)
  //   return Release();
  // output_buffer_.MoveReadIndex(ret);
  // if (output_buffer_.ReadAbleSize() == 0) {
  //   channel_.DisableWrite();
  //   if (status_ == DISCONNECTING)
  //     Release();
  // }
  if (status_ == CONNECTING && enable_ssl_) {
    DoHandshake();
    return;
  }

  // 握手完成后，正常 SSL_write，处理 partial write
  size_t total = output_buffer_.ReadAbleSize();
  size_t sent = 0;
  if (enable_ssl_) {
    while (sent < total) {
      int n =
          SSL_write(ssl_, output_buffer_.ReadPosition() + sent, total - sent);
      if (n > 0) {
        sent += n;
        continue;
      }
      int err = SSL_get_error(ssl_, n);
      if (err == SSL_ERROR_WANT_WRITE) {
        channel_.EnableWrite();
        return;
      }
      // 其他情况均视为错误，关闭连接
      Release();
      return;
    }
  } else {
    while (sent < total) {
      ssize_t n = socket_.NonBlockSend(output_buffer_.ReadPosition() + sent,
                                       total - sent);
      if (n > 0) {
        sent += n;
        continue;
      }
      if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
        channel_.EnableWrite();
        return;
      }
      Release();
      return;
    }
    Release();
    return;
  }

  // 全部写完，移动读指针并取消写事件
  output_buffer_.MoveReadIndex(sent);
  channel_.DisableWrite();
  if (status_ == DISCONNECTING)
    Release();
}

void Connection::HandleClose() {
  if (input_buffer_.ReadAbleSize() > 0 && message_cb_) {
    message_cb_(shared_from_this(), &input_buffer_);
  }
  Release();
}

void Connection::HandleError() {
  HandleClose();
}

void Connection::HandleEvent() {
  if (enable_inactive_release_)
    loop_->TimerRefresh(conn_id_);
  if (event_cb_)
    event_cb_(shared_from_this());
}

void Connection::Release() {
  if (status_ == DISCONNECTED) {
    return;
  }
  status_ = DISCONNECTED;
  loop_->QueueInLoop([this]() { ReleaseInLoop(); });
}

void Connection::FreeSSL() {
  if (ssl_) {
    SSL_shutdown(ssl_);
    SSL_free(ssl_);
    ssl_ = nullptr;
  }
}

void Connection::ReleaseInLoop() {
  FreeSSL();
  // status_ = DISCONNECTED;
  channel_.Remove();
  socket_.Close();
  if (loop_->HasTimer(conn_id_))
    CancelInactiveReleaseInLoop();
  if (closed_cb_)
    closed_cb_(shared_from_this());
  if (srv_closed_cb_)
    srv_closed_cb_(shared_from_this());
}

void Connection::Send(const char* data, size_t len) {
  Buffer buf;
  buf.WriteAndPush(data, len);
  loop_->RunInLoop([this, buf]() mutable { SendInLoop(buf); });
}

void Connection::SendInLoop(Buffer& buf) {
  if (status_ == DISCONNECTED)
    return;
  output_buffer_.WriteAndPush(buf);
  if (!channel_.IsWriting())
    channel_.EnableWrite();
}

void Connection::Shutdown() {
  loop_->RunInLoop([this]() { ShutdownInLoop(); });
}

void Connection::ShutdownInLoop() {
  status_ = DISCONNECTING;
  if (input_buffer_.ReadAbleSize() > 0 && message_cb_)
    message_cb_(shared_from_this(), &input_buffer_);
  if (output_buffer_.ReadAbleSize() > 0) {
    if (!channel_.IsWriting())
      channel_.EnableWrite();
  }
  if (output_buffer_.ReadAbleSize() == 0)
    Release();
}

void Connection::EnableInactiveRelease(int sec) {
  loop_->RunInLoop([this, sec]() { EnableInactiveReleaseInLoop(sec); });
}

void Connection::EnableInactiveReleaseInLoop(int sec) {
  enable_inactive_release_ = true;
  if (loop_->HasTimer(conn_id_)) {
    loop_->TimerRefresh(conn_id_);
  } else {
    loop_->TimerAdd(conn_id_, sec, [this]() { Release(); });
  }
}

void Connection::CancelInactiveRelease() {
  loop_->RunInLoop([this]() { CancelInactiveReleaseInLoop(); });
}

void Connection::CancelInactiveReleaseInLoop() {
  enable_inactive_release_ = false;
  if (loop_->HasTimer(conn_id_))
    loop_->TimerCancel(conn_id_);
}

void Connection::DoHandshake() {
  if (!enable_ssl_) {
    return;
  }
  // 发起或继续 TLS 握手
  int ret = SSL_do_handshake(ssl_);
  if (ret == 1) {
    // 握手完成，切换到正常 I/O
    status_ = CONNECTED;
    channel_.DisableRead();
    channel_.DisableWrite();
    channel_.SetReadCallback([this]() { HandleRead(); });
    channel_.SetWriteCallback([this]() { HandleWrite(); });
    channel_.EnableRead();
    if (connected_cb_)
      connected_cb_(shared_from_this());
    return;
  }

  // 根据错误类型注册下一步事件
  int err = SSL_get_error(ssl_, ret);
  if (err == SSL_ERROR_WANT_READ) {
    // 还需要读数据才能继续握手
    channel_.EnableRead();
  } else if (err == SSL_ERROR_WANT_WRITE) {
    // 还需要写数据才能继续握手
    channel_.EnableWrite();
  } else {
    // 真正的失败，直接关闭连接
    Release();
  }
}

EventLoop* Connection::GetOwner() {
  return loop_;
}

ssize_t Connection::Recv(void* buf, size_t len) {
  if (status_ != CONNECTED)
    return -1;
  if (enable_ssl_) {
    int ret = SSL_read(ssl_, buf, static_cast<int>(len));
    if (ret > 0)
      return ret;
    int err = SSL_get_error(ssl_, ret);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
      return 0;
    return -1;
  }
  return socket_.NonBlockRecv(buf, len);
}

Socket Connection::GetSocket(){
  return socket_;
}
}  // namespace Xianwei
