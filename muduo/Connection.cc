#include "Connection.h"
#include "logger.h"

namespace Xianwei {

Connection::Connection(EventLoop* loop, uint64_t conn_id, int sockfd)
    : conn_id_(conn_id),
      sockfd_(sockfd),
      enable_inactive_release_(false),
      loop_(loop),
      status_(CONNECTING),
      socket_(sockfd),
      channel_(loop, sockfd) {
  socket_.NonBlock();
  channel_.SetCloseCallback([this]() { HandleClose(); });
  channel_.SetEventCallback([this]() { HandleEvent(); });
  channel_.SetReadCallback([this]() { HandleRead(); });
  channel_.SetWriteCallback([this]() { HandleWrite(); });
  channel_.SetErrorCallback([this]() { HandleError(); });
}

// Connection::Connection(EventLoop* loop,
//                        uint64_t conn_id,
//                        int sockfd,
//                        SSL_CTX* ctx,
//                        SSL* ssl)
//     : conn_id_(conn_id),
//       sockfd_(sockfd),
//       enable_inactive_release_(false),
//       loop_(loop),
//       status_(CONNECTING),
//       socket_(sockfd),
//       channel_(loop, sockfd),
//       ssl_ctx_(ctx),
//       ssl_(ssl),
//       enable_ssl_(true) {
//   socket_.NonBlock();
//   channel_.SetCloseCallback([this]() { HandleClose(); });
//   channel_.SetEventCallback([this]() { HandleEvent(); });
//   channel_.SetReadCallback([this]() { HandleRead(); });
//   channel_.SetWriteCallback([this]() { HandleWrite(); });
//   channel_.SetErrorCallback([this]() { HandleError(); });
// }

Connection::~Connection() {}

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
  assert(status_ == CONNECTING);

  status_ = CONNECTED;
  channel_.EnableRead();
  if (connected_cb_) {
    connected_cb_(shared_from_this());
  }
}

void Connection::HandleRead() {
  int savedErrno = 0;
  ssize_t n = input_buffer_.readFd(channel_.Fd(), &savedErrno);
  if (n > 0)
    message_cb_(shared_from_this(), &input_buffer_);
  else if (n == 0)
    HandleClose();
  else {
    errno = savedErrno;
    LOG_ERROR("TcpConnection::handleRead");
    HandleError();
  }
}

void Connection::HandleWrite() {
  if (channel_.IsWriting()) {
    ssize_t n = ::write(channel_.Fd(), output_buffer_.ReadPosition(),
                        output_buffer_.ReadAbleSize());
    LOG_INFO("写入数据");
    if (n > 0) {
      output_buffer_.MoveReadIndex(n);
      if (output_buffer_.ReadAbleSize() == 0) {
        channel_.DisableWrite();
        if (status_ == DISCONNECTING) {
          ShutdownInLoop();
        }
      } else {
        LOG_TRACE("I am going to write more data");
      }
    } else {
      LOG_ERROR("TcpConnection::handleWrite");
    }
  } else {
    LOG_TRACE("Connection is down,no more writing");
  }
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

void Connection::ReleaseInLoop() {
  status_ = DISCONNECTED;
  channel_.Remove();
  socket_.Close();
  if (loop_->HasTimer(conn_id_))
    CancelInactiveReleaseInLoop();
  if (closed_cb_)
    closed_cb_(shared_from_this());
  if (srv_closed_cb_)
    srv_closed_cb_(shared_from_this());
}

// void Connection::Send(const char* data, size_t len) {
//   Buffer buf(1024);
//   buf.WriteAndPush(data, len);
//   SendInLoop(buf);
// }

void Connection::Send(const std::string& buf) {
  if (loop_->IsInLoopThread()) {
    SendInLoop(buf);
  } else {
    loop_->RunInLoop([this, buf](){ SendInLoop(buf); });
  }
}

void Connection::SendInLoop(const std::string& buf) {
  // if (status_ == DISCONNECTED)
  //   return;
  // {
  //   std::unique_lock<std::mutex> mtx(lock_);
  //   output_buffer_.WriteAndPush(buf);
  // }
  // if (!channel_.IsWriting())
  //   channel_.EnableWrite();
  loop_->AssertInLoopThread();
  ssize_t nwrote = 0;
  if (!channel_.IsWriting() && output_buffer_.ReadAbleSize() == 0) {
    nwrote = ::write(channel_.Fd(), buf.data(), buf.size());
    LOG_INFO("写入数据");
    if (nwrote >= 0) {
    } else {
      nwrote = 0;
    }
  }
  if (static_cast<size_t>(nwrote) < buf.size()) {
    output_buffer_.WriteAndPush(buf.data() + nwrote, buf.size() - nwrote);
    if(!channel_.IsWriting()){
      channel_.EnableWrite();
    }
  }
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

EventLoop* Connection::GetOwner() {
  return loop_;
}

ssize_t Connection::Recv(void* buf, size_t len) {
  if (status_ != CONNECTED)
    return -1;
  return socket_.NonBlockRecv(buf, len);
}

Socket Connection::GetSocket() {
  return socket_;
}
}  // namespace Xianwei
