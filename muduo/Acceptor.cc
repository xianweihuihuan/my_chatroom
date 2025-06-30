#include "Acceptor.h"

namespace Xianwei {

Acceptor::Acceptor(EventLoop* loop, int port)
    : socket_(CreateServer(port)),
      loop_(loop),
      channel_(loop, socket_.Fd()) {
    channel_.SetReadCallback(std::bind(&Acceptor::HandleRead, this));
}

void Acceptor::SetAcceptCallback(const AcceptCallback& cb) {
    accept_callback_ = cb;
}

void Acceptor::Listen() {
    channel_.EnableRead();
}

int Acceptor::CreateServer(int port) {
    bool ret = socket_.CreateServer(port);
    assert(ret == true);
    return socket_.Fd();
}

void Acceptor::HandleRead() {
    int newfd = socket_.Accept();
    if (newfd < 0) {
        LOG_ERROR("Acceptor 获取新连接失败");
        return;
    }

    LOG_INFO("Acceptor 获取新连接，fd = {}", newfd);

    if (accept_callback_) {
        accept_callback_(newfd);
    }
}

}  // namespace net
