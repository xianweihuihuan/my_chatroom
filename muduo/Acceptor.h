#pragma once

#include <functional>
#include <cassert>
#include "Socket.h"
#include "Channel.h"
#include "EventLoop.h"
#include "logger.h"

namespace Xianwei {

class Acceptor {
public:
    using AcceptCallback = std::function<void(int)>;

    // 构造 Acceptor，并初始化监听套接字、注册读事件回调
    Acceptor(EventLoop* loop, int port);

    // 设置当有新连接时的回调函数
    void SetAcceptCallback(const AcceptCallback& cb);

    // 开始监听套接字的读事件（不能在构造中做）
    void Listen();

private:
    // 监听套接字的读事件回调处理函数
    void HandleRead();

    // 创建服务端监听 socket，并返回 fd
    int CreateServer(int port);

    Socket socket_;         // 监听 socket 封装
    EventLoop* loop_;       // 所属事件循环
    Channel channel_;       // 套接字对应的事件通道
    AcceptCallback accept_callback_;  // 接收连接的回调处理器
};

}  // namespace net

