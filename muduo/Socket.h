#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>
#include "logger.h"

namespace Xianwei {

constexpr int kDefaultBacklog = 128;

class Socket {
public:
    Socket();
    explicit Socket(int fd);
    ~Socket();

    int Fd() const;

    // 创建 TCP 套接字
    bool Create();

    // 绑定地址
    bool Bind(const std::string& ip, uint16_t port);

    // 开始监听
    bool Listen(int backlog = kDefaultBacklog);

    // 连接到服务器
    bool Connect(const std::string& ip, uint16_t port);

    // 获取新连接
    int Accept();

    // 阻塞接收数据
    ssize_t Recv(void* buf, size_t len, int flag = 0);

    // 非阻塞接收数据
    ssize_t NonBlockRecv(void* buf, size_t len);

    // 阻塞发送数据
    ssize_t Send(const void* buf, size_t len, int flag = 0);

    // 非阻塞发送数据
    ssize_t NonBlockSend(void* buf, size_t len);

    // 关闭套接字
    void Close();

    // 创建服务端 socket 并绑定、监听
    bool CreateServer(uint16_t port, const std::string& ip = "0.0.0.0", bool nonblock = false);

    // 创建客户端 socket 并连接服务器
    bool CreateClient(uint16_t port, const std::string& ip);

    // 设置地址复用选项
    void ReuseAddress();

    // 设置非阻塞
    void NonBlock();

private:
    int sockfd_;
};

}  // namespace net

