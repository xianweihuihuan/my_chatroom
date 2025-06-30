#pragma once

#include <functional>
#include <sys/epoll.h>
#include "logger.h"

namespace Xianwei {

class EventLoop;

class Channel {
public:
    using EventCallback = std::function<void()>;

    // 构造函数
    Channel(EventLoop* loop, int fd);

    // 获取绑定的文件描述符
    int Fd() const;

    // 获取当前监听的事件（读/写等）
    uint32_t Events() const;

    // 设置实际触发的事件（由 epoll 设置）
    void SetREvents(uint32_t events);

    EventLoop* GetOwner() { return loop_; }

    // 设置回调函数
    void SetReadCallback(const EventCallback& cb);
    void SetWriteCallback(const EventCallback& cb);
    void SetErrorCallback(const EventCallback& cb);
    void SetCloseCallback(const EventCallback& cb);
    void SetEventCallback(const EventCallback& cb);

    // 启用/禁用事件监听
    void EnableRead();
    void EnableWrite();
    void DisableRead();
    void DisableWrite();
    void DisableAll();

    // 判断当前监听状态
    bool IsReading() const;
    bool IsWriting() const;

    // 从 epoll 中移除
    void Remove();

    // 通知 EventLoop 修改事件监听
    void Update();

    // 当 fd 上有事件发生时，执行回调处理
    void HandleEvent();

private:
    int fd_;                         // 文件描述符
    EventLoop* loop_;                // 所属的事件循环
    uint32_t events_;               // 当前监听的事件
    uint32_t revents_;              // 实际触发的事件

    EventCallback read_callback_;   // 可读回调
    EventCallback write_callback_;  // 可写回调
    EventCallback error_callback_;  // 错误回调
    EventCallback close_callback_;  // 关闭回调
    EventCallback event_callback_;  // 任意事件回调
};

}  // namespace net
