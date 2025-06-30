#pragma once

#include <sys/epoll.h>
#include <unordered_map>
#include <vector>
#include <cassert>
#include <cstring>
#include "logger.h"
#include "Channel.h"

namespace Xianwei {

constexpr int kMaxEpollEvents = 4096;

class Poller {
public:
    Poller();

    // 添加或更新事件监听
    void UpdateEvent(Channel* channel);

    // 移除事件监听
    void RemoveEvent(Channel* channel);

    // 执行 epoll 监控，将就绪的 Channel 写入 active 中
    void Poll(std::vector<Channel*>* active);

private:
    // 内部通用的 epoll_ctl 封装
    void Update(Channel* channel, int operation);

    // 判断某个 Channel 是否已添加
    bool HasChannel(Channel* channel) const;

    int epoll_fd_;                                        // epoll 文件描述符
    struct epoll_event events_[kMaxEpollEvents];          // 返回的就绪事件数组
    std::unordered_map<int, Channel*> channels_;          // fd -> Channel 映射表
};

}  // namespace net
