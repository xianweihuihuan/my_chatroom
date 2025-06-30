#include "Poller.h"

namespace Xianwei {

Poller::Poller() {
    epoll_fd_ = epoll_create(kMaxEpollEvents);
    if (epoll_fd_ < 0) {
        LOG_ERROR("创建 epoll 实例失败: {}", strerror(errno));
        abort();
    }
}

void Poller::UpdateEvent(Channel* channel) {
    if (!HasChannel(channel)) {
        channels_.insert({channel->Fd(), channel});
        Update(channel, EPOLL_CTL_ADD);
    } else {
        Update(channel, EPOLL_CTL_MOD);
    }
}

void Poller::RemoveEvent(Channel* channel) {
    int fd = channel->Fd();
    if (channels_.count(fd)) {
        channels_.erase(fd);
        Update(channel, EPOLL_CTL_DEL);
    }
}

void Poller::Poll(std::vector<Channel*>* active) {
    int nfds = epoll_wait(epoll_fd_, events_, kMaxEpollEvents, -1);
    if (nfds < 0) {
        if (errno == EINTR) return;
        LOG_ERROR("epoll_wait 出错: {}", strerror(errno));
        abort();
    }

    for (int i = 0; i < nfds; ++i) {
        int fd = events_[i].data.fd;
        auto it = channels_.find(fd);
        assert(it != channels_.end());

        Channel* channel = it->second;
        channel->SetREvents(events_[i].events);
        active->push_back(channel);
    }
}

void Poller::Update(Channel* channel, int operation) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.fd = channel->Fd();
    ev.events = channel->Events();

    int ret = epoll_ctl(epoll_fd_, operation, channel->Fd(), &ev);
    if (ret < 0) {
        LOG_ERROR("epoll_ctl 失败，操作类型 {}，fd = {}，错误: {}",
                  operation, channel->Fd(), strerror(errno));
    }
}

bool Poller::HasChannel(Channel* channel) const {
    return channels_.count(channel->Fd()) > 0;
}

}  // namespace net
