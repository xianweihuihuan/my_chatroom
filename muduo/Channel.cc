#include "Channel.h"
#include "EventLoop.h"

namespace Xianwei {

Channel::Channel(EventLoop* loop, int fd)
    : fd_(fd), loop_(loop), events_(0), revents_(0) {}

int Channel::Fd() const {
    return fd_;
}

uint32_t Channel::Events() const {
    return events_;
}

void Channel::SetREvents(uint32_t events) {
    revents_ = events;
}

void Channel::SetReadCallback(const EventCallback& cb) {
    read_callback_ = cb;
}

void Channel::SetWriteCallback(const EventCallback& cb) {
    write_callback_ = cb;
}

void Channel::SetErrorCallback(const EventCallback& cb) {
    error_callback_ = cb;
}

void Channel::SetCloseCallback(const EventCallback& cb) {
    close_callback_ = cb;
}

void Channel::SetEventCallback(const EventCallback& cb) {
    event_callback_ = cb;
}

void Channel::EnableRead() {
    events_ |= EPOLLIN;
    Update();
}

void Channel::EnableWrite() {
    events_ |= EPOLLOUT;
    Update();
}

void Channel::DisableRead() {
    events_ &= ~EPOLLIN;
    Update();
}

void Channel::DisableWrite() {
    events_ &= ~EPOLLOUT;
    Update();
}

void Channel::DisableAll() {
    events_ = 0;
    Update();
}

bool Channel::IsReading() const {
    return events_ & EPOLLIN;
}

bool Channel::IsWriting() const {
    return events_ & EPOLLOUT;
}

void Channel::Update() {
    loop_->UpdateEvent(this);
}

void Channel::Remove() {
    loop_->RemoveEvent(this);
}

void Channel::HandleEvent() {
    if ((revents_ & EPOLLIN) || (revents_ & EPOLLRDHUP) || (revents_ & EPOLLPRI)) {
        if (read_callback_) read_callback_();
    }

    if (revents_ & EPOLLOUT) {
        if (write_callback_) write_callback_();
    } else if (revents_ & EPOLLERR) {
        if (error_callback_) error_callback_();
    } else if (revents_ & EPOLLHUP) {
        if (close_callback_) close_callback_();
    }

    if (event_callback_) event_callback_();
}

}  // namespace net
