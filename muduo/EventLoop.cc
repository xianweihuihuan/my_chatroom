#include "EventLoop.h"

namespace Xianwei {
TimerTask::TimerTask(uint64_t id, uint32_t delay, const TaskFunc& cb)
    : id_(id), timeout_(delay), canceled_(false), task_cb_(cb) {}

TimerTask::~TimerTask() {
  if (!canceled_)
    task_cb_();
  if (release_)
    release_();
}

void TimerTask::Cancel() {
  canceled_ = true;
}

void TimerTask::SetRelease(const ReleaseFunc& cb) {
  release_ = cb;
}

uint32_t TimerTask::DelayTime() {
  return timeout_;
}

// ----------------- TimerWheel 实现 -----------------

TimerWheel::TimerWheel(EventLoop* loop)
    : tick_(0),
      capacity_(600),
      wheel_(capacity_),
      loop_(loop),
      timerfd_(CreateTimerfd()),
      timer_channel_(new Channel(loop, timerfd_)) {
  timer_channel_->SetReadCallback(std::bind(&TimerWheel::OnTime, this));
  timer_channel_->EnableRead();  // 启动定时器可读事件监控
}

int TimerWheel::CreateTimerfd() {
  int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
  if (timerfd < 0) {
    LOG_ERROR("创建timefd失败");
    abort();
  }

  struct itimerspec itime;
  itime.it_value.tv_sec = 1;
  itime.it_value.tv_nsec = 0;
  itime.it_interval.tv_sec = 1;
  itime.it_interval.tv_nsec = 0;

  timerfd_settime(timerfd, 0, &itime, nullptr);
  return timerfd;
}

int TimerWheel::ReadTimefd() {
  uint64_t times;
  int ret = read(timerfd_, &times, sizeof(times));
  if (ret < 0) {
    LOG_ERROR("读取timefd失败");
    abort();
  }
  return static_cast<int>(times);
}

void TimerWheel::RunTimerTask() {
  tick_ = (tick_ + 1) % capacity_;
  wheel_[tick_].clear();  // 清空指定位置，释放所有任务
}

void TimerWheel::OnTime() {
  int times = ReadTimefd();
  for (int i = 0; i < times; ++i) {
    RunTimerTask();
  }
}

void TimerWheel::RemoveTimer(uint64_t id) {
  timers_.erase(id);
}

void TimerWheel::TimerAdd(uint64_t id, uint32_t delay, const TaskFunc& cb) {
  loop_->RunInLoop(std::bind(&TimerWheel::TimerAddInLoop, this, id, delay, cb));
}

void TimerWheel::TimerAddInLoop(uint64_t id,
                                uint32_t delay,
                                const TaskFunc& cb) {
  PtrTask pt(new TimerTask(id, delay, cb));
  pt->SetRelease(std::bind(&TimerWheel::RemoveTimer, this, id));
  int pos = (tick_ + delay) % capacity_;
  wheel_[pos].push_back(pt);
  timers_[id] = WeakTask(pt);
}

void TimerWheel::TimerRefresh(uint64_t id) {
  loop_->RunInLoop(std::bind(&TimerWheel::TimerRefreshInLoop, this, id));
}

void TimerWheel::TimerRefreshInLoop(uint64_t id) {
  auto it = timers_.find(id);
  if (it == timers_.end())
    return;
  PtrTask pt = it->second.lock();
  if (!pt)
    return;
  int delay = pt->DelayTime();
  int pos = (tick_ + delay) % capacity_;
  wheel_[pos].push_back(pt);
}

void TimerWheel::TimerCancel(uint64_t id) {
  loop_->RunInLoop(std::bind(&TimerWheel::TimerCancelInLoop, this, id));
}

void TimerWheel::TimerCancelInLoop(uint64_t id) {
  auto it = timers_.find(id);
  if (it == timers_.end())
    return;
  PtrTask pt = it->second.lock();
  if (pt)
    pt->Cancel();
}

bool TimerWheel::HasTimer(uint64_t id) {
  return timers_.find(id) != timers_.end();
}

EventLoop::EventLoop()
    : thread_id_(std::this_thread::get_id()),
      event_fd_(CreateEventFd()),
      quit_(false),
      event_channel_(new Channel(this, event_fd_)),
      timer_wheel_(this) {
  event_channel_->SetReadCallback(
      std::bind(&EventLoop::HandleReadEventfd, this));
  event_channel_->EnableRead();
  LOG_INFO("EventLoop 创建成功，线程 ID = {}",
           std::hash<std::thread::id>{}(thread_id_));
}

void EventLoop::Start() {
  LOG_INFO("事件循环开始...");
  quit_ = false;
  while (!quit_) {
    std::vector<Channel*> active_channels;
    poller_.Poll(&active_channels);
    for (auto& channel : active_channels) {
      channel->HandleEvent();
    }
    RunAllTasks();
  }
}

void EventLoop::Stop() {
  quit_ = true;
  WakeUpEventFd();
}

void EventLoop::RunAllTasks() {
  std::vector<Functor> functors;
  {
    std::unique_lock<std::mutex> lock(mutex_);
    task_queue_.swap(functors);
  }
  for (auto& task : functors) {
    task();
  }
}

void EventLoop::RunInLoop(const Functor& task) {
  if (IsInLoopThread()) {
    task();
  } else {
    QueueInLoop(task);
  }
}

void EventLoop::QueueInLoop(const Functor& task) {
  {
    std::unique_lock<std::mutex> lock(mutex_);
    task_queue_.push_back(task);
  }
  WakeUpEventFd();
}

bool EventLoop::IsInLoopThread() const {
  return thread_id_ == std::this_thread::get_id();
}

void EventLoop::AssertInLoopThread() const {
  assert(IsInLoopThread());
}

int EventLoop::CreateEventFd() {
  int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (fd < 0) {
    LOG_ERROR("创建 eventfd 失败: {}", strerror(errno));
    abort();
  }
  return fd;
}

void EventLoop::HandleReadEventfd() {
  uint64_t one = 0;
  ssize_t n = read(event_fd_, &one, sizeof one);
  if (n != sizeof(one)) {
    LOG_ERROR("读取 eventfd 失败，应读 {} 字节，实际读了 {}", sizeof(one), n);
  }
}

void EventLoop::WakeUpEventFd() {
  uint64_t one = 1;
  ssize_t n = write(event_fd_, &one, sizeof one);
  if (n != sizeof(one)) {
    LOG_ERROR("写入 eventfd 失败，应写 {} 字节，实际写了 {}", sizeof(one), n);
  }
}

void EventLoop::UpdateEvent(Channel* channel) {
  poller_.UpdateEvent(channel);
}

void EventLoop::RemoveEvent(Channel* channel) {
  poller_.RemoveEvent(channel);
}

void EventLoop::TimerAdd(uint64_t id, uint32_t delay, const TaskFunc& cb) {
  timer_wheel_.TimerAdd(id, delay, cb);
}

void EventLoop::TimerRefresh(uint64_t id) {
  timer_wheel_.TimerRefresh(id);
}

void EventLoop::TimerCancel(uint64_t id) {
  timer_wheel_.TimerCancel(id);
}

bool EventLoop::HasTimer(uint64_t id) {
  return timer_wheel_.HasTimer(id);
}

EventLoop::EventLoop(const std::string& mysql_user,
                     const std::string& mysql_pswd,
                     const std::string& mysql_host,
                     const std::string& mysql_db,
                     const std::string& mysql_cset,
                     int mysql_port,
                     int mysql_conn_pool_count,
                     const std::string& redis_host,
                     int redis_port,
                     int redis_db,
                     bool redis_keep_alive,
                     const std::string& username,
                     const std::string& key)
    : thread_id_(std::this_thread::get_id()),
      event_fd_(CreateEventFd()),
      quit_(false),
      event_channel_(new Channel(this, event_fd_)),
      timer_wheel_(this),
      mysql_client_(ODBFactory::Create(mysql_user,
                                       mysql_pswd,
                                       mysql_host,
                                       mysql_db,
                                       mysql_cset,
                                       mysql_port,
                                       mysql_conn_pool_count)),
      redis_client_(RedisClientFactory::Create(redis_host,
                                               redis_port,
                                               redis_db,
                                               redis_keep_alive)),
      ver_client_(std::make_shared<VerificationCodeSend>(username, key)),
      user_table_(std::make_shared<UserTable>(mysql_client_)),
      message_table_(std::make_shared<MessageTable>(mysql_client_)),
      relation_table_(std::make_shared<RelationTable>(mysql_client_)),
      friendapply_table_(std::make_shared<FriendApplyTable>(mysql_client_)),
      csm_table_(std::make_shared<ChatSessionMemberTable>(mysql_client_)),
      css_table_(std::make_shared<ChatSessionTable>(mysql_client_)),
      file_table_(std::make_shared<FileTable>(mysql_client_)),
      session_table_(std::make_shared<SessionApplyTable>(mysql_client_)),
      redis_codes_(std::make_shared<Codes>(redis_client_)),
      redis_status_(std::make_shared<Status>(redis_client_)),
      redis_message_(std::make_shared<OfflineMessage>(redis_client_)),
      redis_apply_(std::make_shared<OfflineApply>(redis_client_)) {}

}  // namespace Xianwei
