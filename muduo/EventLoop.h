#pragma once

#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <atomic>
#include <cassert>
#include <functional>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>
#include "Channel.h"
#include "Poller.h"
#include "data_redis.hpp"
#include "logger.h"
#include "message_cache.h"
#include "mysql_apply.hpp"
#include "mysql_chat_session.hpp"
#include "mysql_chat_session_member.hpp"
#include "mysql_file.hpp"
#include "mysql_message.hpp"
#include "mysql_relation.hpp"
#include "mysql_user.hpp"
#include "verification_code_send.h"

namespace Xianwei {
using TaskFunc = std::function<void()>;
using ReleaseFunc = std::function<void()>;

// 定时器任务对象类
class TimerTask {
 public:
  // 构造函数，设置任务 id、延迟时间、任务回调
  TimerTask(uint64_t id, uint32_t delay, const TaskFunc& cb);

  // 析构函数，若任务未取消则执行任务，随后调用释放回调
  ~TimerTask();

  // 取消当前任务
  void Cancel();

  // 设置释放任务时的回调（从 TimerWheel 移除）
  void SetRelease(const ReleaseFunc& cb);

  // 获取延迟时间
  uint32_t DelayTime();

 private:
  uint64_t id_;          // 任务唯一 ID
  uint32_t timeout_;     // 延迟时间（秒）
  bool canceled_;        // 是否已取消
  TaskFunc task_cb_;     // 要执行的任务
  ReleaseFunc release_;  // 释放回调
};

// 定时器轮结构：使用时间轮算法实现定时任务管理
class TimerWheel {
 public:
  explicit TimerWheel(EventLoop* loop);

  // 添加一个定时任务（线程安全，内部转发到 EventLoop）
  void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc& cb);

  // 刷新任务位置，相当于延迟执行
  void TimerRefresh(uint64_t id);

  // 取消定时任务
  void TimerCancel(uint64_t id);

  // 判断是否存在指定 ID 的任务（仅模块内部使用）
  bool HasTimer(uint64_t id);

 private:
  using WeakTask = std::weak_ptr<TimerTask>;
  using PtrTask = std::shared_ptr<TimerTask>;

  // 从任务表中移除指定任务 ID
  void RemoveTimer(uint64_t id);

  // 创建 timerfd
  static int CreateTimerfd();

  // 读取 timerfd 中的次数
  int ReadTimefd();

  // 秒针推进一格并清空对应格的任务
  void RunTimerTask();

  // 超时事件触发时执行
  void OnTime();

  // 以下为只允许在 EventLoop 线程中调用的接口
  void TimerAddInLoop(uint64_t id, uint32_t delay, const TaskFunc& cb);
  void TimerRefreshInLoop(uint64_t id);
  void TimerCancelInLoop(uint64_t id);

 private:
  int tick_;                                 // 当前秒针位置
  int capacity_;                             // 表盘大小
  std::vector<std::vector<PtrTask>> wheel_;  // 时间轮

  std::unordered_map<uint64_t, WeakTask> timers_;  // 全部任务的 ID 映射表
  EventLoop* loop_;                                // 所属事件循环线程
  int timerfd_;                                    // 定时器描述符
  std::unique_ptr<Channel> timer_channel_;         // 定时器 channel
};
class EventLoop {
 public:
  using Functor = std::function<void()>;

  EventLoop();

  EventLoop(const std::string& mysql_user,
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
            const std::string& key);

  // 启动事件循环（Reactor 主循环）
  void Start();

  void Stop();

  // 执行任务池中所有待执行任务（用户投递的）
  void RunAllTasks();

  // 将任务立即在当前线程中执行（如果是本线程），否则投递任务
  void RunInLoop(const Functor& task);

  // 始终将任务加入任务队列，在适当时机被执行
  void QueueInLoop(const Functor& task);

  // 判断当前线程是否为创建 EventLoop 的线程
  bool IsInLoopThread() const;

  // 断言：必须在事件循环线程中调用（否则触发断言失败）
  void AssertInLoopThread() const;

  // 修改或添加某个 channel 的事件监听
  void UpdateEvent(Channel* channel);

  // 移除某个 channel 的事件监听
  void RemoveEvent(Channel* channel);

  // 添加定时任务
  void TimerAdd(uint64_t id, uint32_t delay, const TaskFunc& cb);

  // 刷新定时任务的过期时间
  void TimerRefresh(uint64_t id);

  // 取消定时任务
  void TimerCancel(uint64_t id);

  // 判断某个定时器是否存在
  bool HasTimer(uint64_t id);

  UserTable::ptr GetUserTable() { return user_table_; }
  MessageTable::ptr GetMessageTable() { return message_table_; }
  RelationTable::ptr GetRelationTable() { return relation_table_; }
  FriendApplyTable::ptr GetFriendApplyTable() { return friendapply_table_; }
  ChatSessionMemberTable::ptr GetChatSessionMemberTable() { return csm_table_; }
  ChatSessionTable::ptr GetChatSessionTable() { return css_table_; }
  FileTable::ptr GetFileTable() { return file_table_; }
  SessionApplyTable::ptr GetSessionApplyTable() { return session_table_; }

  Status::ptr GetStatus() { return redis_status_; }
  Codes::ptr GetCodes() { return redis_codes_; }
  OfflineMessage::ptr GetOfflineMessage() { return redis_message_; }
  OfflineApply::ptr GetOfflineApply() { return redis_apply_; }

  VerificationCodeSend::ptr GetVerClient() { return ver_client_; }
  void WakeUpEventFd();

 private:
  // 创建 eventfd，用于跨线程唤醒 epoll
  int CreateEventFd();

  // 读取 eventfd 中的通知数据（用于清除事件）
  void HandleReadEventfd();

  // 向 eventfd 写入数据（唤醒阻塞中的 epoll）

  std::thread::id thread_id_;               // 创建该 EventLoop 的线程 ID
  int event_fd_;                            // eventfd，用于跨线程唤醒
  std::unique_ptr<Channel> event_channel_;  // 封装 eventfd 的 Channel
  Poller poller_;                           // epoll 封装器
  std::vector<Functor> task_queue_;         // 任务队列（线程安全）
  std::mutex mutex_;                        // 保护任务队列的互斥锁
  TimerWheel timer_wheel_;                  // 定时器容器
  std::atomic<bool> quit_;

  std::shared_ptr<odb::core::database> mysql_client_;
  std::shared_ptr<sw::redis::Redis> redis_client_;
  std::shared_ptr<VerificationCodeSend> ver_client_;

  UserTable::ptr user_table_;
  MessageTable::ptr message_table_;
  FriendApplyTable::ptr friendapply_table_;
  RelationTable::ptr relation_table_;
  ChatSessionMemberTable::ptr csm_table_;
  ChatSessionTable::ptr css_table_;
  FileTable::ptr file_table_;
  SessionApplyTable::ptr session_table_;

  Status::ptr redis_status_;
  Codes::ptr redis_codes_;
  OfflineMessage::ptr redis_message_;
  OfflineApply::ptr redis_apply_;


};

}  // namespace Xianwei
