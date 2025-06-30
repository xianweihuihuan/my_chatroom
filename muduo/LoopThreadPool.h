#pragma once

#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>
#include "EventLoop.h"

namespace Xianwei {

class LoopThread {
 private:
  std::string mysql_user_;
  std::string mysql_pswd_;
  std::string mysql_host_;
  std::string mysql_db_;
  std::string mysql_cset_;
  int mysql_port_;
  int mysql_conn_pool_count_;

  std::string redis_host_;
  int redis_port_;
  int redis_db_;
  bool redis_keep_alive_;

  std::string ver_user_;
  std::string ver_key_;
  std::mutex mutex_;              // 互斥锁
  std::condition_variable cond_;  // 条件变量
  EventLoop* loop_;               // EventLoop对象指针

  std::thread thread_;  // 执行EventLoop的线程
 private:
  // 线程函数，创建EventLoop并启动循环
  void ThreadEntry();

 public:
  LoopThread();
  LoopThread(const std::string& mysql_user,
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

  EventLoop* GetLoop();  // 获取线程对应的EventLoop指针
};

class LoopThreadPool {
 private:
  int thread_count_;                  // 线程数量
  int next_index_;                    // 用于轮询调度的下标
  EventLoop* base_loop_;              // 主线程的EventLoop
  std::vector<LoopThread*> threads_;  // LoopThread对象列表
  std::vector<EventLoop*> loops_;     // 所有线程的EventLoop指针列表

  std::string mysql_user_;
  std::string mysql_pswd_;
  std::string mysql_host_;
  std::string mysql_db_;
  std::string mysql_cset_;
  int mysql_port_;
  int mysql_conn_pool_count_;

  std::string redis_host_;
  int redis_port_;
  int redis_db_;
  bool redis_keep_alive_;

  std::string ver_user_;
  std::string ver_key_;

 public:
  explicit LoopThreadPool(EventLoop* base_loop);
  void SetThreadCount(int count);  // 设置线程数量
  void Create();                   // 创建所有子线程及其EventLoop
  EventLoop* NextLoop();           // 获取下一个可用EventLoop


  void SetMysqlMessage(std::string user,
                       const std::string& pswd,
                       const std::string& host,
                       const std::string& db,
                       const std::string& cset,
                       int port,
                       int conn_pool_count);

  void SetRedisMessage(const std::string& host,
                       int port,
                       int db,
                       bool keep_alive);

  void SetVerMessage(const std::string& username, const std::string& key);
};

}  // namespace Xianwei
