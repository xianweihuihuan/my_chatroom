#include "LoopThreadPool.h"
#include "logger.h"

namespace Xianwei {

LoopThread::LoopThread()
    : loop_(nullptr), thread_(&LoopThread::ThreadEntry, this) {}

void LoopThread::ThreadEntry() {
  EventLoop loop(mysql_user_, mysql_pswd_, mysql_host_, mysql_db_, mysql_cset_,
                 mysql_port_, mysql_conn_pool_count_, redis_host_, redis_port_,
                 redis_db_, redis_keep_alive_, ver_user_, ver_key_);
  {
    std::unique_lock<std::mutex> lock(mutex_);
    loop_ = &loop;
    cond_.notify_all();
  }
  loop.Start();
}

EventLoop* LoopThread::GetLoop() {
  std::unique_lock<std::mutex> lock(mutex_);
  cond_.wait(lock, [&]() { return loop_ != nullptr; });
  return loop_;
}

LoopThreadPool::LoopThreadPool(EventLoop* base_loop)
    : thread_count_(0), next_index_(0), base_loop_(base_loop) {}

void LoopThreadPool::SetThreadCount(int count) {
  thread_count_ = count;
}

void LoopThreadPool::Create() {
  if (thread_count_ > 0) {
    threads_.resize(thread_count_);
    loops_.resize(thread_count_);
    for (int i = 0; i < thread_count_; ++i) {
      threads_[i] = new LoopThread(
          mysql_user_, mysql_pswd_, mysql_host_, mysql_db_, mysql_cset_,
          mysql_port_, mysql_conn_pool_count_, redis_host_, redis_port_,redis_db_,redis_keep_alive_,ver_user_,ver_key_);
      loops_[i] = threads_[i]->GetLoop();
    }
  }
}

EventLoop* LoopThreadPool::NextLoop() {
  if (thread_count_ == 0) {
    return base_loop_;
  }
  next_index_ = (next_index_ + 1) % thread_count_;
  return loops_[next_index_];
}

LoopThread::LoopThread(const std::string& mysql_user,
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
    : mysql_user_(mysql_user),
      mysql_pswd_(mysql_pswd),
      mysql_host_(mysql_host),
      mysql_db_(mysql_db),
      mysql_cset_(mysql_cset),
      mysql_port_(mysql_port),
      mysql_conn_pool_count_(mysql_conn_pool_count),
      redis_host_(redis_host),
      redis_port_(redis_port),
      redis_db_(redis_db),
      redis_keep_alive_(redis_keep_alive),
      ver_user_(username),
      ver_key_(key),
      loop_(nullptr),
      thread_(&LoopThread::ThreadEntry, this) {}

void LoopThreadPool::SetMysqlMessage(std::string user,
                                     const std::string& pswd,
                                     const std::string& host,
                                     const std::string& db,
                                     const std::string& cset,
                                     int port,
                                     int conn_pool_count) {
  mysql_user_ = user;
  mysql_pswd_ = pswd;
  mysql_host_ = host;
  mysql_db_ = db;
  mysql_cset_ = cset;
  mysql_port_ = port;
  mysql_conn_pool_count_ = conn_pool_count;
}

void LoopThreadPool::SetRedisMessage(const std::string& host,
                                     int port,
                                     int db,
                                     bool keep_alive) {
  redis_host_ = host;
  redis_port_ = port;
  redis_db_ = db;
  redis_keep_alive_ = keep_alive;
}

void LoopThreadPool::SetVerMessage(const std::string& username, const std::string& key){
  ver_user_ = username;
  ver_key_ = key;
}
}  // namespace Xianwei
