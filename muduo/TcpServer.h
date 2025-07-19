#pragma once

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <functional>
#include <unordered_map>
#include "Acceptor.h"
#include "Buffer.h"
#include "Connection.h"
#include "EventLoop.h"
#include "LoopThreadPool.h"

namespace Xianwei {

class TcpServer {
 public:
  using PtrConnection = std::shared_ptr<Connection>;
  using ConnectedCallback = std::function<void(const PtrConnection&)>;
  using MessageCallback = std::function<void(const PtrConnection&, Buffer*)>;
  using ClosedCallback = std::function<void(const PtrConnection&)>;
  using AnyEventCallback = std::function<void(const PtrConnection&)>;
  using Functor = std::function<void()>;

  // explicit TcpServer(int port,const std::string& scrt,const std::string&
  // skey);

  explicit TcpServer(int port,
                     bool enable_ssl,
                     const std::string& scrt,
                     const std::string& skey,
                     const std::string& ca);

  // 设置线程池线程数量
  void SetThreadCount(int count);

  // 设置连接建立后的回调
  void SetConnectedCallback(const ConnectedCallback& cb);

  // 设置消息接收回调
  void SetMessageCallback(const MessageCallback& cb);

  // 设置连接关闭回调
  void SetClosedCallback(const ClosedCallback& cb);

  // 设置任意事件回调
  void SetAnyEventCallback(const AnyEventCallback& cb);

  // 启用非活跃连接超时销毁机制
  void EnableInactiveRelease(int timeout);

  // 向事件循环注册延迟任务
  void RunAfter(const Functor& task, int delay);

  // 启动服务器主循环与线程池
  void Start();

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

 private:
  // 在事件循环中延迟执行任务
  void RunAfterInLoop(const Functor& task, int delay);

  // 新连接建立回调：创建 Connection 对象
  void NewConnection(int fd);

  // 在主循环中移除连接
  void RemoveConnectionInLoop(const PtrConnection& conn);

  // 线程安全移除连接（调度到主循环）
  void RemoveConnection(const PtrConnection& conn);

  void ScheduleFlush(Functor& task, int delay);

  uint64_t next_id_;
  int port_;
  int timeout_;
  bool enable_inactive_release_;

  EventLoop base_loop_;
  SSL_CTX* ssl_ctx_;
  Acceptor acceptor_;
  LoopThreadPool pool_;
  std::unordered_map<uint64_t, PtrConnection> connections_;

  ConnectedCallback connected_callback_;
  MessageCallback message_callback_;
  ClosedCallback closed_callback_;
  AnyEventCallback event_callback_;

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

  bool enable_ssl_;
  // const std::string& host,
  //                                                 int port,
  //                                                 int db,
  //                                                 bool keep_alive
};

}  // namespace Xianwei
