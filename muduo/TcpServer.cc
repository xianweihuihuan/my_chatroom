#include "TcpServer.h"
#include "logger.h"

namespace Xianwei {

// TcpServer::TcpServer(int port, const std::string& scrt, const std::string&
// skey)
//     : port_(port),
//       next_id_(0),
//       enable_inactive_release_(false),
//       acceptor_(&base_loop_, port),
//       pool_(&base_loop_),
//       ssl_ctx_(nullptr) {
//   SSL_library_init();
//   OpenSSL_add_all_algorithms();
//   SSL_load_error_strings();

//   ssl_ctx_ = SSL_CTX_new(TLS_server_method());
//   // SSL_CTX_use_certificate_file(ssl_ctx_, "../../key/server.crt",
//   // SSL_FILETYPE_PEM); SSL_CTX_use_PrivateKey_file(ssl_ctx_,
//   // "../../key/server.key", SSL_FILETYPE_PEM);
//   if (!ssl_ctx_) {
//     LOG_ERROR("SSL_CTX_new failed");
//     ERR_print_errors_fp(stderr);
//     abort();
//   }
//   // 加载证书
//   if (SSL_CTX_use_certificate_file(ssl_ctx_, scrt.c_str(), SSL_FILETYPE_PEM)
//   !=
//       1) {
//     LOG_ERROR("加载证书失败");
//     ERR_print_errors_fp(stderr);
//     SSL_CTX_free(ssl_ctx_);
//     abort();
//   }
//   // 加载私钥
//   if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, skey.c_str(), SSL_FILETYPE_PEM)
//   !=
//       1) {
//     LOG_ERROR("加载私钥失败");
//     ERR_print_errors_fp(stderr);
//     SSL_CTX_free(ssl_ctx_);
//     abort();
//   }
//   // 校验证书与私钥匹配
//   if (SSL_CTX_check_private_key(ssl_ctx_) != 1) {
//     LOG_ERROR("证书与私钥不匹配");
//     ERR_print_errors_fp(stderr);
//     SSL_CTX_free(ssl_ctx_);
//     abort();
//   }
//   SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);
//   if (SSL_CTX_load_verify_locations(ssl_ctx_, "../../key/ca.crt", nullptr) !=
//       1) {
//     LOG_ERROR("加载 CA 失败，用于客户端证书校验");
//     ERR_print_errors_fp(stderr);
//     SSL_CTX_free(ssl_ctx_);
//     abort();
//   }
//   LOG_DEBUG("SSL加载完毕");

//   acceptor_.SetAcceptCallback(
//       std::bind(&TcpServer::NewConnection, this, std::placeholders::_1));
//   acceptor_.Listen();
// }

TcpServer::TcpServer(int port,
                     bool enable_ssl,
                     const std::string& scrt,
                     const std::string& skey)
    : port_(port),
      next_id_(0),
      enable_inactive_release_(false),
      acceptor_(&base_loop_, port),
      pool_(&base_loop_),
      ssl_ctx_(nullptr),
      enable_ssl_(enable_ssl) {
  if (enable_ssl_) {
    // 初始化SSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    // 创建SSL
    ssl_ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx_) {
      LOG_ERROR("SSL_CTX_new failed");
      ERR_print_errors_fp(stderr);
      abort();
    }
    // 加载证书
    if (SSL_CTX_use_certificate_file(ssl_ctx_, scrt.c_str(),
                                     SSL_FILETYPE_PEM) != 1) {
      LOG_ERROR("加载证书失败");
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(ssl_ctx_);
      abort();
    }
    // 加载私钥
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, skey.c_str(), SSL_FILETYPE_PEM) !=
        1) {
      LOG_ERROR("加载私钥失败");
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(ssl_ctx_);
      abort();
    }
    // 校验证书与私钥匹配
    if (SSL_CTX_check_private_key(ssl_ctx_) != 1) {
      LOG_ERROR("证书与私钥不匹配");
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(ssl_ctx_);
      abort();
    }
    SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_load_verify_locations(ssl_ctx_, "../../key/ca.crt", nullptr) !=
        1) {
      LOG_ERROR("加载 CA 失败，用于客户端证书校验");
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(ssl_ctx_);
      abort();
    }
    LOG_DEBUG("SSL加载完毕");
  }
  //接收FD设置回调函数
  acceptor_.SetAcceptCallback(
      std::bind(&TcpServer::NewConnection, this, std::placeholders::_1));
  acceptor_.Listen();
}

void TcpServer::SetThreadCount(int count) {
  pool_.SetThreadCount(count);
}

void TcpServer::SetConnectedCallback(const ConnectedCallback& cb) {
  connected_callback_ = cb;
}

void TcpServer::SetMessageCallback(const MessageCallback& cb) {
  message_callback_ = cb;
}

void TcpServer::SetClosedCallback(const ClosedCallback& cb) {
  closed_callback_ = cb;
}

void TcpServer::SetAnyEventCallback(const AnyEventCallback& cb) {
  event_callback_ = cb;
}

void TcpServer::EnableInactiveRelease(int timeout) {
  timeout_ = timeout;
  enable_inactive_release_ = true;
}

void TcpServer::RunAfter(const Functor& task, int delay) {
  base_loop_.RunInLoop(
      std::bind(&TcpServer::RunAfterInLoop, this, task, delay));
}

void TcpServer::RunAfterInLoop(const Functor& task, int delay) {
  next_id_++;
  base_loop_.TimerAdd(next_id_, delay, task);
}

void TcpServer::NewConnection(int fd) {
  next_id_++;
  PtrConnection conn = std::make_shared<Connection>(pool_.NextLoop(), next_id_,
                                                    fd, ssl_ctx_, enable_ssl_);
  conn->SetMessageCallback(message_callback_);
  conn->SetClosedCallback(closed_callback_);
  conn->SetConnectedCallback(connected_callback_);
  conn->SetAnyEventCallback(event_callback_);
  conn->SetSrvClosedCallback(
      std::bind(&TcpServer::RemoveConnection, this, std::placeholders::_1));
  if (enable_inactive_release_) {
    conn->EnableInactiveRelease(timeout_);
  }
  conn->Established();
  connections_[next_id_] = conn;
}

void TcpServer::RemoveConnection(const PtrConnection& conn) {
  base_loop_.RunInLoop(
      std::bind(&TcpServer::RemoveConnectionInLoop, this, conn));
}

void TcpServer::RemoveConnectionInLoop(const PtrConnection& conn) {
  int id = conn->Id();
  auto it = connections_.find(id);
  if (it != connections_.end()) {
    connections_.erase(it);
  }
}

void TcpServer::Start() {
  pool_.Create();
  base_loop_.Start();
}

void TcpServer::SetMysqlMessage(std::string user,
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
  pool_.SetMysqlMessage(mysql_user_, mysql_pswd_, mysql_host_, mysql_db_,
                        mysql_cset_, mysql_port_, mysql_conn_pool_count_);
}

void TcpServer::SetRedisMessage(const std::string& host,
                                int port,
                                int db,
                                bool keep_alive) {
  redis_host_ = host;
  redis_port_ = port;
  redis_db_ = db;
  redis_keep_alive_ = keep_alive;
  pool_.SetRedisMessage(redis_host_, redis_port_, redis_db_, redis_keep_alive_);
}

void TcpServer::SetVerMessage(const std::string& username,
                              const std::string& key) {
  ver_user_ = username;
  ver_key_ = key;
  pool_.SetVerMessage(ver_user_, ver_key_);
}
}  // namespace Xianwei
