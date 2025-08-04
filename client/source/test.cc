#include "client.hpp"

// —— 在这里配置 ——
DEFINE_bool(run_mode, false, "程序的运行模式，false-调试；true-发布。");
DEFINE_string(log_file, "Xianwei", "发布模式下，日志的输出文件");
DEFINE_int32(log_level, 0, "发布模式下，日志的输出等级");

DEFINE_string(server_ip, "127.0.0.1", "服务器IP地址");
DEFINE_int32(server_port, 8080, "服务器的端口");
DEFINE_string(ca_path, "../../key/ca.crt", "ca证书所在位置");

DEFINE_string(file_ip, "127.0.0.1", "文件服务器IP地址");
DEFINE_int32(file_port, 8085, "文件服务器监听端口");
DEFINE_string(file_dir, "./file_data", "本地文件储存目录");

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  Xianwei::init_logger(FLAGS_run_mode, FLAGS_log_file, FLAGS_log_level);
  // 1. 初始化 OpenSSL
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  file_ip = FLAGS_server_ip;
  file_port = FLAGS_file_port;
  file_dir = FLAGS_file_dir;
  mkdir(file_dir.c_str(), 0775);
  if (file_dir.back() != '/') {
    file_dir += '/';
  }
  // 2. 创建 SSL_CTX 并加载 CA
  ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
  if (SSL_CTX_load_verify_locations(ctx, FLAGS_ca_path.c_str(), nullptr) != 1) {
    LOG_ERROR("加载CA证书失败");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return 1;
  }
  Xianwei::Socket so;
  so.CreateClient(FLAGS_server_port, FLAGS_server_ip);
  // 4. 绑定 SSL 并握手
  int buf_size = 1024 * 1024;  // 1MB
  if (setsockopt(so.Fd(), SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) <
      0)
    perror("setsockopt SO_SNDBUF failed");
  if (setsockopt(so.Fd(), SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) <
      0)
    perror("setsockopt SO_RCVBUF failed");
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, so.Fd());
  sockfd = so.Fd();
  if (SSL_connect(ssl) != 1) {
    LOG_ERROR("SSL连接失败");
    ERR_print_errors_fp(stderr);
    return 2;
  }
  vcodefd = eventfd(0, EFD_CLOEXEC);
  selfefd = eventfd(0, EFD_CLOEXEC);
  friendefd = eventfd(0, EFD_CLOEXEC);
  groupefd = eventfd(0, EFD_CLOEXEC);
  iflogin = false;
  signal(SIGINT, Xianwei::SingleRe);
  Xianwei::Heart();
  Xianwei::Print();
  std::cout << Yellow << "输入”start“以开始：";
  std::string ifstart;
  std::cout << Tail;
  while (true) {
    if (!std::getline(std::cin, ifstart)) {
      return 0;
    }
    if (ifstart == "start") {
      break;
    }
    std::cout << Red << "未知操作，请重新输入：" << Yellow;
    ifstart.clear();
    std::cin.clear();
    std::cout << Tail;
  }
  Xianwei::Start();
}
