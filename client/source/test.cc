#include "client.hpp"



// —— 在这里配置 ——

DEFINE_string(server_ip, "127.0.0.1", "服务器IP地址");
DEFINE_string(server_port, "8080", "服务器的端口");
DEFINE_string(ca_path, "../../key/ca.crt", "ca证书所在位置");




void Recv() {
}

int main(int argc,char*argv[]) {
  Xianwei::init_logger(false, "", 0);
  google::ParseCommandLineFlags(&argc, &argv, true);
  // 1. 初始化 OpenSSL
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  
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
  so.CreateClient(8080, "127.0.0.1");
  // 4. 绑定 SSL 并握手
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, so.Fd());
  if (SSL_connect(ssl) != 1) {
    LOG_ERROR("SSL连接失败");
    ERR_print_errors_fp(stderr);
    return 2;
  }
  vcodefd = eventfd(0, EFD_CLOEXEC);
  selfefd = eventfd(0, EFD_CLOEXEC);
  friendefd = eventfd(0, EFD_CLOEXEC);
  Xianwei::Print();
  std::cout << Yellow << "输入”start“以开始：";
  std::string ifstart;
  std::cin.clear();
  std::cin >> ifstart;
  std::cout << Tail;
  while (ifstart != "start") {
    std::cout <<Red<<"未知操作，请重新输入：" <<Yellow;
    ifstart.clear();
    std::cin.clear();
    std::cin >> ifstart;
    std::cout << Tail;
  }
  Xianwei::Start();
}
