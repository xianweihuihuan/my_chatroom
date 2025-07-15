#include <gflags/gflags.h>
#include "file.hpp"

DEFINE_bool(run_mode, false, "程序的运行模式，false-调试；true-发布。");
DEFINE_string(log_file, "Xianwei", "发布模式下，日志的输出文件");
DEFINE_int32(log_level, 0, "发布模式下，日志的输出等级");

DEFINE_string(mysql_user, "root", "Mysql用户名");
DEFINE_string(mysql_pswd, "5344110s", "Mysql登陆密码");
DEFINE_string(mysql_host, "127.0.0.1", "Mysql服务器访问地址");
DEFINE_string(mysql_db, "ChatRoom", "Mysql访问数据库");
DEFINE_string(mysql_cset, "UTF8", "Mysql字符集");
DEFINE_int32(mysql_port, 0, "Mysql服务器访问端口");
DEFINE_int32(mysql_pool_count, 4, "Mysql连接池最大连接数量");

DEFINE_string(redis_host, "127.0.0.1", "Redis访问地址");
DEFINE_int32(redis_port, 6379, "Redis访问端口");
DEFINE_int32(redis_db, 0, "Redis访问数据库编号");
DEFINE_bool(redis_keepalive, true, "Redis数据长保活");

DEFINE_string(ver_username, "xianweihuihuan@163.com", "发送邮箱");
DEFINE_string(ver_pswd, "QPtgXwngD2zjgFGU", "邮箱验证密钥");

DEFINE_string(scrt, "../../key/server.crt", "SSL服务端证书");
DEFINE_string(skey, "../../key/server.key", "SSL服务端密钥");

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  Xianwei::init_logger(FLAGS_run_mode, FLAGS_log_file, FLAGS_log_level);
  Xianwei::TcpServer sp(8085, false, "", "");
  sp.SetMysqlMessage(FLAGS_mysql_user, FLAGS_mysql_pswd, FLAGS_mysql_host,
                     FLAGS_mysql_db, FLAGS_mysql_cset, FLAGS_mysql_port,
                     FLAGS_mysql_pool_count);
  sp.SetRedisMessage(FLAGS_redis_host, FLAGS_redis_port, FLAGS_redis_db,
                     FLAGS_redis_keepalive);
  sp.SetVerMessage(FLAGS_ver_username, FLAGS_ver_pswd);
  sp.SetMessageCallback(Xianwei::OnMessage);
  sp.SetThreadCount(10);
  mkdir(Xianwei::path.c_str(), 0775);
  if (Xianwei::path.back() != '/') {
    Xianwei::path += '/';
  }
  sp.Start();

  return 0;
}