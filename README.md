# my_chatroom

这是一个使用 C++ 编写的小型聊天室系统，基于 Muduo 网络库并通过 TLS 提供安全连接。整个项目分为以下三个组件：

* **chat_server** —— 负责账户管理、好友关系以及文本消息的主服务器；
* **file_server** —— 提供文件上传与下载，存储聊天过程中产生的文件；
* **client** —— 简易命令行客户端，用于与服务器交互。

系统支持用户注册/登录、好友与群组管理、离线消息缓存以及文件传输等功能，可作为学习网络编程和服务器设计的参考。默认证书存放于 `key/` 目录，生产环境中建议更换。

## 依赖

项目使用了以下库和技术：

* [gflags](https://gflags.github.io/gflags/) 处理命令行参数
* [Protobuf](https://developers.google.com/protocol-buffers) 定义消息格式（位于 `proto/`）
* [spdlog](https://github.com/gabime/spdlog) 记录日志
* MySQL 与 Redis 作为持久化存储
* OpenSSL 提供加密连接
* `muduo` 目录下的轻量级网络框架
* [fmt](https://github.com/fmtlib/fmt) 与 [spdlog](https://github.com/gabime/spdlog) 提供格式化与日志功能
* [cpprestsdk](https://github.com/microsoft/cpprestsdk)、[cpr](https://github.com/libcpr/cpr) 等用于 HTTP 请求
* [hiredis](https://github.com/redis/hiredis) 与 [redis-plus-plus](https://github.com/sewenew/redis-plus-plus) 连接 Redis
* [ODB](https://www.codesynthesis.com/products/odb/) 及其 MySQL/Boost 插件（生成 ORM 代码）

以上依赖可通过包管理器或源码方式安装，Ubuntu 系统示例：

```bash
sudo apt-get update
sudo apt-get install g++ cmake libgflags-dev libspdlog-dev libfmt-dev \
    libprotobuf-dev protobuf-compiler libssl-dev libmysqlclient-dev \
    libhiredis-dev libredis++-dev libboost-all-dev libcpprest-dev \
    libcpr-dev libcurl4-openssl-dev zlib1g-dev libjsoncpp-dev
```

若仓库未提供 `libcpr-dev`，可参考 [cpr](https://github.com/libcpr/cpr) 的说明从源码编译。
ODB 编译器及其插件需从 [官网](https://www.codesynthesis.com/products/odb/) 下载，例如：

```bash
wget https://www.codesynthesis.com/download/odb/2.5/odb_2.5.0-1_amd64.deb
sudo dpkg -i odb_2.5.0-1_amd64.deb
```

全部依赖准备完成后即可开始编译。

## 目录结构

```
chat_server/   主服务器的 C++ 代码与构建脚本
file_server/   文件存储服务器实现
client/        示例命令行客户端
common/        通用工具及数据库辅助代码
muduo/         服务器使用的网络库
odb/           ODB 数据库映射定义
proto/         Protobuf 消息定义
key/           开发时使用的 SSL 证书
```

## 编译

本项目使用 CMake，每个组件都有独立的 `CMakeLists.txt`。首次构建时会自动调用
`protoc` 与 `odb` 生成代码，确保这两个可执行文件已在 `PATH` 中。
以编译 `chat_server` 为例：

```bash
mkdir build
cd build
cmake ../chat_server   # 其它组件将路径替换为 ../file_server 或 ../client
make -j$(nproc)
```

所有可执行文件均位于 `build` 目录。若提示找不到 `odb`，请确认已经安装并将其加入 `PATH`。

## 运行

服务器提供多种命令行参数，可用于配置端口、数据库及证书路径等。一个简单的本地运行示例：

```bash
./chat_server --port=8080 --mysql_user=root --redis_host=127.0.0.1 \
              --scrt=../key/server.crt --skey=../key/server.key
mkdir -p ./file_data
./file_server --port=8085 --file_path=./file_data
```

在启动前请确保 MySQL 与 Redis 服务已就绪，并根据实际情况修改命令行中的连接信息。

之后在另一个终端运行客户端，连接到聊天服务器：

```bash
./client --server_ip=127.0.0.1 --server_port=8080
```

更多参数请参考 `chat_server/source/server.cc` 与 `file_server/source/server.cc` 中的定义。

## 项目状态

当前代码实现了一个基本可用的聊天室，支持用户注册、好友和群聊功能，以及文件传输。项目主要用于学习和实验，尚未对异常情况和安全性做完整处理，若需在生产环境中使用还需进一步完善。

