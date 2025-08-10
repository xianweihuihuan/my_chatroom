# my_chatroom

`my_chatroom` 是一个使用 C++ 编写的简易聊天室系统，
基于 [Muduo](https://github.com/chenshuo/muduo) 网络库。
整个项目由以下三个独立组件组成：

| 组件 | 说明 |
| ---- | ---- |
| **chat_server** | 负责用户管理、好友关系以及即时消息的主服务器 |
| **file_server** | 处理文件上传/下载/删除并在本地存储聊天文件 |
| **client** | 简易命令行客户端，用于连接服务器体验功能 |

系统支持用户注册与登录、好友与群组管理、离线消息缓存以及文件传输等功能，
可作为学习 C++ 网络编程和服务器设计的参考。

## 功能特性

- 用户注册、登录与状态管理
- 好友、群组及离线消息
- 文件上传、下载与持久化存储
- `spdlog` 日志记录

## 目录结构

```
chat_server/   主服务器的 C++ 源码与 CMake 脚本
file_server/   文件存储服务器实现
client/        示例命令行客户端
common/        通用工具及数据库辅助代码
muduo/         使用的轻量级网络库
odb/           ODB 数据库映射定义
proto/         Protobuf 消息定义
```

## 环境依赖

项目主要依赖以下库和工具：

- [gflags](https://gflags.github.io/gflags/) 解析命令行参数
- [Protobuf](https://developers.google.com/protocol-buffers) 描述消息格式
- [spdlog](https://github.com/gabime/spdlog) 与 [fmt](https://github.com/fmtlib/fmt) 负责日志和格式化
- MySQL 与 Redis 提供持久化存储
- `muduo` 目录下的轻量级网络框架
- [cpprestsdk](https://github.com/microsoft/cpprestsdk)、[cpr](https://github.com/libcpr/cpr) 等用于 HTTP 请求
- [hiredis](https://github.com/redis/hiredis) 与 [redis-plus-plus](https://github.com/sewenew/redis-plus-plus) 访问 Redis
- [ODB](https://www.codesynthesis.com/products/odb/) 及其 MySQL/Boost 插件

在 Ubuntu 系统上可以通过包管理器安装大部分依赖：

```bash
sudo apt-get update
sudo apt-get install g++ cmake libgflags-dev libspdlog-dev libfmt-dev \
    libprotobuf-dev protobuf-compiler libmysqlclient-dev \
    libhiredis-dev libredis++-dev libboost-all-dev libcpprest-dev \
    libcpr-dev libcurl4-openssl-dev zlib1g-dev libjsoncpp-dev
```

若发行版仓库中没有 `libcpr-dev`，可参考 [cpr 项目](https://github.com/libcpr/cpr) 说明自行编译安装。
ODB 编译器及其插件需从 [官网](https://www.codesynthesis.com/products/odb/) 下载，例如：

```bash
wget https://www.codesynthesis.com/download/odb/2.5/odb_2.5.0-1_amd64.deb
sudo dpkg -i odb_2.5.0-1_amd64.deb
```

## 构建步骤

项目使用 CMake 构建，每个组件拥有独立的 `CMakeLists.txt`。
首次构建时会调用 `protoc` 与 `odb` 自动生成源码，确保它们在 `PATH` 中。

以编译 `chat_server` 为例：

```bash
mkdir build
cd build
cmake ..  
make 
```

生成的可执行文件位于 `build/` 目录。
若提示找不到 `odb`，请确认已正确安装并加入 `PATH`

## 运行示例

启动聊天服务器与文件服务器的基本流程如下：

```bash
./chat_server --port=8080 --mysql_user=root --redis_host=127.0.0.1
mkdir -p ./file_data
./file_server --port=8085 --file_path=./file_data
```

在启动前请确保 MySQL 与 Redis 服务已就绪，并根据实际情况修改命令行中的连接信息。

之后在另一个终端运行客户端，连接到聊天服务器：

```bash
cd client
docker pull xianwei042/client:v2
docker compose run --rm chat_client
```

更多参数和使用方式可参考 `chat_server/source/server.cc` 与 `file_server/source/server.cc` 中的定义。

## 开发提示

- 当 `proto/` 或 `odb/` 下的定义发生变化时，需要重新运行构建以生成对应源码。

## 项目状态

本仓库旨在学习与实验，尚未对异常情况及安全性进行全面处理，
若需在生产环境中使用请务必完善并经过充分测试。
