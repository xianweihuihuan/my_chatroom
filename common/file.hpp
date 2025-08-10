#pragma once
#include <sys/sendfile.h>
#include <filesystem>
#include <fstream>
#include "TcpServer.h"
#include "file.pb.h"

namespace Xianwei {

std::string path;

void OnMessage(const int fd) {
  Socket socket(fd);
  Buffer buf;
  char tmp[65535];  
  while (true) {
    int sz = socket.NonBlockRecv(tmp, sizeof(tmp));
    if(sz < 0){
      continue;
    }
    buf.WriteAndPush(tmp, sz);
    std::string lenLine = buf.GetLine();
    if (lenLine.empty()) {
      break;
    }
    int bodyLen = 0;
    try {
      bodyLen = std::stoi(lenLine.substr(0, lenLine.size() - 2));
    } catch (...) {
      buf.Clear();
      socket.Close();
      return;
    }
    if (buf.ReadAbleSize() < lenLine.size() + static_cast<size_t>(bodyLen)) {
      break;
    }
    buf.MoveReadIndex(lenLine.size());
    std::string data = buf.ReadAsStringAndPop(bodyLen);
    FileServer msg;
    if (!msg.ParseFromString(data)) {
      continue;
    }
    if (msg.type() == FileServerType::FileSendReqType) {
      FileClient rsp;
      rsp.set_type(FileClientType::FileSendRspType);
      auto req = msg.file_send_req();
      std::string file_id = req.file_id();
      std::string file = path + file_id;
      std::ofstream out;
      if (req.send_type() == FileSendType::FileSendFromBegin) {
        out.open(file, std::ios::out | std::ios::trunc | std::ios::binary);
        rsp.mutable_file_send_rsp()->set_file_sz(0);
      } else if (req.send_type() == FileSendType::FileSendContinue) {
        if (!std::filesystem::exists(file)) {
          rsp.mutable_file_send_rsp()->set_success(false);
          rsp.mutable_file_send_rsp()->set_errmsg("服务器不存在此文件");
          std::string srsp = rsp.SerializeAsString();
          std::string body = std::to_string(srsp.size()) + "\r\n" + srsp;
          socket.Send(body.c_str(), body.size());
          std::this_thread::sleep_for(std::chrono::seconds(10));
          return;
        }
        auto size = std::filesystem::file_size(file);
        rsp.mutable_file_send_rsp()->set_file_sz(size);
        out.open(file, std::ios::out | std::ios::app | std::ios::binary);
      }
      if (out.is_open()) {
        rsp.mutable_file_send_rsp()->set_success(true);
      } else {
        rsp.mutable_file_send_rsp()->set_success(false);
        rsp.mutable_file_send_rsp()->set_errmsg("未成功打开服务器文件");
        std::string srsp = rsp.SerializeAsString();
        std::string body = std::to_string(srsp.size()) + "\r\n" + srsp;
        socket.Send(body.c_str(), body.size());
        std::this_thread::sleep_for(std::chrono::seconds(10));
        return;
      }
      std::string srsp = rsp.SerializeAsString();
      std::string body = std::to_string(srsp.size()) + "\r\n" + srsp;
      socket.Send(body.c_str(), body.size());
      char buffer[65535];
      while (true) {
        ssize_t sz = socket.Recv(buffer, sizeof(buffer));
        if (sz == 0) {
          LOG_DEBUG("对端关闭");
          out.close();
          break;
        } else if (sz < 0) {
          if (sz < 0 && ((errno == EAGAIN || errno == EINTR))) {
            continue;
          }
          out.close();
          return;
        }
        out.write(buffer, sz);
        //LOG_DEBUG("写入{}", sz);
      }
      break;
    } else if (msg.type() == FileServerType::FileGetReqType) {
      FileClient rsp;
      rsp.set_type(FileClientType::FileGetRspType);
      auto req = msg.file_get_req();
      std::string file_id = req.file_id();
      std::string file = path + file_id;
      if (!std::filesystem::exists(file)) {
        rsp.mutable_file_get_rsp()->set_success(false);
        rsp.mutable_file_get_rsp()->set_errmsg("服务器不存在该文件");
        std::string srsp = rsp.SerializeAsString();
        std::string body = std::to_string(srsp.size()) + "\r\n" + srsp;
        socket.Send(body.c_str(), body.size());
        std::this_thread::sleep_for(std::chrono::seconds(10));
        return;
      }
      int file_fd = open(file.c_str(), O_RDONLY);
      if (file_fd < 0) {
        LOG_ERROR("打开文件{}失败", file);
        rsp.mutable_file_get_rsp()->set_success(false);
        rsp.mutable_file_get_rsp()->set_errmsg("打开文件失败");
        std::string srsp = rsp.SerializeAsString();
        std::string body = std::to_string(srsp.size()) + "\r\n" + srsp;
        socket.Send(body.c_str(), body.size());
        std::this_thread::sleep_for(std::chrono::seconds(10));
        return;
      }
      rsp.mutable_file_get_rsp()->set_success(true);
      std::string srsp = rsp.SerializeAsString();
      std::string body = std::to_string(srsp.size()) + "\r\n" + srsp;
      socket.Send(body.c_str(), body.size());
      size_t tsz = std::filesystem::file_size(file);
      std::cout << tsz << std::endl;
      size_t step = 60000;
      off_t offset = 0;
      std::this_thread::sleep_for(std::chrono::seconds(1));
      while (offset < tsz) {
        auto count = std::min(step,
                              tsz - offset);  // 计算剩余数据大小
        ssize_t ret =
            sendfile(socket.Fd(), file_fd, &offset, count);  // 发送文件部分
        if (ret == -1) {
          if (errno == EAGAIN || errno == EINTR) {
            continue;
          }
          LOG_ERROR("发送文件失败");
          close(file_fd);
          break;
        }
      }
      LOG_ERROR("文件传输完毕");
      close(file_fd);
      close(fd);
      break;
    }else if(msg.type() == FileServerType::FileDelReqType){
      auto req = msg.file_del_req();
      for (int i = 0; i < req.file_id_size();++i){
        auto file = path + req.file_id(i);
        std::remove(file.c_str());
      }
    }
  }
}
}  // namespace Xianwei