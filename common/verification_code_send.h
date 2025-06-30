#pragma once
#include "email_send.hpp"

namespace Xianwei {

std::string generate_code();

// 用于读取邮件内容的回调结构体

class VerificationCodeSend {
 public:
  using ptr = std::shared_ptr<VerificationCodeSend>;
  VerificationCodeSend(
      const std::string& username,
      const std::string& password,
      const std::string& smtp_server = "smtps://smtp.163.com:465")
      : _send(username, password, smtp_server) {}

  // ...existing code...
  bool Send(const std::string& send_to, const std::string& code);
  // ...existing code...

 private:
  EmailSend _send;
};
}  // namespace Xianwei
