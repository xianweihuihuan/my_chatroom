#include "verification_code_send.h"

namespace Xianwei {
std::string generate_code() {
  srand(time(nullptr));
  int code = rand() % 900000 + 100000;
  return std::to_string(code);
}

bool VerificationCodeSend::Send(const std::string& send_to,
                                const std::string& code) {
  std::string body =
      "感谢您使用环语轩系列产品，您的验证码是："
      "<span "
      "style=\"color:#1e90ff;text-decoration:underline;font-size:20px;\">" +
      code +
      "</span>"
      "。注意请不要将此验证码外泄，如非本人操作，请忽略此邮件并检查账号安全"
      "。";
  // 主题和正文都用UTF-8编码，正文为HTML
  bool ret = _send.Send(send_to, "验证码", body, true);
  return ret;
}


}  // namespace Xianwei
   // namespace Xianwei
