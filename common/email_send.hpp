#pragma once
#include <curl/curl.h>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <regex>
#include <string>
#include "logger.h"

namespace Xianwei {
class EmailSend {
 public:
  EmailSend(const std::string& username,
            const std::string& password,
            const std::string& smtp_server = "smtps://smtp.163.com:465")
      : _smtp_server(smtp_server), _username(username), _password(password) {}

  struct UploadStatus {
    size_t bytes_read;
  };

  bool Send(const std::string& to_email,
            const std::string& ssubject,
            const std::string& txt,
            bool IsHTML = true) {
    CURL* curl;
    CURLcode res = CURLE_OK;
    struct curl_slist* recipients = nullptr;

    // 构造邮件内容
    std::string from = "From: " + _username + "\r\n";
    std::string to = "To: " + to_email + "\r\n";
    std::string subject = "Subject: " + ssubject + "\r\n";
    std::string content_type;
    if (IsHTML) {
      content_type = "Content-Type: text/html; charset=UTF-8\r\n";
    }
    std::string body = "\r\n" + txt + "\r\n";
    std::string data = from + to + subject + content_type + body;

    curl = curl_easy_init();
    if (curl) {
      curl_easy_setopt(curl, CURLOPT_USERNAME, _username.c_str());
      curl_easy_setopt(curl, CURLOPT_PASSWORD, _password.c_str());
      curl_easy_setopt(curl, CURLOPT_URL, _smtp_server.c_str());
      curl_easy_setopt(curl, CURLOPT_MAIL_FROM,
                       ("<" + _username + ">").c_str());

      recipients =
          curl_slist_append(recipients, ("<" + to_email + ">").c_str());
      curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

      // 设置SSL
      curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
                       0L);  // 测试可设为0，生产建议设为1
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
                       0L);  // 测试可设为0，生产建议设为2

      // 设置邮件内容读取回调
      curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
      curl_easy_setopt(curl, CURLOPT_READDATA, &data);
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

      res = curl_easy_perform(curl);

      curl_slist_free_all(recipients);
      curl_easy_cleanup(curl);

      if (res != CURLE_OK) {
        LOG_ERROR("发送失败：{}", curl_easy_strerror(res));
        return false;
      }
      LOG_DEBUG("{} 已成功发送到 {}", txt, to_email);
      return true;
    }
    return false;
  }

 private:
  static size_t payload_source(void* ptr,
                               size_t size,
                               size_t nmemb,
                               void* userp) {
    std::string* payload = static_cast<std::string*>(userp);
    size_t buffer_size = size * nmemb;
    if (payload->empty())
      return 0;
    size_t copy_size = std::min(buffer_size, payload->size());
    memcpy(ptr, payload->c_str(), copy_size);
    payload->erase(0, copy_size);
    return copy_size;
  }


 private:
  std::string _smtp_server;
  std::string _username;
  std::string _password;
};
}  // namespace Xianwei