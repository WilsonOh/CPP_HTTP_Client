#ifndef HTTPCLIENT_HPP
#define HTTPCLIENT_HPP

#include "Url.hpp"
#include "strutil.hpp"
#include <arpa/inet.h> // inet_pton
#include <cstring>
#include <fcntl.h> // open
#include <fstream>
#include <map>
#include <netinet/in.h> // sockaddr types, htons
#include <openssl/ssl.h>
#include <signal.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h> // connect, AF_INET
#include <sys/types.h>
#include <unistd.h>
#include <vector>

struct HttpReponse {
  std::map<std::string, std::string> headers;
  int statuscode;
  std::string body;
};

enum HttpMethod { GET, POST, DELETE, PUT };

using HttpHeaders = std::map<std::string, std::string>;

class HttpClient {
  int _sockfd = -1;
  SSL *_ssl = NULL;
  SSL_CTX *_ctx = NULL;
  url::Url _base_url;
  std::shared_ptr<spdlog::logger> logger;

  void ssl_setup(const url::Url &url);

  int connect_to_host(url::Url &url);

  std::pair<HttpHeaders, int> parse_response_header();

  std::string read_fixed_length_body(int length);

  std::string read_chunked_body();

  std::string ssl_read_fixed_length_body(int length);

  std::string ssl_read_chunked_body();

  std::pair<std::map<std::string, std::string>, int> ssl_get_resp_headers();

  int handle_read(char *buf, std::size_t size);

  int handle_write(const char *buf, std::size_t size);

  void drain(std::size_t size);

  HttpReponse send_http_request(const std::string &url, HttpMethod method,
                                HttpHeaders headers, const std::string &body);

  HttpReponse ssl_send();

  HttpReponse non_ssl_send();

  std::string get_formatted_request(const std::string &uri, HttpMethod method,
                                    HttpHeaders &headers,
                                    const std::string &body) const;
  std::string get_method(HttpMethod method) const;

public:
  HttpClient(const std::string &url,
             spdlog::level::level_enum logging_level = spdlog::level::off);

  ~HttpClient();

  HttpReponse get(const std::string &uri);
  HttpReponse get(const std::string &uri, const HttpHeaders &headers);

  HttpReponse post(const std::string &uri, const std::string &body);
  HttpReponse post(const std::string &uri, const std::string &body,
                   const HttpHeaders &headers);

  HttpReponse put(const std::string &uri, const std::string &body);
  HttpReponse put(const std::string &uri, const std::string &body,
                  const HttpHeaders &headers);

  HttpReponse del(const std::string &uri);
  HttpReponse del(const std::string &uri, const HttpHeaders &headers);
};

#endif // !HTTPCLIENT_HPP
