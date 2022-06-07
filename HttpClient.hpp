#ifndef HTTPCLIENT_HPP
#define HTTPCLIENT_HPP

#include "Url.hpp"
#include "get_ip.hpp"
#include "strutil.hpp"
#include <arpa/inet.h> // inet_pton
#include <cstring>
#include <fcntl.h> // open
#include <fmt/core.h>
#include <map>
#include <netinet/in.h> // sockaddr types, htons
#include <signal.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h> // connect, AF_INET
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

struct HttpReponse {
  std::map<std::string, std::string> headers;
  int statuscode;
  std::string body;
};

enum HttpMethod { GET, POST, DELETE, PUT };

class HttpClient {
  url::Url _url;
  std::map<std::string, std::string> _headers;
  HttpMethod _method;
  int _sockfd;
  BIO *_bio;
  SSL_CTX *_ctx;

  HttpClient(const url::Url &url);

  void ssl_setup();

  void setup();

public:
  static HttpClient new_client(const std::string &url);

  void print_headers();

  HttpClient &del();
  HttpClient &get();
  HttpClient &post();
  HttpClient &put();

  HttpClient &add_headers(std::map<std::string, std::string> headers);

  std::string get_method();

  std::string get_formatted_request();

  std::pair<std::map<std::string, std::string>, int> get_resp_headers();

  std::string read_fixed_length_body(int length);

  std::string read_chunked_body();

  std::string ssl_read_fixed_length_body(int length);

  std::string ssl_read_chunked_body();

  std::pair<std::map<std::string, std::string>, int> ssl_get_resp_headers();

  HttpReponse ssl_send();

  HttpReponse non_ssl_send();

  HttpReponse send();

  url::Url get_url();
};

#endif // !HTTPCLIENT_HPP
