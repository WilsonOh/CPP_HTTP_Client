#ifndef HTTPCLIENT_HPP
#define HTTPCLIENT_HPP

#include "Url.hpp"
#include "get_ip.hpp"
#include "strutil.hpp"
#include <arpa/inet.h> // inet_pton
#include <cstring>
#include <fcntl.h> // open
#include <fstream>
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
  int _sockfd = -1;
  BIO *_bio = NULL;
  SSL_CTX *_ctx = NULL;
  std::string _body;
  std::string _download_file;
  std::ofstream _of;

  HttpClient(const url::Url &url);

  void ssl_setup();

  void non_ssl_setup();

  std::pair<std::map<std::string, std::string>, int> get_resp_headers();

  std::string read_fixed_length_body(int length);

  std::string read_chunked_body();

  std::string ssl_read_fixed_length_body(int length);

  std::string ssl_read_chunked_body();

  std::pair<std::map<std::string, std::string>, int> ssl_get_resp_headers();

  HttpReponse ssl_send();

  HttpReponse non_ssl_send();

public:
  static HttpClient new_client(const std::string &url);

  ~HttpClient();

  void print_headers();

  HttpClient &del();
  HttpClient &get();
  HttpClient &post();
  HttpClient &put();
  HttpClient &download_to_file(const std::string &file_name);

  HttpClient &add_headers(std::map<std::string, std::string> headers);
  HttpClient &add_header(std::string key, std::string value);

  HttpClient &body(std::string s);

  std::string get_method();

  std::string get_formatted_request();
  HttpReponse send();

  url::Url get_url();
};

#endif // !HTTPCLIENT_HPP
