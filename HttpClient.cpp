#include "HttpClient.hpp"
#include "fmt/core.h"
#include "strutil.hpp"

HttpClient::HttpClient(const url::Url &url) : _url(url) {
  if (strutil::lowers(_url.scheme()) == "https") {
    ssl_setup();
  } else {
    setup();
  }
}

void HttpClient::ssl_setup() {
  SSL_library_init();
  if ((_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
    throw std::runtime_error("Failed to create SSL context");
  }
  SSL_CTX_set_options(_ctx, SSL_OP_NO_SSLv2);
  _bio = BIO_new_ssl_connect(_ctx);
  std::string tmp =
      fmt::format("{}:{}", _url.domain(), std::to_string(_url.port()));
  BIO_set_conn_hostname(_bio, tmp.c_str());
  if (BIO_do_connect(_bio) != 1) {
    std::cout << ERR_error_string(ERR_get_error(), NULL) << '\n';
    throw std::runtime_error("Failed to do ssl connect");
  }
}

void HttpClient::setup() {
  _sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (_sockfd == -1) {
    throw std::runtime_error("failed to create socket");
  }
  struct sockaddr_in sa = {0};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(_url.port());
  std::string ip = get_ipaddr(_url.domain());
  if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) == -1) {
    throw std::runtime_error("inet_pton: error");
  }
  if (connect(_sockfd, (struct sockaddr *)&sa, sizeof(struct sockaddr)) == -1) {
    throw std::runtime_error("failed to connect to ip: " + ip);
  }
}

HttpClient HttpClient::new_client(const std::string &url) {
  return HttpClient(url::parse(url));
}

void HttpClient::print_headers() {
  for (const auto &[k, v] : _headers) {
    std::cout << k << " : " << v << '\n';
  }
}

HttpClient &HttpClient::del() {
  _method = HttpMethod::DELETE;
  return *this;
}
HttpClient &HttpClient::get() {
  _method = HttpMethod::GET;
  return *this;
}
HttpClient &HttpClient::post() {
  _method = HttpMethod::POST;
  return *this;
}
HttpClient &HttpClient::put() {
  _method = HttpMethod::PUT;
  return *this;
}

HttpClient &
HttpClient::add_headers(std::map<std::string, std::string> headers) {
  _headers.merge(headers);
  return *this;
}

HttpClient &HttpClient::add_header(std::string key, std::string value) {
  _headers.insert_or_assign(key, value);
  return *this;
}

HttpClient &HttpClient::body(std::string s) {
  _body = s;
  return *this;
}

std::string HttpClient::get_method() {
  switch (_method) {
  case GET:
    return "GET";
  case POST:
    return "POST";
  case PUT:
    return "PUT";
  case DELETE:
    return "DELETE";
  default:
    return "GET";
  }
}

std::string HttpClient::get_formatted_request() {
  std::string req = fmt::format("{} {} HTTP/1.1\r\n", get_method(), _url.uri());
  for (const auto &[k, v] : _headers) {
    req.append(fmt::format("{}: {}\r\n", k, v));
  }
  req.append(fmt::format("Host: {}\r\n", _url.domain()));
  if (!_body.empty()) {
    req.append(fmt::format("{}: {}", "Content-Length", _body.length()));
  }
  req.append("\r\n\r\n");
  req.append(_body);
  return req;
}

std::pair<std::map<std::string, std::string>, int>
HttpClient::get_resp_headers() {
  std::string resp;
  char buf[2] = {0};
  while (read(_sockfd, buf, 1) > 0) {
    resp.append(buf);
    if (resp.find("\r\n\r\n") != std::string::npos) {
      break;
    }
  }
  std::vector<std::string> resp_headers = strutil::split(resp, "\n");
  auto it = resp_headers.cbegin();
  int statuscode = std::stoi(strutil::split(*it, " ")[1]);
  it++;
  std::map<std::string, std::string> ret;
  for (; it != resp_headers.cend(); ++it) {
    std::vector<std::string> tmp = strutil::split(strutil::trim(*it), ": ");
    if (tmp.empty()) continue;
    if (!tmp[0].empty() && !tmp[1].empty())
      ret.insert({tmp[0], tmp[1]});
  }
  return {ret, statuscode};
}

std::string HttpClient::read_fixed_length_body(int length) {
  int total = 0;
  char buf[2] = {0};
  std::string body;
  while (total < length) {
    total += read(_sockfd, buf, 1);
    body.append(buf);
  }
  return body;
}

std::string HttpClient::read_chunked_body() {
  std::string body;
  char buf[2] = {0};
  std::string tmp;
  std::string::size_type n;
  int len;
  while (read(_sockfd, buf, 1)) {
    tmp.append(buf);
    if ((n = tmp.find("\r\n")) != std::string::npos) {
      tmp.erase(n, tmp.length());
      len = std::stoi(tmp, 0, 16);
      if (len == 0)
        return body;
      body.append(read_fixed_length_body(len + 2));
      tmp.erase();
    }
  }
  return body;
}

std::string HttpClient::ssl_read_fixed_length_body(int length) {
  if (length == 0) {
    return "";
  }
  int total = 0;
  char buf[2] = {0};
  std::string body;
  while (total < length) {
    total += BIO_read(_bio, buf, 1);
    body.append(buf);
  }
  return body;
}

std::string HttpClient::ssl_read_chunked_body() {
  std::string body;
  char buf[2] = {0};
  std::string tmp;
  std::string::size_type n;
  int len;
  while (BIO_read(_bio, buf, 1)) {
    tmp.append(buf);
    if ((n = tmp.find("\r\n")) != std::string::npos) {
      tmp.erase(n, tmp.length());
      len = std::stoi(tmp, 0, 16);
      if (len == 0)
        return body;
      body.append(ssl_read_fixed_length_body(len + 2));
      tmp.erase();
    }
  }
  return body;
}

std::pair<std::map<std::string, std::string>, int>
HttpClient::ssl_get_resp_headers() {
  std::string resp;
  char buf[2] = {0};
  while (BIO_read(_bio, buf, 1) > 0) {
    resp.append(buf);
    if (resp.find("\r\n\r\n") != std::string::npos) {
      break;
    }
  }
  std::vector<std::string> resp_headers = strutil::split(resp, "\n");
  auto it = resp_headers.cbegin();
  int statuscode = std::stoi(strutil::split(*it, " ")[1]);
  it++;
  std::map<std::string, std::string> ret;
  for (; it != resp_headers.cend(); ++it) {
    std::vector<std::string> tmp = strutil::split(strutil::trim(*it), ": ");
    if (tmp.empty()) continue;
    if (!tmp[0].empty() && !tmp[1].empty())
      ret.insert({tmp[0], tmp[1]});
  }
  return {ret, statuscode};
}

HttpReponse HttpClient::ssl_send() {
  std::string req = get_formatted_request();
  if (BIO_write(_bio, req.c_str(), req.length()) <= 0) {
    throw std::runtime_error("failed to write");
  }
  auto [resp_headers, statuscode] = ssl_get_resp_headers();
  std::string body;
  if (resp_headers.find("Content-Length") != resp_headers.end()) {
    body = ssl_read_fixed_length_body(
        std::stoi(resp_headers.at("Content-Length")));
  } else if (resp_headers.find("Transfer-Encoding") != resp_headers.end()) {
    body = ssl_read_chunked_body();
  } else {
    throw std::runtime_error("host server response header has no "
                             "content-length or chunked encoding");
  }
  if (statuscode == 301 || statuscode == 302) {
    HttpClient copy = *this;
    copy.ssl_setup();
    copy._url = url::parse(resp_headers.at("Location"));
    return copy.ssl_send();
  }
  return {resp_headers, statuscode, body};
}

HttpReponse HttpClient::non_ssl_send() {
  std::string req = get_formatted_request();
  if (write(_sockfd, req.c_str(), req.length()) == -1) {
    throw std::runtime_error("failed to write (non-ssl)");
  }
  auto [resp_headers, statuscode] = get_resp_headers();
  std::string body;
  if (resp_headers.find("Content-Length") != resp_headers.end()) {
    body = read_fixed_length_body(std::stoi(resp_headers.at("Content-Length")));
  } else if (resp_headers.find("Transfer-Encoding") != resp_headers.end()) {
    body = read_chunked_body();
  } else {
    throw std::runtime_error("host server response header has no "
                             "content-length or chunked encoding");
  }
  if (statuscode == 301 || statuscode == 302) {
    _url = url::parse(resp_headers.at("Location"));
    return send();
  }
  return {resp_headers, statuscode, body};
}

HttpReponse HttpClient::send() {
  HttpReponse ret;
  if (strutil::lowers(_url.scheme()) == "https") {
    ret = ssl_send();
    BIO_free_all(_bio);
    SSL_CTX_free(_ctx);
  } else {
    ret = non_ssl_send();
    close(_sockfd);
  }
  return ret;
}

url::Url HttpClient::get_url() { return _url; }
