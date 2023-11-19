#include "HttpClient.hpp"
#include "Url.hpp"
#include "spdlog/fmt/bundled/core.h"
#include "strutil.hpp"
#include <arpa/inet.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <ios>
#include <iostream>
#include <netdb.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

std::string get_ip_from_addrinfo(struct addrinfo *ai) {
  std::string buf;
  if (ai->ai_addr->sa_family == AF_INET) {
    struct sockaddr_in *addr_in = (struct sockaddr_in *)ai->ai_addr;
    buf.resize(INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(addr_in->sin_addr), buf.data(), INET_ADDRSTRLEN);
  } else if (ai->ai_addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)ai->ai_addr;
    buf.resize(INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(addr_in6->sin6_addr), buf.data(), INET6_ADDRSTRLEN);
  }
  return buf;
}

/**
 * @brief finds the first valid ip address for {domain} and {port}
 *
 * @param domain the domain to connect to
 * @param port the port to connect to
 * @return the file descriptor of the socket if there's a valid address, or -1
 * if there are no valid addresses
 */
int connect_to_host(url::Url &url) {
  struct addrinfo hints = {0};
  struct addrinfo *res;
  int addrinfo_err;
  int sockfd;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if ((addrinfo_err =
           getaddrinfo(url.domain().c_str(), std::to_string(url.port()).c_str(),
                       &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(addrinfo_err));
    return -1;
  }
  for (; res != NULL; res = res->ai_next) {
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
      continue;
    }
    std::string ip = get_ip_from_addrinfo(res);
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) != 0) {
      continue;
    }
    break;
  }
  if (res == NULL) {
    return -1;
  }
  freeaddrinfo(res);
  return sockfd;
}

// Let the buffer size for reading from sockets one page
#define BUF_SIZE 4096

/*----------Constructor, Destructor and Setup Functions----------*/

HttpClient::HttpClient(const std::string &url) {
  url::Url parsed_url = url::parse(url);
  _base_url = parsed_url;
  _sockfd = connect_to_host(parsed_url);

  if (_sockfd == -1) {
    throw std::runtime_error("Error connecting to server.");
  }

  if (parsed_url.scheme() == "https") {
    ssl_setup(parsed_url);
  }
}

HttpClient::~HttpClient() {
  if (_ssl != NULL) {
    SSL_shutdown(_ssl);
    SSL_free(_ssl);
  }
  if (_ctx != NULL) {
    SSL_CTX_free(_ctx);
  }
  if (_sockfd > 0) {
    close(_sockfd);
  }
}

void HttpClient::ssl_setup(const url::Url &url) {
  _ctx = SSL_CTX_new(TLS_method());
  if (_ctx == NULL) {
    throw std::runtime_error("Failed to create SSL context");
  }
  _ssl = SSL_new(_ctx);
  if (_ssl == NULL) {
    throw std::runtime_error("Failed to get SSL object");
  }
  // set SNI for servers with multiple virtual hosts
  SSL_set_tlsext_host_name(_ssl, url.domain().c_str());
  SSL_set_fd(_ssl, _sockfd);
  SSL_connect(_ssl);
}

/*------------Getter and Setter Methods------------*/

std::string HttpClient::get_method(HttpMethod method) const {
  switch (method) {
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

std::string HttpClient::get_formatted_request(const std::string &uri,
                                              HttpMethod method,
                                              HttpHeaders &user_headers,
                                              const std::string &body) const {
  HttpHeaders headers = {{"Host", _base_url.domain()}};

  if (!body.empty()) {
    headers.insert_or_assign("Content-Length", std::to_string(body.length()));
  }

  headers.merge(user_headers);

  std::stringstream req_ss;
  req_ss << get_method(method) << ' ' << uri << ' ' << "HTTP/1.1\r\n";
  for (const auto &[k, v] : headers) {
    std::stringstream header_ss;
    req_ss << k << ": " << v << "\r\n";
  }
  req_ss << "\r\n";
  req_ss << body;
  return req_ss.str();
}

/*---------------------"Engine" Methods-----------------*/

/**
 * Read and parse the response headers sent by the server
 * and returns a pair of headers and the status code
 */
std::pair<HttpHeaders, int> HttpClient::parse_response_header() {
  std::string resp;
  char buf[2] = {0};
  /* Read byte-by-byte from the server socket until we reach the
   * end of the headers indicated by a "\r\n\r\n"
   */
  while (true) {
    int num_bytes_read = handle_read(buf, 1);
    if (num_bytes_read < 0) {
      throw std::runtime_error("Error reading from socket");
    }
    if (num_bytes_read == 0) {
      break;
    }
    resp.append(buf);
    if (resp.ends_with("\r\n\r\n")) {
      break;
    }
  }
  std::vector<std::string> resp_headers = strutil::split(resp, "\n");
  /* Get the iterator pointing to the first line */
  auto it = resp_headers.cbegin();
  /* Since the status line has the format of:
   * <METHOD STATUS_CODE STATUS_MSG>,
   * we can get the status code by splitting the line on whitespace
   * and taking the second word
   */
  int statuscode = std::stoi(strutil::split(*it, " ")[1]);
  /* Advance the iterator to the next line */
  it++;
  /* Iterate over the rest of the lines and add them as headers*/
  std::map<std::string, std::string> ret;
  for (; it != resp_headers.cend(); ++it) {
    std::vector<std::string> tmp = strutil::split(strutil::trim(*it), ": ");
    /* Sanity checks to make sure we don't do anything with empty strings */
    if (tmp.empty())
      continue;
    if (!tmp[0].empty() && !tmp[1].empty())
      /* make the headers all lower-case for consistency thorughout the code
       * base */
      ret.insert({strutil::lowers(tmp[0]), strutil::lowers(tmp[1])});
  }
  return {ret, statuscode};
}

int HttpClient::handle_read(char *buf, std::size_t size) {
  if (_ssl != NULL) {
    return SSL_read(_ssl, buf, size);
  }
  return read(_sockfd, buf, size);
}

int HttpClient::handle_write(const char *buf, std::size_t size) {
  if (_ssl != NULL) {
    return SSL_write(_ssl, buf, size);
  }
  return write(_sockfd, buf, size);
}

void HttpClient::drain(std::size_t size) {
  std::vector<char> buf(size);
  handle_read(buf.data(), size);
}

/**
 * Read a fixed number of bytes from the server using
 * the `Content-Length` header
 */
std::string HttpClient::read_fixed_length_body(int length) {
  int total = 0;
  char buf[BUF_SIZE] = {0};
  std::string body;
  while (total < length) {
    int num_bytes_read = handle_read(buf, BUF_SIZE - 1);
    if (num_bytes_read < 0) {
      throw std::runtime_error("Error reading from socket.");
    }
    if (num_bytes_read == 0) {
      break;
    }
    total += num_bytes_read;
    body.append(buf, num_bytes_read);
  }
  return body;
}

/**
 * Read the the response body from the server in chunks
 * if `Transfer-Encoding: chunked` is specified in the
 * response headers.
 */
std::string HttpClient::read_chunked_body() {
  std::string body;
  char buf[2] = {0};
  std::string tmp;
  int len;
  while (true) {
    int num_bytes_read = handle_read(buf, 1);
    if (num_bytes_read < 0) {
      throw std::runtime_error("Error reading from socket.");
    }
    if (num_bytes_read == 0) {
      break;
    }

    /* Read into temp buffer until we hit "\r\n",
     * indicating the start of a chunk
     */
    tmp.append(buf, 1);
    if (tmp.ends_with("\r\n")) {
      /*
       * If we reach this block, it means that the chunk size + "\r\n"
       * is read into the temp buffer. In order the get the chunk size as a
       * decimal number, we must remove the "\r\n" (can use strutil::trim
       * instead)
       */
      len = std::stoi(strutil::trim(tmp), 0, 16);
      /* If len is 0, that means it is the end of the response body. So we
       * return the body.
       */
      if (len == 0)
        break;
      /**
       * Else we can use the `read_fixed_length_body` to read `len` number of
       * bytes from the server.
       */
      body.append(read_fixed_length_body(len));
      /* Clear the temp buffer for the next iteration */
      tmp.erase();

      /*
       * IMPT: we have to "drain" 2 bytes from the socket
       * to take into account the "\r\n" at the end of each chunk!
       * */
      drain(2);
    }
  }
  return body;
}

HttpReponse HttpClient::send_http_request(const std::string &uri,
                                          HttpMethod method,
                                          HttpHeaders headers,
                                          const std::string &body) {

  std::string req = get_formatted_request(uri, method, headers, body);
  if (handle_write(req.c_str(), req.length()) <= 0) {
    throw std::runtime_error("Error sending request");
  }
  auto [resp_headers, statuscode] = parse_response_header();
  std::string response_body;
  if (resp_headers.contains("content-length")) {
    response_body =
        read_fixed_length_body(std::stoi(resp_headers.at("content-length")));
  } else if (resp_headers.contains("transfer-encoding")) {
    response_body = read_chunked_body();
  } else {
    throw std::runtime_error("server response headers have no "
                             "content-length or transfer-encoding: chunked");
  }
  if (statuscode >= 300 && statuscode < 400) {
    std::string new_location = resp_headers.at("location");
    // Handle case where the provided location is a relative URL
    if (new_location[0] == '/') {
      std::stringstream new_location_ss;
      new_location_ss << _base_url.scheme() << "://" << _base_url.domain()
                      << new_location;
      new_location = new_location_ss.str();
    }
    return send_http_request(new_location, method, headers, body);
  }
  return {resp_headers, statuscode, response_body};
}

HttpReponse HttpClient::get(const std::string &uri) {
  return send_http_request(uri, HttpMethod::GET, {}, "");
}

HttpReponse HttpClient::get(const std::string &uri,
                            const HttpHeaders &headers) {
  return send_http_request(uri, HttpMethod::GET, headers, "");
}

HttpReponse HttpClient::post(const std::string &uri, const std::string &body) {
  return send_http_request(uri, HttpMethod::POST, {}, body);
}

HttpReponse HttpClient::post(const std::string &uri, const std::string &body,
                             const HttpHeaders &headers) {
  return send_http_request(uri, HttpMethod::POST, headers, body);
}

HttpReponse HttpClient::put(const std::string &uri, const std::string &body) {
  return send_http_request(uri, HttpMethod::PUT, {}, body);
}

HttpReponse HttpClient::put(const std::string &uri, const std::string &body,
                            const HttpHeaders &headers) {
  return send_http_request(uri, HttpMethod::PUT, headers, body);
}

HttpReponse HttpClient::del(const std::string &uri) {
  return send_http_request(uri, HttpMethod::DELETE, {}, "");
}

HttpReponse HttpClient::del(const std::string &uri,
                            const HttpHeaders &headers) {
  return send_http_request(uri, HttpMethod::DELETE, headers, "");
}
