#include "HttpClient.hpp"
#include "Url.hpp"
#include "get_ip.hpp"
#include "strutil.hpp"
#include <arpa/inet.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <openssl/bio.h>
#include <openssl/cryptoerr.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/sslerr.h>
#include <openssl/tls1.h>
#include <sstream>
#include <unistd.h>

#ifdef VERBOSE
static bool verbose = true;
#else
static bool verbose = false;
#endif

/*----------Constructor, Destructor and Setup Functions----------*/
HttpClient::HttpClient(const url::Url &url) : _url(url) {}

HttpClient::~HttpClient() {
  if (_url.scheme() == "https") {
    if (_bio != NULL)
      BIO_free_all(_bio);
    if (_ctx != NULL)
      SSL_CTX_free(_ctx);
  } else {
    if (_sockfd != -1)
      close(_sockfd);
  }
}

/**
 * Additional setup that can be called:
  SSL_library_init();
  ERR_load_CRYPTO_strings();
  ERR_load_SSL_strings();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();

  SSL_CTX_set_verify_depth(_ctx, 4);
  SSL_CTX_set_options(_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1
  SSL_OP_NO_COMPRESSION); SSL_CTX_set_cipher_list(_ctx, "ALL");
  SSL_CTX_load_verify_locations(_ctx, NULL, "/etc/ssl/certs");

  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
 */
void HttpClient::ssl_setup() {
  if ((_ctx = SSL_CTX_new(TLS_method())) == NULL) {
    throw std::runtime_error("Failed to create SSL context");
  }
  if ((_bio = BIO_new_ssl_connect(_ctx)) == NULL) {
    throw std::runtime_error("Failed to create BIO");
  }
  SSL *ssl(nullptr);
  BIO_get_ssl(_bio, &ssl);
  if (ssl == NULL) {
    throw std::runtime_error("Failed to get SSL object");
  }
  std::stringstream ss;
  ss << _url.domain() << ':' << _url.port();
  std::string domain_with_port = ss.str();
  // VERY IMPT ↓!! It sets the SNI for the host server which is mandatory for
  // some TLS connections with some servers
  SSL_set_tlsext_host_name(ssl, _url.domain().c_str());
  BIO_set_conn_hostname(_bio, domain_with_port.c_str());
  if (BIO_do_connect(_bio) != 1) {
    std::cout << ERR_error_string(ERR_get_error(), NULL) << '\n';
    throw std::runtime_error("Failed to do ssl connect");
  }
}

void HttpClient::non_ssl_setup() {
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

/*------------Getter and Setter Methods------------*/
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

url::Url HttpClient::get_url() { return _url; }

std::string HttpClient::get_formatted_request() {
  std::stringstream req_ss;
  req_ss << get_method() << ' ' << _url.uri() << ' ' << "HTTP/1.1\r\n";
  std::string req = req_ss.str();
  for (const auto &[k, v] : _headers) {
    std::stringstream header_ss;
    header_ss << k << ": " << v << "\r\n";
    req.append(header_ss.str());
  }
  std::stringstream host_ss;
  host_ss << "Host: " << _url.domain() << "\r\n";
  req.append(host_ss.str());
  if (!_body.empty()) {
    std::stringstream content_len_ss;
    content_len_ss << "Content-Length: " << _body.length();
    req.append(content_len_ss.str());
  }
  req.append("\r\n\r\n");
  req.append(_body);
  return req;
}

/*---------------------"Engine" Methods-----------------*/

/**
 * Read and parse the response headers sent by the server
 * and returns a pair of headers and the status code
 */
std::pair<std::map<std::string, std::string>, int>
HttpClient::get_resp_headers() {
  std::string resp;
  char buf[2] = {0};
  /* Read byte-by-byte from the server socket until we reach the
   * end of the headers indicated by a "\r\n\r\n"
   */
  while (read(_sockfd, buf, 1) > 0) {
    resp.append(buf);
    if (resp.find("\r\n\r\n") != std::string::npos) {
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

/**
 * Identical to `get_resp_headers` above, except we are using
 * `BIO_read` instead of `read`
 */
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
    if (tmp.empty())
      continue;
    if (!tmp[0].empty() && !tmp[1].empty())
      ret.insert({strutil::lowers(tmp[0]), strutil::lowers(tmp[1])});
  }
  return {ret, statuscode};
}

/**
 * Read a fixed number of bytes from the server using
 * the `Content-Length` header
 */
std::string HttpClient::read_fixed_length_body(int length) {
  if (length == 0) {
    return "";
  }
  int total = 0;
  unsigned char buf[2] = {0};
  std::string body;
  while (total < length) {
    total += read(_sockfd, buf, 1);
    if (!_download_file.empty()) {
      _of.write((char *)buf, 1);
    }
    body.append((char *)buf);
    std::cout << '\r' << total << " out of " << length << " bytes read, "
              << std::fixed << std::setprecision(2)
              << (((float)total / length) * 100) << '%';
    std::cout.flush();
  }
  std::cout << '\n';
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
  std::string::size_type n;
  int len;
  while (read(_sockfd, buf, 1)) {
    /* Read into temp buffer until we hit "\r\n",
     * indicating the start of a chunk
     */
    tmp.append(buf);
    if ((n = tmp.find("\r\n")) != std::string::npos) {
      /*
       * If we reach this block, it means that the chunk size + "\r\n"
       * is read into the temp buffer. In order the get the chunk size as a
       * decimal number, we must remove the "\r\n" (can use strutil::trim
       * instead)
       */
      tmp.erase(n, tmp.length());
      len = std::stoi(tmp, 0, 16);
      /* If len is 0, that means it is the end of the response body. So we
       * return the body.
       */
      if (len == 0)
        return body;
      /**
       * Else we can use the `read_fixed_length_body` to read `len` number of
       * bytes from the server. IMPT: we have to read in `len + 2` bytes so as
       * to take into account the "\r\n" at the end of each chunk!
       */
      body.append(read_fixed_length_body(len + 2));
      /* Clear the temp buffer for the next iteration */
      tmp.erase();
    }
  }
  return body;
}

/**
 * Identical to its non_ssl counterpart, except this used `BIO_read`
 * instead of `read`.
 */
std::string HttpClient::ssl_read_fixed_length_body(int length) {
  if (length == 0) {
    return "";
  }
  int total = 0;
  unsigned char buf[2] = {0};
  std::string body;
  while (total < length) {
    total += BIO_read(_bio, buf, 1);
    if (!_download_file.empty()) {
      _of.write((char *)buf, 1);
    }
    body.append((char *)buf);
    std::cout << '\r' << total << " out of " << length << " bytes read, "
              << std::fixed << std::setprecision(2)
              << (((float)total / length) * 100) << '%';
    std::cout.flush();
  }
  std::cout << '\n';
  return body;
}

/**
 * Identical to its non_ssl counterpart, except this used `BIO_read`
 * instead of `read`.
 */
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

HttpReponse HttpClient::ssl_send() {
  ssl_setup();
  std::string req = get_formatted_request();
  if (BIO_write(_bio, req.c_str(), req.length()) <= 0) {
    throw std::runtime_error("failed to write");
  }
  auto [resp_headers, statuscode] = ssl_get_resp_headers();
  std::string body;
  if (resp_headers.find("content-length") != resp_headers.end()) {
    body = ssl_read_fixed_length_body(
        std::stoi(resp_headers.at("content-length")));
  } else if (resp_headers.find("transfer-encoding") != resp_headers.end()) {
    body = ssl_read_chunked_body();
  } else {
    throw std::runtime_error("host server response header has no "
                             "content-length or chunked encoding");
  }
  if (statuscode >= 300 && statuscode < 400) {
    std::string new_location = resp_headers.at("location");
    if (new_location[0] == '/') {
      std::stringstream new_location_ss;
      new_location_ss << _url.scheme() << "://" << _url.domain()
                      << new_location;
      new_location = new_location_ss.str();
    }
    return new_client(new_location).download_to_file(_download_file).send();
  }
  return {resp_headers, statuscode, body};
}

HttpReponse HttpClient::non_ssl_send() {
  /* First we have to setup the socket connection  */
  non_ssl_setup();
  /* We then get the fully configured and formatted request string */
  std::string req = get_formatted_request();
  /* We write the request to the server */
  if (write(_sockfd, req.c_str(), req.length()) == -1) {
    throw std::runtime_error("failed to write (non-ssl)");
  }
  auto [resp_headers, statuscode] = get_resp_headers();
  std::string body;
  /* If the server responds with a "Content-Length" header, we will use the
   * fixed-length method */
  if (resp_headers.find("content-length") != resp_headers.end()) {
    body = read_fixed_length_body(std::stoi(resp_headers.at("content-length")));
    /* Else if "Transfer-Encoding" was specified instead, read from the server
     * in chunks */
  } else if (resp_headers.find("transfer-encoding") != resp_headers.end()) {
    body = read_chunked_body();
    /* Else panic as we don't know how to deal with any other methods of reading
     * the body */
  } else {
    throw std::runtime_error("host server response header has no "
                             "content-length or chunked encoding");
  }
  /* Check for redirection status codes */
  if (statuscode >= 300 && statuscode < 400) {
    std::string new_location = resp_headers.at("location");
    /* If the server redirects to a relative path, construct the full path from
     * the relative path */
    if (new_location[0] == '/') {
      std::stringstream new_location_ss;
      new_location_ss << _url.scheme() << "://" << _url.domain()
                      << new_location;
      new_location = new_location_ss.str();
    }
    /* Create a new client and send a request to the new location.
     * This can recursively redirect until we get an valid status code
     */
    return new_client(new_location).download_to_file(_download_file).send();
  }
  return {resp_headers, statuscode, body};
}

HttpReponse HttpClient::send() {
  if (!_download_file.empty()) {
    std::cout << "Downloading file into: " << _download_file << '\n';
  }
  HttpReponse ret;
  if (verbose) {
    std::cout << "[LOG] Sending Request String: \n " << get_formatted_request()
              << '\n';
  }
  /* Choose between ssl and non-ssl methods depending on the scheme */
  if (_url.scheme() == "https") {
    ret = ssl_send();
  } else {
    ret = non_ssl_send();
  }
  if (!_download_file.empty()) {
    _of.close();
    std::filesystem::rename(_download_file + ".tmp", _download_file);
  }
  return ret;
}

HttpClient &HttpClient::download_to_file(const std::string &file_name) {
  _download_file = file_name;
  if (_of.is_open()) {
    _of.close();
  }
  _of.open(file_name + ".tmp", std::ios::binary);
  return *this;
}
