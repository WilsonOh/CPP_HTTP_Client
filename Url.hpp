#ifndef URL_HPP
#define URL_HPP

#include <string>

namespace url {
class Url {
  std::string _url;
  std::string _scheme;
  std::string _domain;
  uint16_t _port;
  std::string _path;
  std::string _parameters;
  std::string _fragment;

  friend Url parse(const std::string &url);
  friend std::ostream &operator<<(std::ostream &out, const Url &url);
  Url(const std::string &url, const std::string &scheme,
      const std::string &domain, const uint16_t &port, const std::string &path,
      const std::string &parameters, const std::string &fragment);

public:
  Url() = default;
  std::string scheme();
  std::string domain();
  uint16_t port();
  std::string params();
  std::string fragment();
  std::string uri();
};

std::ostream &operator<<(std::ostream &out, const url::Url &url);
/**
 * Parses the string containing a url and returns a Url object
 *
 * @param url The url to be parsed
 * @return a Url object containing all the components of the url
 */
Url parse(const std::string &url);
} // namespace url

#endif // !URL_HPP
