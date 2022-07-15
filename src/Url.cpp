#include "Url.hpp"
#include "strutil.hpp"
#include <cstdint>
#include <fmt/core.h>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>

using std::string;

url::Url::Url(const string &url, const string &scheme, const string &domain,
              const uint16_t &port, const string &path,
              const string &parameters, const string &fragment)
    : _url(url), _scheme(scheme), _domain(domain), _port(port), _path(path),
      _parameters(parameters), _fragment(fragment) {}

string url::Url::scheme() { return _scheme; }
string url::Url::domain() { return _domain; }
uint16_t url::Url::port() { return _port; }
string url::Url::params() { return _parameters; }
string url::Url::fragment() { return _fragment; }
string url::Url::uri() {
  string params = !_parameters.empty() ? "?" + _parameters : _parameters;
  string frag = !_fragment.empty() ? "#" + _fragment : _fragment;
  return _path + params + frag;
}

std::ostream &url::operator<<(std::ostream &out, const url::Url &url) {
  out << fmt::format("Url[\n  scheme: {}\n  domain: {}\n  port: {}\n  path: "
                     "{}\n  params: {}\n  fragment: {}\n]",
                     url._scheme, url._domain, url._port, url._path,
                     url._parameters, url._fragment);
  return out;
}

static string get_scheme(string &url) {
  string::size_type n = url.find("://");
  if (n == string::npos) {
    throw std::invalid_argument("Url provided does not contain a scheme.");
  }
  string ret = url.substr(0, n);
  url.erase(0, n + 3);
  return strutil::lowers(ret);
}

static string get_authority(string &url) {
  string::size_type n = url.find("/");
  if (n == string::npos) {
    string ret = url;
    url.erase();
    return ret;
  }
  string ret = url.substr(0, n);
  url.erase(0, n);
  return ret;
}

static std::tuple<string, std::optional<uint16_t>>
parse_authority(const string &authority) {
  string::size_type n = authority.find(":");
  if (n == string::npos) {
    return {authority, std::nullopt};
  }
  string domain = authority.substr(0, n);
  uint16_t port = static_cast<uint16_t>(std::stoi(authority.substr(n + 1)));
  return {domain, port};
}

static std::optional<string> get_path(string &url) {
  if (url.empty())
    return std::nullopt;
  string::size_type n = url.find("?");
  if (n == string::npos) {
    string ret = url;
    url.erase();
    return ret;
  }
  string ret = url.substr(0, n);
  url.erase(0, n + 1);
  return ret;
}

static std::optional<string> get_params(string &url) {
  if (url.empty())
    return std::nullopt;
  string::size_type n = url.find("#");
  if (n == string::npos) {
    string ret = url;
    url.erase();
    return ret;
  }
  string ret = url.substr(0, n);
  url.erase(0, n + 1);
  return ret;
}

static uint16_t get_port(const string &scheme) {
  string tmp = strutil::lowers(scheme);
  if (scheme == "http") {
    return 80;
  } else if (scheme == "https") {
    return 443;
  }
  // TODO: add support for more schemes
  throw std::invalid_argument("invalid scheme");
}

url::Url url::parse(const string &url) {
  string tmp = url;
  string scheme = get_scheme(tmp);
  string authority = get_authority(tmp);
  auto [domain, port_opt] = parse_authority(authority);
  uint16_t port = port_opt.value_or(get_port(scheme));
  string path = get_path(tmp).value_or("/");
  string params = get_params(tmp).value_or("");
  return {url, scheme, domain, port, path, params, tmp};
}
