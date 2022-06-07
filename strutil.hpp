#ifndef STRUTIL_HPP
#define STRUTIL_HPP

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace strutil {
inline std::vector<std::string> split(std::string s, std::string delimiter) {
  size_t pos_start = 0;
  size_t pos_end;
  size_t delim_len = delimiter.length();
  std::string token;
  std::vector<std::string> res;

  while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
    token = s.substr(pos_start, pos_end - pos_start);
    pos_start = pos_end + delim_len;
    res.push_back(token);
  }

  std::string last = s.substr(pos_start);
  if (!last.empty())
    res.push_back(s.substr(pos_start));
  return res;
}

inline std::string lowers(const std::string &s) {
  std::string tmp = s;
  std::transform(tmp.cbegin(), tmp.cend(), tmp.begin(),
                 [](const char &c) { return tolower(c); });
  return tmp;
}

} // namespace strutil

#endif // STRUTIL_HPP
