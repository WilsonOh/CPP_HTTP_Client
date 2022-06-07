# HTTP Client Written in C++
This is a side project for me to gain a deeper understanding of how HTTP connections work and also to learn more about C++. There's probably some bugs that are not fixed and the SSL connections work for some websites only 😢 (Please help!)

# This library only works on Linux!

## Dependencies
* [fmt library](https://fmt.dev/latest/index.html)

## Features
* GET requests for http connections and *some* https connections depending on the website (other methods technically work but there's no support for request body yet 😞)
* Simple redirect handling (for 301/302)
* Url parsing using the `url::Url` object

## Classes
### HttpClient
HttpClient handles all the connections details, e.g. creating a socket and sockaddr struct and connecting to the host server
#### Methods
The methods are written in a way which supports chaining
 ```cpp
static HttpClient new_client(const std::string &url); // Constructor method which takes in a url string,
                                                       // parses it internally and returns a HttpClient object
HttpClient &del();
HttpClient &get();
HttpClient &post();
HttpClient &put();
// sets the http method

HttpClient &add_headers(std::map<std::string, std::string> headers); // Adds http headers as a map

HttpReponse send(); // sends the fully configured request and returns a HttpResponse struct

std::string get_method();
std::string get_formatted_request();
url::Url get_url();
```
### Url
Namespaced under `url`
```cpp
Url parse(const std::string &url); // Takes in a url string and returns a Url object
/* Getter methods */
std::string scheme();
std::string domain();
uint16_t port();
std::string params();
std::string fragment();
std::string uri();
```
### HttpResponse
The HttpResponse struct is defined as the following:
```cpp
struct HttpReponse {
  std::map<std::string, std::string> headers;
  int statuscode;
  std::string body;
};
```

### Example Usage
```cpp
// main.cpp

#include <iostream>
#include "HttpClient.hpp"

int main(void) {
  HttpClient client = HttpClient::new_client("https://google.com")
                        .add_headers({{"Accept", "text/html"}, {"Foo", "Bar"}})
                        .get();
  std::cout << client.get_formatted_req();
  /*
  GET / HTTP/1.1
  Accept: text/html
  Foo: Bar
  Host: www.google.com
  
  
  */
  if (res.statuscode != 200) {
    ...
  }
  for (const auto &[k, v] : res.headers) {
    ...
  }
  std::cout << res.body;
}
```
#### To Compile
```console
g++ main.cpp Url.cpp HttpClient.cpp -lfmt -lssl -lcrypto -std=c++17 -o main
```

## TODO
* Learn how to properly set up SSL conections using openssl so that the https requests work properly
* Add support for adding a body for the request (using [this json library](https://github.com/nlohmann/json) maybe?)

