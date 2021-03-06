# HTTP Client Written in C++
This is a side project for me to gain a deeper understanding of how HTTP connections work and to also learn more about C++.

> **Note** This library only works on Linux and macOS!

## Dependencies
* `openssl` development library
* `C++17`
* `cmake` 3.23.2 (for integrating this library into your project)

## Features :sparkles:
* GET/POST/PUT/DELETE requests for HTTP and HTTPS connections
* Simple redirect handling (for 3XX codes)
* Url parsing using the `url::Url` class
* Add request headers and request body easily

## HELP
~~The https requests works for sites like [Google](https://google.com), [YouTube](https://youtube.com) or [httpbin](https://httpbin.org) but does not work for sites like [json placeholder](https://jsonplaceholder.typicode.com/) or [Pokémon api](https://pokeapi.co/).<br>
I don't really know what the issue is as I'm not too familiar with tls programming so any help or feedback would be appreciated!~~<br>
Thanks to some helpful people over at [StackOverflow](https://stackoverflow.com/questions/49474347/why-would-bio-do-connect-from-openssl-not-work-right-with-gdax-a-k-a-cloudfl), I managed to find and fix the problem! Apparently some servers require a Server Name Indication(SNI) in the TLS handshake so I just had to add it in with ` SSL_set_tlsext_host_name(ssl, _url.domain().c_str());` and now all https requests work 🙂 (hopefully).

## Installation
### CMake Integration
This project should be used through its CMake integration.<br>
Simply add the following lines to your project `CMakeLists.txt` file:
```cmake
include(FetchContent)

cmake_minimum_required(VERSION 3.23.2)

project(<Your Project Name> CXX)

set(ENABLE_LOGGING <ON/OFF>) # Set the ENABLE_LOGGING option on or off

FetchContent_Declare(
  HttpClient
  GIT_REPOSITORY https://github.com/WilsonOh/CPP_HTTP_Client.git
  GIT_TAG main
)

FetchContent_MakeAvailable(HttpClient)

add_executable(${PROJECT_NAME} <Your Source Files>...)

target_link_libraries(${PROJECT_NAME} PRIVATE HttpClient)
```
You can also specify whether to turn on logging or not when running cmake:
`cmake -S . - B build -DENABLE_LOGGING=ON`

## Library Overview

### Helper Functions
<details>
<summary>get_ip.hpp</summary>

```cpp
inline std::string get_ipaddr(const std::string &hostname); // returns the dot-and-numbers notation of a given hostname
```
</details>

<details>
<summary>strutil.hpp</summary>

Namespaced under `strutil`
```cpp
inline std::vector<std::string> split(std::string s, std::string delimiter);
inline std::string lowers(const std::string &s); // returns a lowercase copy of a string 
inline std::string uppers(const std::string &s); // returns a uppercase copy of a string
inline std::string ltrim(const std::string &s); // removes leading whitespace from a string
inline std::string rtrim(const std::string &s); // removes trailing whitespace from a string
inline std::string trim(const std::string &s); // removes leading and trailing whitespace from a string
```
</details>

### Classes

<details>

<summary>HttpClient</summary>

HttpClient handles all the connections details, e.g. creating a socket and sockaddr struct and connecting to the host server.<br>

The HttpClient class is defined as the following:
```cpp
class HttpClient {
  url::Url _url;
  std::map<std::string, std::string> _headers;
  HttpMethod _method;
  int _sockfd;
  BIO *_bio;
  SSL_CTX *_ctx;
  std::string _body;

  HttpClient(const url::Url &url); // private constructor, not to be used
  ...other methods
}
```
#### Methods
The methods are written in a way, which supports chaining
 ```cpp
static HttpClient new_client(const std::string &url); // Constructor method which takes in a url string,
                                                       // parses it internally and returns a HttpClient object
HttpClient &del();
HttpClient &get();
HttpClient &post();
HttpClient &put();
// sets the http method, defaults to GET if no methods are set

HttpClient &add_headers(std::map<std::string, std::string> headers); // Adds http headers as a map
HttpClient &add_header(std::string key, std::string value); // Add a single header as a key-value pair of strings
HttpClient &body(std::string s); // Sets the request body

// Getter methods
std::string get_method();
std::string get_formatted_request(); // returns the full raw http request
url::Url get_url();


HttpReponse send(); // Termination method;
                    // sends the fully configured request and returns a HttpResponse struct
```

</details>

<details>

<summary>Url</summary>

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
</details>

<details>
<summary>HttpResponse</summary>

The HttpResponse struct is defined as the following:
```cpp
struct HttpReponse {
  std::map<std::string, std::string> headers;
  int statuscode;
  std::string body;
};
```
</details>

## Example Usage
### GET Requests
```cpp
// main.cpp

#include <iostream>
#include <HttpClient.hpp>

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
  auto res = HttpClient::new_client("https://jsonplaceholder.typicode.com/todos/1").send();
  std::cout << res.body;
  /*
  {
      "userId": 1,
      "id": 1,
      "title": "delectus aut autem",
      "completed": false
  }
  */

  HttpResponse res = client.send();
  if (res.statuscode != 200) {
    ...
  }
  for (const auto &[k, v] : res.headers) {
    ...
  }
  std::cout << res.body;
}
```
### POST Requests
```cpp
// main.cpp

#include <iostream>
#include <HttpClient.hpp>

int main(void) {
  auto res = HttpClient::new_client("https://httpbin.org/post")
                 .add_header("accept", "application/json")
                 .add_header("content-type", "application/json")
                 .body(R"({"foo": "bar"})")
                 .post()
                 .send();
  std::cout << res.body;
  /*
  {
  "args": {}, 
  "data": "{\"foo\": \"bar\"}", 
  "files": {}, 
  "form": {}, 
  "headers": {
    "Accept": "application/json", 
    "Content-Length": "14", 
    "Content-Type": "application/json", 
    "Host": "httpbin.org", 
    "X-Amzn-Trace-Id": "Root=1-62a06d82-73c561f957d3c3cb72ddf198"
  }, 
  "json": {
    "foo": "bar"
  }, 
  "origin": <IP Address>, 
  "url": "https://httpbin.org/post"
  }
  */
}
```

## TODO
- [x] Learn how to properly set up SSL conections using openssl so that the https requests work properly
- [x] Add support for adding a body for the request (using [this json library](https://github.com/nlohmann/json) maybe?)
- [ ] use a json library to make sending json request bodies easier

