# CPP_HTTP_Client

This is a side project for me to gain a deeper understanding of low-level networking concepts as well as the HTTP spec.

> **Note** This library only works on Linux and macOS!

## Dependencies

- `openssl` development library
- `C++20`
- `cmake` 3.23.2 (for integrating this library into your project)
- `spdlog` for logging (can be bundled automatically by CMake)

## Features :sparkles:

- GET/POST/PUT/DELETE requests for HTTP and HTTPS connections
- Redirect handling (for 3XX codes)
- Configure requests with ease

## Hello World Example
```cpp
#include <HttpClient.hpp>
#include <iostream>

int main() {
  HttpClient client{"https://jsonplaceholder.typicode.com"};
  auto res = client.get("/todos/1");
  std::cout << res.body << '\n';
}

```

## Design
Instead of making requests with a single url i.e. 
```cpp
client.get("https://jsonplaceholder.typicode.com/todos/1");
```
The `base url` is first set, and then requests are made using the `uri`.
The `base_url` consists of the `scheme` e.g. https or http and the `host name` e.g. `jsonplaceholder.typicode.com` i.e.
```cpp
HttpClient client{"https://jsonplaceholder.typicode.com"};
client.get("/todos/1");
```
It is designed this way so that each client is bound to a single TCP connection which can be re-used for multiple requests to the same domain.


## Installation

### CMake Integration

This project should be used through its CMake integration.<br>
Simply add the following lines to your project `CMakeLists.txt` file:

```cmake
include(FetchContent)

cmake_minimum_required(VERSION 3.23.2)

project(<Your Project Name> CXX)

FetchContent_Declare(
  HttpClient
  GIT_REPOSITORY https://github.com/WilsonOh/CPP_HTTP_Client.git
  GIT_TAG main
)

FetchContent_MakeAvailable(HttpClient)

add_executable(${PROJECT_NAME} <Your Source Files>...)

target_link_libraries(${PROJECT_NAME} PRIVATE HttpClient)
```

### The manual way
You can also `git clone` this repo and simply include all the source files under `src/` for complilation

## More examples

### Checking the response
```cpp
#include <HttpClient.hpp>
#include <iostream>

int main() {
  HttpClient client{"https://jsonplaceholder.typicode.com"};
  auto res = client.get("/todos/1");
  if (res.statuscode != 200) {
    ...
  }
  if (res.headers["Content-Type"] != "application/json") {
    ...
  }
  std::cout << res.body << '\n';
}

```

### Adding headers

```cpp
#include "HttpClient.hpp"
#include <iostream>

int main() {
  HttpClient client{"https://jsonplaceholder.typicode.com"};
  auto res = client.get("/todos/1", {{"Accept", "application/json"}});
  std::cout << res.body << '\n';
}

```

### Sending a request body

```cpp
#include "HttpClient.hpp"
#include <iostream>

int main() {
  HttpClient client{"https://jsonplaceholder.typicode.com"};
  auto res = client.post("/posts", R"({
    title: 'foo',
    body: 'bar',
    userId: 1,
  })");
  std::cout << res.body << '\n';
}

```
### Sending a request body with headers
```cpp
#include "HttpClient.hpp"
#include <iostream>

int main() {
  HttpClient client{"https://jsonplaceholder.typicode.com"};
  auto res = client.post("/posts", R"({
    title: 'foo',
    body: 'bar',
    userId: 1,
  })",
  {{"Content-type", "application/json; charset=UTF-8"}}
  );
  std::cout << res.body << '\n';
}

```
