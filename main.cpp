#include "Url.hpp"
#include "strutil.hpp"
#include <iostream>
#include <optional>
#include <string>

#include <arpa/inet.h>  // inet_pton
#include <fcntl.h>      // open
#include <netinet/in.h> // sockaddr types, htons
#include <signal.h>
#include <sys/socket.h> // connect, AF_INET
#include <sys/types.h>
#include <unistd.h>

#include "HttpClient.hpp"

int main(void) {
  HttpReponse res = HttpClient::new_client("https://www.comp.nus.edu.sg")
    .get()
    .send();
  std::cout << res.body;
}
