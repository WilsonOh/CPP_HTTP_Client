cmake_minimum_required(VERSION 3.23.2)

project(HttpClient)

option(ENABLE_LOGGING "Enable Logging" OFF)

add_subdirectory(spdlog)

function(add_headers VAR)
  set(headers ${${VAR}})
  foreach(header ${ARGN})
    set(headers ${headers} include/${header})
  endforeach()
  set(${VAR} ${headers})
endfunction()

find_package(
  OpenSSL
  COMPONENTS SSL Crypto
  REQUIRED)

add_headers(HEADERS HttpClient.hpp strutil.hpp Url.hpp)

add_library(${PROJECT_NAME} ${HEADERS} src/HttpClient.cpp src/Url.cpp README.md)

target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto
                      spdlog::spdlog)

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wpedantic)

target_include_directories(${PROJECT_NAME} PUBLIC include src)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)

if(ENABLE_LOGGING)
  target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_LOGGING)
endif()
