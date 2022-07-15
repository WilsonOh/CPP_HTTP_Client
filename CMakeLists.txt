cmake_minimum_required(VERSION 3.23.2)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

project(HttpClient)

function(add_headers VAR)
  set(headers ${${VAR}})
  foreach (header ${ARGN})
    set(headers ${headers} include/${header})
  endforeach()
  set(${VAR} ${headers} PARENT_SCOPE)
endfunction()

function(add_sources VAR)
  set(headers ${${VAR}})
  foreach (header ${ARGN})
    set(headers ${headers} src/${header})
  endforeach()
  set(${VAR} ${headers} PARENT_SCOPE)
endfunction()

add_headers(HEADERS HttpClient.hpp strutil.hpp Url.hpp)

add_sources(SOURCES HttpClient.cpp Url.cpp)

add_library(${PROJECT_NAME} ${HEADERS} ${SOURCES} README.md)

set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)

target_link_libraries(${PROJECT_NAME} -lfmt -lssl -lcrypto)

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wpedantic)

target_include_directories(${PROJECT_NAME} PUBLIC include src)
