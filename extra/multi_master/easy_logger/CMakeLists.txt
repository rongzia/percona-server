cmake_minimum_required (VERSION 3.10)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/easy_logger/include/)

add_executable(easy_log_test_main test_main.cc)
target_link_libraries(easy_log_test_main  pthread)