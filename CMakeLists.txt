cmake_minimum_required (VERSION 2.8)
project (nginx-jwt C)

set(JANSSON_BUILD_DOCS OFF)
add_subdirectory(jansson)
add_subdirectory(libjwt)

