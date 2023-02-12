cmake_minimum_required(VERSION 3.19.0 FATAL_ERROR)
project(TOTP VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#set(CMAKE_CXX_CLANG_TIDY clang-tidy;
#  -checks=*
#  )

add_compile_options(-fdiagnostics-color=always)

set(CMAKE_BUILD_TYPE Release) # Debug

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${PROJECT_BINARY_DIR}")
  message(FATAL_ERROR "In-source builds are not supported. Please create a new directory (e.g. 'Builds') and run CMake from there")
endif ()

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include_directories(${PROJECT_SOURCE_DIR})

add_custom_target(__prebuild__ ALL
  COMMAND ${CMAKE_COMMAND} -E create_symlink "${PROJECT_BINARY_DIR}/compile_commands.json" "${PROJECT_SOURCE_DIR}/compile_commands.json"
  )

add_library(otp)
target_sources(otp PRIVATE
  otp.cpp otp.h
  otpauthuri.cpp otpauthuri.h
  )
target_link_libraries(otp PUBLIC -lsodium)
set_target_properties(otp PROPERTIES PUBLIC_HEADER otp.h)
install(TARGETS otp PUBLIC_HEADER)

add_executable(totp)
target_sources(totp PRIVATE main.cpp)
target_link_libraries(totp PRIVATE otp)

# vim:fenc=utf-8 et sw=2:
