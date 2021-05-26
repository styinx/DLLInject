cmake_minimum_required(VERSION 3.17)
project(DLLInject)

set(CMAKE_CXX_STANDARD 14)

include_directories(source)

# Point to the path were the static library is built
link_directories(./cmake-build-debug)

# ---

# Example from source files
add_executable(example examples/example.cpp source/DLLInject.cpp)

# Example with header only
add_executable(example_headeronly examples/example_headeronly.cpp)

# Example with linking
add_executable(example_linked examples/example.cpp)
target_link_libraries(example_linked -ldllinject)

# Build the library
add_library(dllinject STATIC source/DLLInject.cpp)
