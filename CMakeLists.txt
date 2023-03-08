cmake_minimum_required(VERSION 3.0)

project(HelloWorld)

set(CMAKE_CXX_STANDARD 14)

include_directories(
    ${RAPIDJSON_INCLUDE_DIR}
    ${SECP256K1_INCLUDE_DIR}
    /opt/homebrew/opt/openssl@3/include
)

link_directories(/opt/homebrew/opt/openssl@3/lib )


add_executable(main main.cpp hash-library/keccak.cpp)
target_link_libraries(main
  libsecp256k1.a crypto
)