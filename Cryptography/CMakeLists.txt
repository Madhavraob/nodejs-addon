cmake_minimum_required(VERSION 3.10)
project(EncryptionDemo)

set(CMAKE_CXX_STANDARD 11)

set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)

find_package(OpenSSL REQUIRED)

link_libraries(ssl)
link_libraries(crypto)

add_executable(EncryptionDemo main.cpp EncryptionModule.cpp EncryptionModule.h Utils/KeyUtils.cpp Utils/KeyUtils.h DecryptionModule.cpp DecryptionModule.h MessageContext.h MessageContext.cpp Utils/IOUtils.cpp Utils/IOUtils.h Utils/NetworkUtils.cpp Utils/NetworkUtils.h SecureComm.cpp SecureComm.h)

target_link_libraries(EncryptionDemo OpenSSL::SSL)