# CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(server_project C)

# Set C standard if needed (optional)
set(CMAKE_C_STANDARD 11)

# Define the executable
add_executable(server server.c)

# Include directories (equivalent to -I)
target_include_directories(server PRIVATE
    ${CMAKE_SOURCE_DIR}/openssl-3.5.2/include
)

# Link against the OpenSSL libraries (equivalent to linking .dylib files)
target_link_libraries(server PRIVATE
    ${CMAKE_SOURCE_DIR}/openssl-3.5.2/libssl.dylib
    ${CMAKE_SOURCE_DIR}/openssl-3.5.2/libcrypto.dylib
)

# Add debug symbols (equivalent to -g3)
target_compile_options(server PRIVATE -g3 -O3)

# Define HAVE_OPENSSL preprocessor macro (equivalent to -DHAVE_OPENSSL)
target_compile_definitions(server PRIVATE HAVE_OPENSSL)
