#CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(server_project C)
#Set C standard if needed (optional)
set(CMAKE_C_STANDARD 11)
#Define the executable
add_executable(server server.c)
#Find system OpenSSL if available
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
	target_link_libraries(server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
else()
#Fallback to local OpenSSL
target_include_directories(server PRIVATE
	${CMAKE_SOURCE_DIR}/openssl-3.5.2/include
)
if(APPLE)
target_link_libraries(server PRIVATE
	${CMAKE_SOURCE_DIR}/openssl-3.5.2/libssl.dylib
	${CMAKE_SOURCE_DIR}/openssl-3.5.2/libcrypto.dylib
)
elseif(UNIX AND NOT APPLE)
target_link_libraries(server PRIVATE
	${CMAKE_SOURCE_DIR}/openssl-3.5.2/libssl.so
	${CMAKE_SOURCE_DIR}/openssl-3.5.2/libcrypto.so
)
else()
message(FATAL_ERROR "Platform not supported")
endif()
endif()
#Add debug symbols (equivalent to -g3)
target_compile_options(server PRIVATE -g3 -O3)
#Define HAVE_OPENSSL preprocessor macro (equivalent to -DHAVE_OPENSSL)
target_compile_definitions(server PRIVATE HAVE_OPENSSL)
