gcc -o server -g3 -DHAVE_OPENSSL -I openssl-3.5.2/include/ server.c openssl-3.5.2/libcrypto.dylib openssl-3.5.2/libssl.dylib
