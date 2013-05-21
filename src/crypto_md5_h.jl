# Julia wrapper for header: /usr/include/openssl/md5.h
# Automatically generated using Clang.jl wrap_c, version 0.0.0

@c Int32 MD5_Init (Ptr{MD5_CTX},) libcrypto
@c Int32 MD5_Update (Ptr{MD5_CTX}, Ptr{None}, size_t) libcrypto
@c Int32 MD5_Final (Ptr{Uint8}, Ptr{MD5_CTX}) libcrypto
@c Ptr{Uint8} MD5 (Ptr{Uint8}, size_t, Ptr{Uint8}) libcrypto
@c None MD5_Transform (Ptr{MD5_CTX}, Ptr{Uint8}) libcrypto

