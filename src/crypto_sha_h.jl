# Julia wrapper for header: /usr/include/openssl/sha.h
# Automatically generated using Clang.jl wrap_c, version 0.0.0

@c Int32 SHA_Init (Ptr{SHA_CTX},) libcrypto
@c Int32 SHA_Update (Ptr{SHA_CTX}, Ptr{None}, size_t) libcrypto
@c Int32 SHA_Final (Ptr{Uint8}, Ptr{SHA_CTX}) libcrypto
@c Ptr{Uint8} SHA (Ptr{Uint8}, size_t, Ptr{Uint8}) libcrypto
@c None SHA_Transform (Ptr{SHA_CTX}, Ptr{Uint8}) libcrypto
@c Int32 SHA1_Init (Ptr{SHA_CTX},) libcrypto
@c Int32 SHA1_Update (Ptr{SHA_CTX}, Ptr{None}, size_t) libcrypto
@c Int32 SHA1_Final (Ptr{Uint8}, Ptr{SHA_CTX}) libcrypto
@c Ptr{Uint8} SHA1 (Ptr{Uint8}, size_t, Ptr{Uint8}) libcrypto
@c None SHA1_Transform (Ptr{SHA_CTX}, Ptr{Uint8}) libcrypto
@c Int32 SHA224_Init (Ptr{SHA256_CTX},) libcrypto
@c Int32 SHA224_Update (Ptr{SHA256_CTX}, Ptr{None}, size_t) libcrypto
@c Int32 SHA224_Final (Ptr{Uint8}, Ptr{SHA256_CTX}) libcrypto
@c Ptr{Uint8} SHA224 (Ptr{Uint8}, size_t, Ptr{Uint8}) libcrypto
@c Int32 SHA256_Init (Ptr{SHA256_CTX},) libcrypto
@c Int32 SHA256_Update (Ptr{SHA256_CTX}, Ptr{None}, size_t) libcrypto
@c Int32 SHA256_Final (Ptr{Uint8}, Ptr{SHA256_CTX}) libcrypto
@c Ptr{Uint8} SHA256 (Ptr{Uint8}, size_t, Ptr{Uint8}) libcrypto
@c None SHA256_Transform (Ptr{SHA256_CTX}, Ptr{Uint8}) libcrypto
@c Int32 SHA384_Init (Ptr{SHA512_CTX},) libcrypto
@c Int32 SHA384_Update (Ptr{SHA512_CTX}, Ptr{None}, size_t) libcrypto
@c Int32 SHA384_Final (Ptr{Uint8}, Ptr{SHA512_CTX}) libcrypto
@c Ptr{Uint8} SHA384 (Ptr{Uint8}, size_t, Ptr{Uint8}) libcrypto
@c Int32 SHA512_Init (Ptr{SHA512_CTX},) libcrypto
@c Int32 SHA512_Update (Ptr{SHA512_CTX}, Ptr{None}, size_t) libcrypto
@c Int32 SHA512_Final (Ptr{Uint8}, Ptr{SHA512_CTX}) libcrypto
@c Ptr{Uint8} SHA512 (Ptr{Uint8}, size_t, Ptr{Uint8}) libcrypto
@c None SHA512_Transform (Ptr{SHA512_CTX}, Ptr{Uint8}) libcrypto

