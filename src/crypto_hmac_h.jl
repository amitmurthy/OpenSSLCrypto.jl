# Julia wrapper for header: /usr/include/openssl/hmac.h
# Automatically generated using Clang.jl wrap_c, version 0.0.0

@c None HMAC_CTX_init (Ptr{HMAC_CTX},) libcrypto
@c None HMAC_CTX_cleanup (Ptr{HMAC_CTX},) libcrypto
@c Int32 HMAC_Init (Ptr{HMAC_CTX}, Ptr{None}, Int32, Ptr{EVP_MD}) libcrypto
@c Int32 HMAC_Init_ex (Ptr{HMAC_CTX}, Ptr{None}, Int32, Ptr{EVP_MD}, Ptr{ENGINE}) libcrypto
@c Int32 HMAC_Update (Ptr{HMAC_CTX}, Ptr{Uint8}, size_t) libcrypto
@c Int32 HMAC_Final (Ptr{HMAC_CTX}, Ptr{Uint8}, Ptr{Uint32}) libcrypto
@c Ptr{Uint8} HMAC (Ptr{EVP_MD}, Ptr{None}, Int32, Ptr{Uint8}, size_t, Ptr{Uint8}, Ptr{Uint32}) libcrypto
@c Int32 HMAC_CTX_copy (Ptr{HMAC_CTX}, Ptr{HMAC_CTX}) libcrypto
@c None HMAC_CTX_set_flags (Ptr{HMAC_CTX}, Uint32) libcrypto

