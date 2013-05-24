OpenSSLCrypto
=============

Julia interface to crypto functions from OpenSSL.


gen/generate.jl generates the wrapper using Clang.jl

src/crpyto_* files are the generated files
src/Crypto.jl and OpenSSL.jl includes the generated files

## Usage

- Currently functions in openssl/md5.h, openssl/hmac.h, openssl/sha.h and openssl/evp.h have been wrapped

- Please refer to openssl documentation on using them

- The EVP_* family of functions provide higer level functions for other lower level openssl functions.

- ```man EVP_DigestInit``` has information on using them.

- Additionally, the following utility functions have been provided.

```hmacsha256_digest(s::String, k::Union(String, Vector{Uint8})) -> Vector{Uint8}``` returns a 32 byte HMACSHA256 digest for the given data and key

```hmacsha1_digest(s::String, k::Union(String, Vector{Uint8})) -> Vector{Uint8}```  returns a 20 byte HMACSHA1 digest for given data and key

```md5(s::String) -> Vector{Uint8}``` is a regular 16 byte MD5 digest of the string

```md5(s::IO) -> Vector{Uint8}``` same as md5 above, except that it processes the IOStream  or IOBuffer in 64K chunks



  
  
## Example
```
using OpenSSLCrypto.Crypto
sb = bytes2hex(Crypto.hmacsha256_digest("The quick brown fox jumps over the lazy dog", "key"))
assert(sb == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
```

# TODO 
- More utility functions
- More crypto functions exposed
















