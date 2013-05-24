OpenSSLCrypto
=============

Julia interface to crypto functions from OpenSSL

gen/generate.jl generates the wrapper using Clang.jl

src/crpyto_* files are the generated files
src/Crypto.jl and OpenSSL.jl includes the generated files

USAGE
=====
- The following high level functions are available

```hmacsha256_digest(s::String, k::Union(String, Vector{Uint8})) -> Vector{Uint8}``` returns a 32 byte HMACSHA256 digest for the given data and key
```hmacsha1_digest(s::String, k::Union(String, Vector{Uint8})) -> Vector{Uint8}```  returns a 20 byte HMACSHA1 digest for given data and key
```md5(s::String) -> Vector{Uint8}``` is a regular 16 byte MD5 digest of the string
```md5(s::IO) -> Vector{Uint8}``` same as md5 above, except that it processes the IOStream  or IOBuffer in 64K chunks

- For other crypto functions, please refer to the EVP* functions of openssl. ```man EVP_DigestInit``` should bring up the man page
  for EVP* higher level functions provided by OpenSSL crypto.










