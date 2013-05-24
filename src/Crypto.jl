module Crypto

include("crypto_common_h.jl")

@ctypedef EVP_MD Void
@ctypedef EVP_MD_CTX Void
@ctypedef ENGINE Void

typealias size_t Csize_t

include("crypto_evp_h.jl")
include("crypto_hmac_h.jl")
include("crypto_md5_h.jl")
include("crypto_sha_h.jl")
include("crypto_defines_h.jl")

include("crypto_exports_h.jl")


hmacsha256_digest(s::String, k::Union(String, Vector{Uint8})) =  hmacsha_digest(s, k, EVP_sha256(), 32)
export hmacsha256_digest

hmacsha1_digest(s::String, k::Union(String, Vector{Uint8})) = hmacsha_digest(s, k, EVP_sha1(), 20)
export hmacsha1_digest

function hmacsha_digest(s::String, k::Union(String, Vector{Uint8}), evp, dgst_len)
    if evp == C_NULL error("EVP_sha1() failed!") end

    sig = zeros(Uint8, dgst_len)
    sig_len = zeros(Uint32, 1)
    
    if isa(k, String)
        k = convert(Array{Uint8}, k)
    end

    if HMAC(evp, k, length(k), s, length(s), sig, sig_len) == C_NULL error("HMAC() failed!") end
    if (sig_len[1] != dgst_len) error("Wrong length of signature!") end
    
    return sig
end


function md5(s::String)
    md = zeros(Uint8, 16)
    assert (MD5(s, length(s), md) != C_NULL)
    return md
end

function md5(s::IO)
    evp_md_ctx = EVP_MD_CTX_create()
    assert (evp_md_ctx != C_NULL)

    md = zeros(Uint8, 16)
    try
        evp_md = EVP_md5()
        assert (evp_md != C_NULL)
        
        rc = EVP_DigestInit_ex(evp_md_ctx, evp_md, C_NULL)
        assert(rc == 1)
        
        while (!eof(s))
            b = read(s, Uint8, min(nb_available(s), 65536))    # Read in 64 K chunks....
            
            rc = EVP_DigestUpdate(evp_md_ctx, b, length(b));
            assert(rc == 1)
        end
        
        rc = EVP_DigestFinal_ex(evp_md_ctx, md, C_NULL)
        assert(rc == 1)

    finally
        EVP_MD_CTX_destroy(evp_md_ctx) 
    end

    return md
end


end # Module end

