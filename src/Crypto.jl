module Crypto

include("crypto_common_h.jl")

@ctypedef EVP_MD Void
typealias size_t Csize_t

include("crypto_evp_h.jl")
include("crypto_hmac_h.jl")
include("crypto_md5_h.jl")
include("crypto_sha_h.jl")
include("crypto_defines_h.jl")

include("crypto_exports_h.jl")


hmacsha256_digest(s::String, k::Union(String, Array{Uint8,1})) =  hmacsha_digest(s, k, EVP_sha256(), 32)
export hmacsha256_digest

hmacsha1_digest(s::String, k::Union(String, Array{Uint8,1})) = hmacsha_digest(s, k, EVP_sha1(), 20)
export hmacsha1_digest

function hmacsha_digest(s::String, k::Union(String, Array{Uint8,1}), evp, dgst_len)
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

end