macro c(ret_type, func, arg_types, lib)
  local args_in = Any[ symbol(string('a',x)) for x in 1:length(arg_types.args) ]
  quote
    $(esc(func))($(args_in...)) = ccall( ($(string(func)), $(Expr(:quote, lib)) ), $ret_type, $arg_types, $(args_in...) )
  end
end

macro ctypedef(fake_t,real_t)
  quote
    typealias $fake_t $real_t
  end
end

@ctypedef MD5_CTX Void
@ctypedef HMAC_CTX Void
@ctypedef SHA_CTX Void
@ctypedef SHA256_CTX Void
@ctypedef SHA512_CTX Void
@ctypedef evp_sign_method Void
@ctypedef evp_verify_method Void
@ctypedef EVP_CIPHER_INFO Void
@ctypedef EVP_ENCODE_CTX Void
@ctypedef EVP_PBE_KEYGEN Void
@ctypedef EVP_PKEY_gen_cb Void
