using Clang.cindex
using Clang.wrap_c

JULIAHOME=EnvHash()["JULIAHOME"]

clang_includes = map(x->joinpath(JULIAHOME, x), [
  "deps/llvm-3.2/build/Release/lib/clang/3.2/include",
  "deps/llvm-3.2/include",
  "deps/llvm-3.2/include",
  "deps/llvm-3.2/build/include/",
  "deps/llvm-3.2/include/"
  ])
clang_extraargs = ["-D", "__STDC_LIMIT_MACROS", "-D", "__STDC_CONSTANT_MACROS"]

wrap_hdrs = map( x-> joinpath("/usr/include/openssl", x), [ "md5.h", "hmac.h", "sha.h", "evp.h" ])

#begin println("$th, $h"); (contains(wrap_hdrs, h) && (th == h)) end 
wc = wrap_c.init(".", "../src/crypto_common_h.jl", clang_includes, clang_extraargs, (th, h) -> false, h -> "libcrypto", h -> "../src/crypto_" * replace(last(split(h, "/")), ".", "_")  * ".jl" )
wc.options.wrap_structs = false

wrap_c.wrap_c_headers(wc, wrap_hdrs)

# generate export statements.....
fe = open("../src/crypto_exports_h.jl", "w+")
println(fe, "#   Generating exports")

gen_files = map( x-> "../src/crypto_" * x * "_h.jl", [ "common", "md5", "hmac", "sha", "evp"  ])

for gf in gen_files
    fc = open(gf, "r")
    genjl = split(readall(fc), "\n")
    close(fc)

    for e in genjl
        m = match(r"^\s*\@c\s+[\w\:\{\}\_]+\s+(\w+)", e)
        if (m != nothing) 
        #    println (m.captures[1])
            @printf fe "export %s\n"  m.captures[1]
        else  
            m = match(r"^\s*\@ctypedef\s+(\w+)", e)
            if (m != nothing) 
            #    println(m.captures[1])
                @printf fe "export %s\n"  m.captures[1]
            else 
                m = match(r"^\s*const\s+(\w+)", e)
                if (m != nothing) 
            #        println(m.captures[1])
                    @printf fe "export %s\n"  m.captures[1]
                end
            end
        end
    end
end

function is_valid_c_macro(s) 
    for pfx in ["MD5", "SHA", "HMAC", "EVP", "NID_"]
        if beginswith(s, pfx) 
            return true
        end
    end
    return false
end

ign_defs = [
    "MD5_LONG",
    "SHA_LONG",
    "SHA_LONG64",
    
    # May have to manualy support the below later....
    "EVP_PKEY_NULL_method",
    "EVP_PKEY_DSA_method",
    "EVP_PKEY_ECDSA_method",
    "EVP_PKEY_RSA_method",
    "EVP_PKEY_RSA_ASN1_OCTET_STRING_method",
    
    # Bug in headers?
    "EVP_PKEY_OP_TYPE_NOGEN"
]





f = open("../src/crypto_defines_h.jl", "w+")
println(f, "#   Generating #define constants")

is_defined_set = Set(String, 0)

for fn in ["md5", "hmac", "sha", "evp"]
    hashdefs = split(readall(`gcc -E -dD -P /usr/include/openssl/$(fn).h`), "\n")
    for e in hashdefs
        m = match(r"^\s*#define\s+(\w+)\s+(.+)", e)
        if (m != nothing)
            if is_valid_c_macro(m.captures[1]) && !contains(ign_defs, m.captures[1]) && !contains(is_defined_set, m.captures[1])
                @printf f "const %-30s = %s\n"  m.captures[1]  m.captures[2]
                @printf fe "export %s\n"  m.captures[1]
                add!(is_defined_set, m.captures[1])
            end
        end
    end
end

close(f)
close(fe)




