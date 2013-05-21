# Julia wrapper for header: /usr/include/openssl/evp.h
# Automatically generated using Clang.jl wrap_c, version 0.0.0

@c Int32 EVP_MD_type (Ptr{EVP_MD},) libcrypto
@c Int32 EVP_MD_pkey_type (Ptr{EVP_MD},) libcrypto
@c Int32 EVP_MD_size (Ptr{EVP_MD},) libcrypto
@c Int32 EVP_MD_block_size (Ptr{EVP_MD},) libcrypto
@c Uint32 EVP_MD_flags (Ptr{EVP_MD},) libcrypto
@c Ptr{EVP_MD} EVP_MD_CTX_md (Ptr{EVP_MD_CTX},) libcrypto
@c Int32 EVP_CIPHER_nid (Ptr{EVP_CIPHER},) libcrypto
@c Int32 EVP_CIPHER_block_size (Ptr{EVP_CIPHER},) libcrypto
@c Int32 EVP_CIPHER_key_length (Ptr{EVP_CIPHER},) libcrypto
@c Int32 EVP_CIPHER_iv_length (Ptr{EVP_CIPHER},) libcrypto
@c Uint32 EVP_CIPHER_flags (Ptr{EVP_CIPHER},) libcrypto
@c Ptr{EVP_CIPHER} EVP_CIPHER_CTX_cipher (Ptr{EVP_CIPHER_CTX},) libcrypto
@c Int32 EVP_CIPHER_CTX_nid (Ptr{EVP_CIPHER_CTX},) libcrypto
@c Int32 EVP_CIPHER_CTX_block_size (Ptr{EVP_CIPHER_CTX},) libcrypto
@c Int32 EVP_CIPHER_CTX_key_length (Ptr{EVP_CIPHER_CTX},) libcrypto
@c Int32 EVP_CIPHER_CTX_iv_length (Ptr{EVP_CIPHER_CTX},) libcrypto
@c Int32 EVP_CIPHER_CTX_copy (Ptr{EVP_CIPHER_CTX}, Ptr{EVP_CIPHER_CTX}) libcrypto
@c Ptr{None} EVP_CIPHER_CTX_get_app_data (Ptr{EVP_CIPHER_CTX},) libcrypto
@c None EVP_CIPHER_CTX_set_app_data (Ptr{EVP_CIPHER_CTX}, Ptr{None}) libcrypto
@c Uint32 EVP_CIPHER_CTX_flags (Ptr{EVP_CIPHER_CTX},) libcrypto
@c Int32 EVP_Cipher (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Uint8}, Uint32) libcrypto
@c None EVP_MD_CTX_init (Ptr{EVP_MD_CTX},) libcrypto
@c Int32 EVP_MD_CTX_cleanup (Ptr{EVP_MD_CTX},) libcrypto
@c Ptr{EVP_MD_CTX} EVP_MD_CTX_create () libcrypto
@c None EVP_MD_CTX_destroy (Ptr{EVP_MD_CTX},) libcrypto
@c Int32 EVP_MD_CTX_copy_ex (Ptr{EVP_MD_CTX}, Ptr{EVP_MD_CTX}) libcrypto
@c None EVP_MD_CTX_set_flags (Ptr{EVP_MD_CTX}, Int32) libcrypto
@c None EVP_MD_CTX_clear_flags (Ptr{EVP_MD_CTX}, Int32) libcrypto
@c Int32 EVP_MD_CTX_test_flags (Ptr{EVP_MD_CTX}, Int32) libcrypto
@c Int32 EVP_DigestInit_ex (Ptr{EVP_MD_CTX}, Ptr{EVP_MD}, Ptr{ENGINE}) libcrypto
@c Int32 EVP_DigestUpdate (Ptr{EVP_MD_CTX}, Ptr{None}, size_t) libcrypto
@c Int32 EVP_DigestFinal_ex (Ptr{EVP_MD_CTX}, Ptr{Uint8}, Ptr{Uint32}) libcrypto
@c Int32 EVP_Digest (Ptr{None}, size_t, Ptr{Uint8}, Ptr{Uint32}, Ptr{EVP_MD}, Ptr{ENGINE}) libcrypto
@c Int32 EVP_MD_CTX_copy (Ptr{EVP_MD_CTX}, Ptr{EVP_MD_CTX}) libcrypto
@c Int32 EVP_DigestInit (Ptr{EVP_MD_CTX}, Ptr{EVP_MD}) libcrypto
@c Int32 EVP_DigestFinal (Ptr{EVP_MD_CTX}, Ptr{Uint8}, Ptr{Uint32}) libcrypto
@c Int32 EVP_read_pw_string (Ptr{Uint8}, Int32, Ptr{Uint8}, Int32) libcrypto
@c Int32 EVP_read_pw_string_min (Ptr{Uint8}, Int32, Int32, Ptr{Uint8}, Int32) libcrypto
@c None EVP_set_pw_prompt (Ptr{Uint8},) libcrypto
@c Ptr{Uint8} EVP_get_pw_prompt () libcrypto
@c Int32 EVP_BytesToKey (Ptr{EVP_CIPHER}, Ptr{EVP_MD}, Ptr{Uint8}, Ptr{Uint8}, Int32, Int32, Ptr{Uint8}, Ptr{Uint8}) libcrypto
@c None EVP_CIPHER_CTX_set_flags (Ptr{EVP_CIPHER_CTX}, Int32) libcrypto
@c None EVP_CIPHER_CTX_clear_flags (Ptr{EVP_CIPHER_CTX}, Int32) libcrypto
@c Int32 EVP_CIPHER_CTX_test_flags (Ptr{EVP_CIPHER_CTX}, Int32) libcrypto
@c Int32 EVP_EncryptInit (Ptr{EVP_CIPHER_CTX}, Ptr{EVP_CIPHER}, Ptr{Uint8}, Ptr{Uint8}) libcrypto
@c Int32 EVP_EncryptInit_ex (Ptr{EVP_CIPHER_CTX}, Ptr{EVP_CIPHER}, Ptr{ENGINE}, Ptr{Uint8}, Ptr{Uint8}) libcrypto
@c Int32 EVP_EncryptUpdate (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Int32}, Ptr{Uint8}, Int32) libcrypto
@c Int32 EVP_EncryptFinal_ex (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Int32}) libcrypto
@c Int32 EVP_EncryptFinal (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Int32}) libcrypto
@c Int32 EVP_DecryptInit (Ptr{EVP_CIPHER_CTX}, Ptr{EVP_CIPHER}, Ptr{Uint8}, Ptr{Uint8}) libcrypto
@c Int32 EVP_DecryptInit_ex (Ptr{EVP_CIPHER_CTX}, Ptr{EVP_CIPHER}, Ptr{ENGINE}, Ptr{Uint8}, Ptr{Uint8}) libcrypto
@c Int32 EVP_DecryptUpdate (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Int32}, Ptr{Uint8}, Int32) libcrypto
@c Int32 EVP_DecryptFinal (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Int32}) libcrypto
@c Int32 EVP_DecryptFinal_ex (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Int32}) libcrypto
@c Int32 EVP_CipherInit (Ptr{EVP_CIPHER_CTX}, Ptr{EVP_CIPHER}, Ptr{Uint8}, Ptr{Uint8}, Int32) libcrypto
@c Int32 EVP_CipherInit_ex (Ptr{EVP_CIPHER_CTX}, Ptr{EVP_CIPHER}, Ptr{ENGINE}, Ptr{Uint8}, Ptr{Uint8}, Int32) libcrypto
@c Int32 EVP_CipherUpdate (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Int32}, Ptr{Uint8}, Int32) libcrypto
@c Int32 EVP_CipherFinal (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Int32}) libcrypto
@c Int32 EVP_CipherFinal_ex (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Int32}) libcrypto
@c Int32 EVP_SignFinal (Ptr{EVP_MD_CTX}, Ptr{Uint8}, Ptr{Uint32}, Ptr{EVP_PKEY}) libcrypto
@c Int32 EVP_VerifyFinal (Ptr{EVP_MD_CTX}, Ptr{Uint8}, Uint32, Ptr{EVP_PKEY}) libcrypto
@c Int32 EVP_DigestSignInit (Ptr{EVP_MD_CTX}, Ptr{Ptr{EVP_PKEY_CTX}}, Ptr{EVP_MD}, Ptr{ENGINE}, Ptr{EVP_PKEY}) libcrypto
@c Int32 EVP_DigestSignFinal (Ptr{EVP_MD_CTX}, Ptr{Uint8}, Ptr{size_t}) libcrypto
@c Int32 EVP_DigestVerifyInit (Ptr{EVP_MD_CTX}, Ptr{Ptr{EVP_PKEY_CTX}}, Ptr{EVP_MD}, Ptr{ENGINE}, Ptr{EVP_PKEY}) libcrypto
@c Int32 EVP_DigestVerifyFinal (Ptr{EVP_MD_CTX}, Ptr{Uint8}, size_t) libcrypto
@c Int32 EVP_OpenInit (Ptr{EVP_CIPHER_CTX}, Ptr{EVP_CIPHER}, Ptr{Uint8}, Int32, Ptr{Uint8}, Ptr{EVP_PKEY}) libcrypto
@c Int32 EVP_OpenFinal (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Int32}) libcrypto
@c Int32 EVP_SealInit (Ptr{EVP_CIPHER_CTX}, Ptr{EVP_CIPHER}, Ptr{Ptr{Uint8}}, Ptr{Int32}, Ptr{Uint8}, Ptr{Ptr{EVP_PKEY}}, Int32) libcrypto
@c Int32 EVP_SealFinal (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Ptr{Int32}) libcrypto
@c None EVP_EncodeInit (Ptr{EVP_ENCODE_CTX},) libcrypto
@c None EVP_EncodeUpdate (Ptr{EVP_ENCODE_CTX}, Ptr{Uint8}, Ptr{Int32}, Ptr{Uint8}, Int32) libcrypto
@c None EVP_EncodeFinal (Ptr{EVP_ENCODE_CTX}, Ptr{Uint8}, Ptr{Int32}) libcrypto
@c Int32 EVP_EncodeBlock (Ptr{Uint8}, Ptr{Uint8}, Int32) libcrypto
@c None EVP_DecodeInit (Ptr{EVP_ENCODE_CTX},) libcrypto
@c Int32 EVP_DecodeUpdate (Ptr{EVP_ENCODE_CTX}, Ptr{Uint8}, Ptr{Int32}, Ptr{Uint8}, Int32) libcrypto
@c Int32 EVP_DecodeFinal (Ptr{EVP_ENCODE_CTX}, Ptr{Uint8}, Ptr{Int32}) libcrypto
@c Int32 EVP_DecodeBlock (Ptr{Uint8}, Ptr{Uint8}, Int32) libcrypto
@c None EVP_CIPHER_CTX_init (Ptr{EVP_CIPHER_CTX},) libcrypto
@c Int32 EVP_CIPHER_CTX_cleanup (Ptr{EVP_CIPHER_CTX},) libcrypto
@c Ptr{EVP_CIPHER_CTX} EVP_CIPHER_CTX_new () libcrypto
@c None EVP_CIPHER_CTX_free (Ptr{EVP_CIPHER_CTX},) libcrypto
@c Int32 EVP_CIPHER_CTX_set_key_length (Ptr{EVP_CIPHER_CTX}, Int32) libcrypto
@c Int32 EVP_CIPHER_CTX_set_padding (Ptr{EVP_CIPHER_CTX}, Int32) libcrypto
@c Int32 EVP_CIPHER_CTX_ctrl (Ptr{EVP_CIPHER_CTX}, Int32, Int32, Ptr{None}) libcrypto
@c Int32 EVP_CIPHER_CTX_rand_key (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}) libcrypto
@c Ptr{BIO_METHOD} BIO_f_md () libcrypto
@c Ptr{BIO_METHOD} BIO_f_base64 () libcrypto
@c Ptr{BIO_METHOD} BIO_f_cipher () libcrypto
@c Ptr{BIO_METHOD} BIO_f_reliable () libcrypto
@c None BIO_set_cipher (Ptr{BIO}, Ptr{EVP_CIPHER}, Ptr{Uint8}, Ptr{Uint8}, Int32) libcrypto
@c Ptr{EVP_MD} EVP_md_null () libcrypto
@c Ptr{EVP_MD} EVP_md4 () libcrypto
@c Ptr{EVP_MD} EVP_md5 () libcrypto
@c Ptr{EVP_MD} EVP_sha () libcrypto
@c Ptr{EVP_MD} EVP_sha1 () libcrypto
@c Ptr{EVP_MD} EVP_dss () libcrypto
@c Ptr{EVP_MD} EVP_dss1 () libcrypto
@c Ptr{EVP_MD} EVP_ecdsa () libcrypto
@c Ptr{EVP_MD} EVP_sha224 () libcrypto
@c Ptr{EVP_MD} EVP_sha256 () libcrypto
@c Ptr{EVP_MD} EVP_sha384 () libcrypto
@c Ptr{EVP_MD} EVP_sha512 () libcrypto
@c Ptr{EVP_MD} EVP_ripemd160 () libcrypto
@c Ptr{EVP_MD} EVP_whirlpool () libcrypto
@c Ptr{EVP_CIPHER} EVP_enc_null () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede3 () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede3_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_cfb64 () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_cfb1 () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_cfb8 () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede_cfb64 () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede3_cfb64 () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede3_cfb1 () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede3_cfb8 () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede3_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_des_ede3_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_desx_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_rc4 () libcrypto
@c Ptr{EVP_CIPHER} EVP_rc4_40 () libcrypto
@c Ptr{EVP_CIPHER} EVP_rc4_hmac_md5 () libcrypto
@c Ptr{EVP_CIPHER} EVP_rc2_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_rc2_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_rc2_40_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_rc2_64_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_rc2_cfb64 () libcrypto
@c Ptr{EVP_CIPHER} EVP_rc2_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_bf_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_bf_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_bf_cfb64 () libcrypto
@c Ptr{EVP_CIPHER} EVP_bf_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_cast5_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_cast5_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_cast5_cfb64 () libcrypto
@c Ptr{EVP_CIPHER} EVP_cast5_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_128_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_128_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_128_cfb1 () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_128_cfb8 () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_128_cfb128 () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_128_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_128_ctr () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_128_gcm () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_128_ccm () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_128_xts () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_192_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_192_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_192_cfb1 () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_192_cfb8 () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_192_cfb128 () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_192_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_192_ctr () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_192_gcm () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_192_ccm () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_256_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_256_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_256_cfb1 () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_256_cfb8 () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_256_cfb128 () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_256_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_256_ctr () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_256_gcm () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_256_ccm () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_256_xts () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_128_cbc_hmac_sha1 () libcrypto
@c Ptr{EVP_CIPHER} EVP_aes_256_cbc_hmac_sha1 () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_128_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_128_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_128_cfb1 () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_128_cfb8 () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_128_cfb128 () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_128_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_192_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_192_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_192_cfb1 () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_192_cfb8 () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_192_cfb128 () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_192_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_256_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_256_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_256_cfb1 () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_256_cfb8 () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_256_cfb128 () libcrypto
@c Ptr{EVP_CIPHER} EVP_camellia_256_ofb () libcrypto
@c Ptr{EVP_CIPHER} EVP_seed_ecb () libcrypto
@c Ptr{EVP_CIPHER} EVP_seed_cbc () libcrypto
@c Ptr{EVP_CIPHER} EVP_seed_cfb128 () libcrypto
@c Ptr{EVP_CIPHER} EVP_seed_ofb () libcrypto
@c None OPENSSL_add_all_algorithms_noconf () libcrypto
@c None OPENSSL_add_all_algorithms_conf () libcrypto
@c None OpenSSL_add_all_ciphers () libcrypto
@c None OpenSSL_add_all_digests () libcrypto
@c Int32 EVP_add_cipher (Ptr{EVP_CIPHER},) libcrypto
@c Int32 EVP_add_digest (Ptr{EVP_MD},) libcrypto
@c Ptr{EVP_CIPHER} EVP_get_cipherbyname (Ptr{Uint8},) libcrypto
@c Ptr{EVP_MD} EVP_get_digestbyname (Ptr{Uint8},) libcrypto
@c None EVP_cleanup () libcrypto
@c None EVP_CIPHER_do_all (Ptr{Void}, Ptr{None}) libcrypto
@c None EVP_CIPHER_do_all_sorted (Ptr{Void}, Ptr{None}) libcrypto
@c None EVP_MD_do_all (Ptr{Void}, Ptr{None}) libcrypto
@c None EVP_MD_do_all_sorted (Ptr{Void}, Ptr{None}) libcrypto
@c Int32 EVP_PKEY_decrypt_old (Ptr{Uint8}, Ptr{Uint8}, Int32, Ptr{EVP_PKEY}) libcrypto
@c Int32 EVP_PKEY_encrypt_old (Ptr{Uint8}, Ptr{Uint8}, Int32, Ptr{EVP_PKEY}) libcrypto
@c Int32 EVP_PKEY_type (Int32,) libcrypto
@c Int32 EVP_PKEY_id (Ptr{EVP_PKEY},) libcrypto
@c Int32 EVP_PKEY_base_id (Ptr{EVP_PKEY},) libcrypto
@c Int32 EVP_PKEY_bits (Ptr{EVP_PKEY},) libcrypto
@c Int32 EVP_PKEY_size (Ptr{EVP_PKEY},) libcrypto
@c Int32 EVP_PKEY_set_type (Ptr{EVP_PKEY}, Int32) libcrypto
@c Int32 EVP_PKEY_set_type_str (Ptr{EVP_PKEY}, Ptr{Uint8}, Int32) libcrypto
@c Int32 EVP_PKEY_assign (Ptr{EVP_PKEY}, Int32, Ptr{None}) libcrypto
@c Ptr{None} EVP_PKEY_get0 (Ptr{EVP_PKEY},) libcrypto
@c Int32 EVP_PKEY_set1_RSA (Ptr{EVP_PKEY}, Ptr{Void}) libcrypto
@c Ptr{Void} EVP_PKEY_get1_RSA (Ptr{EVP_PKEY},) libcrypto
@c Int32 EVP_PKEY_set1_DSA (Ptr{EVP_PKEY}, Ptr{Void}) libcrypto
@c Ptr{Void} EVP_PKEY_get1_DSA (Ptr{EVP_PKEY},) libcrypto
@c Int32 EVP_PKEY_set1_DH (Ptr{EVP_PKEY}, Ptr{Void}) libcrypto
@c Ptr{Void} EVP_PKEY_get1_DH (Ptr{EVP_PKEY},) libcrypto
@c Int32 EVP_PKEY_set1_EC_KEY (Ptr{EVP_PKEY}, Ptr{Void}) libcrypto
@c Ptr{Void} EVP_PKEY_get1_EC_KEY (Ptr{EVP_PKEY},) libcrypto
@c Ptr{EVP_PKEY} EVP_PKEY_new () libcrypto
@c None EVP_PKEY_free (Ptr{EVP_PKEY},) libcrypto
@c Ptr{EVP_PKEY} d2i_PublicKey (Int32, Ptr{Ptr{EVP_PKEY}}, Ptr{Ptr{Uint8}}, Int32) libcrypto
@c Int32 i2d_PublicKey (Ptr{EVP_PKEY}, Ptr{Ptr{Uint8}}) libcrypto
@c Ptr{EVP_PKEY} d2i_PrivateKey (Int32, Ptr{Ptr{EVP_PKEY}}, Ptr{Ptr{Uint8}}, Int32) libcrypto
@c Ptr{EVP_PKEY} d2i_AutoPrivateKey (Ptr{Ptr{EVP_PKEY}}, Ptr{Ptr{Uint8}}, Int32) libcrypto
@c Int32 i2d_PrivateKey (Ptr{EVP_PKEY}, Ptr{Ptr{Uint8}}) libcrypto
@c Int32 EVP_PKEY_copy_parameters (Ptr{EVP_PKEY}, Ptr{EVP_PKEY}) libcrypto
@c Int32 EVP_PKEY_missing_parameters (Ptr{EVP_PKEY},) libcrypto
@c Int32 EVP_PKEY_save_parameters (Ptr{EVP_PKEY}, Int32) libcrypto
@c Int32 EVP_PKEY_cmp_parameters (Ptr{EVP_PKEY}, Ptr{EVP_PKEY}) libcrypto
@c Int32 EVP_PKEY_cmp (Ptr{EVP_PKEY}, Ptr{EVP_PKEY}) libcrypto
@c Int32 EVP_PKEY_print_public (Ptr{BIO}, Ptr{EVP_PKEY}, Int32, Ptr{ASN1_PCTX}) libcrypto
@c Int32 EVP_PKEY_print_private (Ptr{BIO}, Ptr{EVP_PKEY}, Int32, Ptr{ASN1_PCTX}) libcrypto
@c Int32 EVP_PKEY_print_params (Ptr{BIO}, Ptr{EVP_PKEY}, Int32, Ptr{ASN1_PCTX}) libcrypto
@c Int32 EVP_PKEY_get_default_digest_nid (Ptr{EVP_PKEY}, Ptr{Int32}) libcrypto
@c Int32 EVP_CIPHER_type (Ptr{EVP_CIPHER},) libcrypto
@c Int32 EVP_CIPHER_param_to_asn1 (Ptr{EVP_CIPHER_CTX}, Ptr{ASN1_TYPE}) libcrypto
@c Int32 EVP_CIPHER_asn1_to_param (Ptr{EVP_CIPHER_CTX}, Ptr{ASN1_TYPE}) libcrypto
@c Int32 EVP_CIPHER_set_asn1_iv (Ptr{EVP_CIPHER_CTX}, Ptr{ASN1_TYPE}) libcrypto
@c Int32 EVP_CIPHER_get_asn1_iv (Ptr{EVP_CIPHER_CTX}, Ptr{ASN1_TYPE}) libcrypto
@c Int32 PKCS5_PBE_keyivgen (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Int32, Ptr{ASN1_TYPE}, Ptr{EVP_CIPHER}, Ptr{EVP_MD}, Int32) libcrypto
@c Int32 PKCS5_PBKDF2_HMAC_SHA1 (Ptr{Uint8}, Int32, Ptr{Uint8}, Int32, Int32, Int32, Ptr{Uint8}) libcrypto
@c Int32 PKCS5_PBKDF2_HMAC (Ptr{Uint8}, Int32, Ptr{Uint8}, Int32, Int32, Ptr{EVP_MD}, Int32, Ptr{Uint8}) libcrypto
@c Int32 PKCS5_v2_PBE_keyivgen (Ptr{EVP_CIPHER_CTX}, Ptr{Uint8}, Int32, Ptr{ASN1_TYPE}, Ptr{EVP_CIPHER}, Ptr{EVP_MD}, Int32) libcrypto
@c None PKCS5_PBE_add () libcrypto
@c Int32 EVP_PBE_CipherInit (Ptr{ASN1_OBJECT}, Ptr{Uint8}, Int32, Ptr{ASN1_TYPE}, Ptr{EVP_CIPHER_CTX}, Int32) libcrypto
@c Int32 EVP_PBE_alg_add_type (Int32, Int32, Int32, Int32, Ptr{EVP_PBE_KEYGEN}) libcrypto
@c Int32 EVP_PBE_alg_add (Int32, Ptr{EVP_CIPHER}, Ptr{EVP_MD}, Ptr{EVP_PBE_KEYGEN}) libcrypto
@c Int32 EVP_PBE_find (Int32, Int32, Ptr{Int32}, Ptr{Int32}, Ptr{Ptr{EVP_PBE_KEYGEN}}) libcrypto
@c None EVP_PBE_cleanup () libcrypto
@c Int32 EVP_PKEY_asn1_get_count () libcrypto
@c Ptr{EVP_PKEY_ASN1_METHOD} EVP_PKEY_asn1_get0 (Int32,) libcrypto
@c Ptr{EVP_PKEY_ASN1_METHOD} EVP_PKEY_asn1_find (Ptr{Ptr{ENGINE}}, Int32) libcrypto
@c Ptr{EVP_PKEY_ASN1_METHOD} EVP_PKEY_asn1_find_str (Ptr{Ptr{ENGINE}}, Ptr{Uint8}, Int32) libcrypto
@c Int32 EVP_PKEY_asn1_add0 (Ptr{EVP_PKEY_ASN1_METHOD},) libcrypto
@c Int32 EVP_PKEY_asn1_add_alias (Int32, Int32) libcrypto
@c Int32 EVP_PKEY_asn1_get0_info (Ptr{Int32}, Ptr{Int32}, Ptr{Int32}, Ptr{Ptr{Uint8}}, Ptr{Ptr{Uint8}}, Ptr{EVP_PKEY_ASN1_METHOD}) libcrypto
@c Ptr{EVP_PKEY_ASN1_METHOD} EVP_PKEY_get0_asn1 (Ptr{EVP_PKEY},) libcrypto
@c Ptr{EVP_PKEY_ASN1_METHOD} EVP_PKEY_asn1_new (Int32, Int32, Ptr{Uint8}, Ptr{Uint8}) libcrypto
@c None EVP_PKEY_asn1_copy (Ptr{EVP_PKEY_ASN1_METHOD}, Ptr{EVP_PKEY_ASN1_METHOD}) libcrypto
@c None EVP_PKEY_asn1_free (Ptr{EVP_PKEY_ASN1_METHOD},) libcrypto
@c None EVP_PKEY_asn1_set_public (Ptr{EVP_PKEY_ASN1_METHOD}, Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_asn1_set_private (Ptr{EVP_PKEY_ASN1_METHOD}, Ptr{Void}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_asn1_set_param (Ptr{EVP_PKEY_ASN1_METHOD}, Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_asn1_set_free (Ptr{EVP_PKEY_ASN1_METHOD}, Ptr{Void}) libcrypto
@c None EVP_PKEY_asn1_set_ctrl (Ptr{EVP_PKEY_ASN1_METHOD}, Ptr{Void}) libcrypto
@c Ptr{EVP_PKEY_METHOD} EVP_PKEY_meth_find (Int32,) libcrypto
@c Ptr{EVP_PKEY_METHOD} EVP_PKEY_meth_new (Int32, Int32) libcrypto
@c None EVP_PKEY_meth_get0_info (Ptr{Int32}, Ptr{Int32}, Ptr{EVP_PKEY_METHOD}) libcrypto
@c None EVP_PKEY_meth_copy (Ptr{EVP_PKEY_METHOD}, Ptr{EVP_PKEY_METHOD}) libcrypto
@c None EVP_PKEY_meth_free (Ptr{EVP_PKEY_METHOD},) libcrypto
@c Int32 EVP_PKEY_meth_add0 (Ptr{EVP_PKEY_METHOD},) libcrypto
@c Ptr{EVP_PKEY_CTX} EVP_PKEY_CTX_new (Ptr{EVP_PKEY}, Ptr{ENGINE}) libcrypto
@c Ptr{EVP_PKEY_CTX} EVP_PKEY_CTX_new_id (Int32, Ptr{ENGINE}) libcrypto
@c Ptr{EVP_PKEY_CTX} EVP_PKEY_CTX_dup (Ptr{EVP_PKEY_CTX},) libcrypto
@c None EVP_PKEY_CTX_free (Ptr{EVP_PKEY_CTX},) libcrypto
@c Int32 EVP_PKEY_CTX_ctrl (Ptr{EVP_PKEY_CTX}, Int32, Int32, Int32, Int32, Ptr{None}) libcrypto
@c Int32 EVP_PKEY_CTX_ctrl_str (Ptr{EVP_PKEY_CTX}, Ptr{Uint8}, Ptr{Uint8}) libcrypto
@c Int32 EVP_PKEY_CTX_get_operation (Ptr{EVP_PKEY_CTX},) libcrypto
@c None EVP_PKEY_CTX_set0_keygen_info (Ptr{EVP_PKEY_CTX}, Ptr{Int32}, Int32) libcrypto
@c Ptr{EVP_PKEY} EVP_PKEY_new_mac_key (Int32, Ptr{ENGINE}, Ptr{Uint8}, Int32) libcrypto
@c None EVP_PKEY_CTX_set_data (Ptr{EVP_PKEY_CTX}, Ptr{None}) libcrypto
@c Ptr{None} EVP_PKEY_CTX_get_data (Ptr{EVP_PKEY_CTX},) libcrypto
@c Ptr{EVP_PKEY} EVP_PKEY_CTX_get0_pkey (Ptr{EVP_PKEY_CTX},) libcrypto
@c Ptr{EVP_PKEY} EVP_PKEY_CTX_get0_peerkey (Ptr{EVP_PKEY_CTX},) libcrypto
@c None EVP_PKEY_CTX_set_app_data (Ptr{EVP_PKEY_CTX}, Ptr{None}) libcrypto
@c Ptr{None} EVP_PKEY_CTX_get_app_data (Ptr{EVP_PKEY_CTX},) libcrypto
@c Int32 EVP_PKEY_sign_init (Ptr{EVP_PKEY_CTX},) libcrypto
@c Int32 EVP_PKEY_sign (Ptr{EVP_PKEY_CTX}, Ptr{Uint8}, Ptr{size_t}, Ptr{Uint8}, size_t) libcrypto
@c Int32 EVP_PKEY_verify_init (Ptr{EVP_PKEY_CTX},) libcrypto
@c Int32 EVP_PKEY_verify (Ptr{EVP_PKEY_CTX}, Ptr{Uint8}, size_t, Ptr{Uint8}, size_t) libcrypto
@c Int32 EVP_PKEY_verify_recover_init (Ptr{EVP_PKEY_CTX},) libcrypto
@c Int32 EVP_PKEY_verify_recover (Ptr{EVP_PKEY_CTX}, Ptr{Uint8}, Ptr{size_t}, Ptr{Uint8}, size_t) libcrypto
@c Int32 EVP_PKEY_encrypt_init (Ptr{EVP_PKEY_CTX},) libcrypto
@c Int32 EVP_PKEY_encrypt (Ptr{EVP_PKEY_CTX}, Ptr{Uint8}, Ptr{size_t}, Ptr{Uint8}, size_t) libcrypto
@c Int32 EVP_PKEY_decrypt_init (Ptr{EVP_PKEY_CTX},) libcrypto
@c Int32 EVP_PKEY_decrypt (Ptr{EVP_PKEY_CTX}, Ptr{Uint8}, Ptr{size_t}, Ptr{Uint8}, size_t) libcrypto
@c Int32 EVP_PKEY_derive_init (Ptr{EVP_PKEY_CTX},) libcrypto
@c Int32 EVP_PKEY_derive_set_peer (Ptr{EVP_PKEY_CTX}, Ptr{EVP_PKEY}) libcrypto
@c Int32 EVP_PKEY_derive (Ptr{EVP_PKEY_CTX}, Ptr{Uint8}, Ptr{size_t}) libcrypto
@c Int32 EVP_PKEY_paramgen_init (Ptr{EVP_PKEY_CTX},) libcrypto
@c Int32 EVP_PKEY_paramgen (Ptr{EVP_PKEY_CTX}, Ptr{Ptr{EVP_PKEY}}) libcrypto
@c Int32 EVP_PKEY_keygen_init (Ptr{EVP_PKEY_CTX},) libcrypto
@c Int32 EVP_PKEY_keygen (Ptr{EVP_PKEY_CTX}, Ptr{Ptr{EVP_PKEY}}) libcrypto
@c None EVP_PKEY_CTX_set_cb (Ptr{EVP_PKEY_CTX}, Ptr{EVP_PKEY_gen_cb}) libcrypto
@c Ptr{EVP_PKEY_gen_cb} EVP_PKEY_CTX_get_cb (Ptr{EVP_PKEY_CTX},) libcrypto
@c Int32 EVP_PKEY_CTX_get_keygen_info (Ptr{EVP_PKEY_CTX}, Int32) libcrypto
@c None EVP_PKEY_meth_set_init (Ptr{EVP_PKEY_METHOD}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_copy (Ptr{EVP_PKEY_METHOD}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_cleanup (Ptr{EVP_PKEY_METHOD}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_paramgen (Ptr{EVP_PKEY_METHOD}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_keygen (Ptr{EVP_PKEY_METHOD}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_sign (Ptr{EVP_PKEY_METHOD}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_verify (Ptr{EVP_PKEY_METHOD}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_verify_recover (Ptr{EVP_PKEY_METHOD}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_signctx (Ptr{EVP_PKEY_METHOD}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_verifyctx (Ptr{EVP_PKEY_METHOD}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_encrypt (Ptr{EVP_PKEY_METHOD}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_decrypt (Ptr{EVP_PKEY_METHOD}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_derive (Ptr{EVP_PKEY_METHOD}, Ptr{Void}, Ptr{Void}) libcrypto
@c None EVP_PKEY_meth_set_ctrl (Ptr{EVP_PKEY_METHOD}, Ptr{Void}, Ptr{Void}) libcrypto
@c None ERR_load_EVP_strings () libcrypto

