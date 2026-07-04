/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2023, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/// @brief Map a V3O_AUTH_PROTO_* value to its OpenSSL digest
/// @return the EVP_MD for the protocol, or NULL if unsupported
const EVP_MD *
v3_auth_md(int auth_proto)
{
    switch (auth_proto) {
    case V3O_AUTH_PROTO_SHA1:   return EVP_sha1();
    case V3O_AUTH_PROTO_SHA224: return EVP_sha224();
    case V3O_AUTH_PROTO_SHA256: return EVP_sha256();
    case V3O_AUTH_PROTO_SHA384: return EVP_sha384();
    case V3O_AUTH_PROTO_SHA512: return EVP_sha512();
    default:                    return NULL;
    }
}

/// @brief MAC truncation length (msgAuthenticationParameters size) for a protocol
/// @return the length in bytes, or -1 if the protocol is unsupported
int
v3_auth_maclen(int auth_proto)
{
    switch (auth_proto) {
    case V3O_AUTH_PROTO_SHA1:   return 12;
    case V3O_AUTH_PROTO_SHA224: return 16;
    case V3O_AUTH_PROTO_SHA256: return 24;
    case V3O_AUTH_PROTO_SHA384: return 32;
    case V3O_AUTH_PROTO_SHA512: return 48;
    default:                    return -1;
    }
}

int
hmac_message(const struct snmpv3info* v3,
             unsigned char* out,
             unsigned out_size,
             unsigned char* msg,
             unsigned msg_len,
             unsigned char* auth_param)
{
    HMAC_CTX* ctx = NULL;
    const EVP_MD* md = v3_auth_md(v3->auth_proto);
    int maclen = v3_auth_maclen(v3->auth_proto);

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned md_len = 0;

    if (!md || maclen < 0) {
        log_error("bad auth protocol");
        errno = EINVAL;
        return -1;
    }
    if (out_size < (unsigned)maclen) {
        log_error("bad hmac output buffer size");
        errno = EINVAL;
        return -1;
    }
    if (auth_param - msg + maclen >= msg_len) {
        log_error("bad auth_param pointer");
        errno = EINVAL;
        return -1;
    }

    ctx = HMAC_CTX_new();
    if (!ctx)
        goto fail;

    if (!HMAC_Init_ex(ctx, v3->authkul, v3->authkul_len, md, NULL))
        goto fail;

    bzero(out, maclen);
    if (!HMAC_Update(ctx, msg, auth_param - msg))
        goto fail;
    if (!HMAC_Update(ctx, out, maclen))
        goto fail;
    if (!HMAC_Update(ctx, auth_param + maclen, msg_len - (auth_param - msg + maclen)))
        goto fail;

    if (!HMAC_Final(ctx, md_value, &md_len))
        goto fail;

    HMAC_CTX_free(ctx);
    memcpy(out, md_value, maclen);

    return 0;

fail:
    ERR_print_errors_fp(stderr);
    HMAC_CTX_free(ctx);
    return -1;
}

/// @brief Encrypt SNMPv3 PDU in-place
/// @param buf Points to the buffer to encrypt
/// @param buf_len Length of the buffer to encrypt
/// @param privp Points to 8 bytes of SNMPv3 privacy parameters that will be initialized during encryption
/// @param v3 SNMPv3 information to use during decryption
/// @return 0 on success, -1 on failure
int
encrypt_in_place(unsigned char *buf, int buf_len, unsigned char *privp, const struct snmpv3info *v3)
{
    EVP_CIPHER_CTX* ctx;
    const EVP_CIPHER *cipher;
    unsigned char *ciphertext;
    int len, ciphertext_len;
    unsigned char ivtemp[16];

    if (RAND_bytes(privp, 8) != 1) {
        return -1;
    }
    *((u_int32_t *)(void*)(ivtemp+0)) = htonl(v3->engine_boots);
    *((u_int32_t *)(void*)(ivtemp+4)) = htonl(v3->engine_time);
    memcpy(ivtemp + 8, privp, 8);

    switch (v3->priv_proto) {
    case V3O_PRIV_PROTO_AES:
        cipher = EVP_aes_128_cfb128();
        break;
    case V3O_PRIV_PROTO_AES256_CISCO:
        cipher = EVP_aes_256_cfb128();
        break;
    default:
        log_error("encrypt_in_place: unrecognized or unsupported privacy algorithm");
        return -1;
        break;
    }

    ciphertext = malloc(buf_len + 32);  // 32 is too much but whatever
    if (!ciphertext)
        croak(2, "encrypt_in_place: malloc(ciphertext)");

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto fail;

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, v3->x_privkul, ivtemp))
        goto fail;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, buf, buf_len))
        goto fail;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        goto fail;
    ciphertext_len += len;

    // fprintf(stderr, "encrypt_in_place: plaintext (%d bytes):\n", buf_len);
	// dump_buf(stderr, buf, buf_len);
    // fprintf(stderr, "encrypt_in_place: ciphertext (%d bytes):\n", ciphertext_len);
	// dump_buf(stderr, ciphertext, ciphertext_len);

    if (buf_len != ciphertext_len) {
        log_error("encrypt_in_place: unexpectedly, ciphertext_len != plaintext_len in CFB mode");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return -1;
    }

    memcpy(buf, ciphertext, ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    return 0;

fail:
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    return -1;
}

/// @brief Decrypt SNMPv3 PDU in-place
/// @param buf Points to the buffer to decrypt
/// @param buf_len Length of the buffer to decrypt
/// @param privp SNMPv3 privacy parameters (8 bytes, used as the second half of the IV)
/// @param v3 SNMPv3 information to use during decryption
/// @return 0 on success, -1 on failure
int
decrypt_in_place(unsigned char *buf, int buf_len, unsigned char *privp, const struct snmpv3info *v3)
{
    EVP_CIPHER_CTX* ctx;
    const EVP_CIPHER *cipher;
    unsigned char *plaintext;
    int len, plaintext_len;
    unsigned char ivtemp[16];

    *((u_int32_t *)(void*)(ivtemp+0)) = htonl(v3->engine_boots);
    *((u_int32_t *)(void*)(ivtemp+4)) = htonl(v3->engine_time);
    memcpy(ivtemp + 8, privp, 8);

    switch (v3->priv_proto) {
    case V3O_PRIV_PROTO_AES:
        cipher = EVP_aes_128_cfb128();
        break;
    case V3O_PRIV_PROTO_AES256_CISCO:
        cipher = EVP_aes_256_cfb128();
        break;
    default:
        log_error("decrypt_in_place: unrecognized or unsupported privacy algorithm");
        return -1;
        break;
    }

    plaintext = malloc(buf_len + 32);  // 32 is too much but whatever
    if (!plaintext)
        croak(2, "decrypt_in_place: malloc(plaintext)");

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto fail;

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, v3->x_privkul, ivtemp))
        goto fail;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, buf, buf_len))
        goto fail;
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        goto fail;
    plaintext_len += len;

    // fprintf(stderr, "decrypt_in_place: ciphertext (%d bytes):\n", buf_len);
	// dump_buf(stderr, buf, buf_len);
    // fprintf(stderr, "decrypt_in_place: plaintext (%d bytes):\n", plaintext_len);
	// dump_buf(stderr, plaintext, plaintext_len);

    if (buf_len != plaintext_len) {
        log_error("decrypt_in_place: unexpectedly, ciphertext_len != plaintext_len in CFB mode");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return -1;
    }

    memcpy(buf, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);

    return 0;

fail:
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    return -1;
}