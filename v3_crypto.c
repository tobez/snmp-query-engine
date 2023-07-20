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

int
hmac_message(const struct snmpv3info* v3,
             unsigned char* out,
             unsigned out_size,
             unsigned char* msg,
             unsigned msg_len,
             unsigned char* auth_param)
{
    HMAC_CTX* ctx = NULL;
    const EVP_MD* md = NULL;

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned md_len = 0;

    if (out_size < 12) {
        fprintf(stderr, "bad hmac output buffer size\n");
        errno = EINVAL;
        return -1;
    }
    if (v3->auth_proto != V3O_AUTH_PROTO_SHA1) {
        fprintf(stderr, "bad auth protocol\n");
        errno = EINVAL;
        return -1;
    }
    if (auth_param - msg + 12 >= msg_len) {
        fprintf(stderr, "bad auth_param pointer\n");
        errno = EINVAL;
        return -1;
    }

    OpenSSL_add_all_digests();

    md = EVP_get_digestbyname("SHA1");
    ctx = HMAC_CTX_new();

    if (!HMAC_Init_ex(ctx, v3->authkul, v3->authkul_len, md, NULL)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    bzero(out, 12);
    if (!HMAC_Update(ctx, msg, auth_param - msg)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (!HMAC_Update(ctx, out, 12)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (!HMAC_Update(ctx, auth_param + 12, msg_len - (auth_param - msg + 12))) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (!HMAC_Final(ctx, md_value, &md_len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    HMAC_CTX_free(ctx);
    memcpy(out, md_value, 12);

    return 0;
}

/// @brief Encrypt SNMPv3 PDU in-place
/// @param buf Points to the buffer to encrypt
/// @param buf_len Length of the buffer to encrypt
/// @param privp Points to SNMPv3 privacy parameters that will be written during encryption
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
        fprintf(stderr, "encrypt_in_place: unrecognized or unsupported privacy algorithm\n");
        return -1;
        break;
    }

    ciphertext = malloc(buf_len + 32);  // 32 is too much but whatever

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, v3->x_privkul, ivtemp)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, buf, buf_len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ciphertext_len += len;

    fprintf(stderr, "encrypt_in_place: plaintext (%d bytes):\n", buf_len);
	dump_buf(stderr, buf, buf_len);
    fprintf(stderr, "encrypt_in_place: ciphertext (%d bytes):\n", ciphertext_len);
	dump_buf(stderr, ciphertext, ciphertext_len);

    if (buf_len != ciphertext_len) {
        fprintf(stderr, "encrypt_in_place: unexpectedly, ciphertext_len != plaintext_len in CFB mode\n");
        return -1;
    }

    memcpy(buf, ciphertext, ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    return 0;
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
        fprintf(stderr, "decrypt_in_place: unrecognized or unsupported privacy algorithm\n");
        return -1;
        break;
    }

    plaintext = malloc(buf_len + 32);  // 32 is too much but whatever

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, v3->x_privkul, ivtemp)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, buf, buf_len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    plaintext_len += len;

    fprintf(stderr, "decrypt_in_place: ciphertext (%d bytes):\n", buf_len);
	dump_buf(stderr, buf, buf_len);
    fprintf(stderr, "decrypt_in_place: plaintext (%d bytes):\n", plaintext_len);
	dump_buf(stderr, plaintext, plaintext_len);

    if (buf_len != plaintext_len) {
        fprintf(stderr, "decrypt_in_place: unexpectedly, ciphertext_len != plaintext_len in CFB mode\n");
        return -1;
    }

    memcpy(buf, plaintext, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);

    return 0;
}