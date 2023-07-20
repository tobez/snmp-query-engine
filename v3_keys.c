/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2023, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"

#include <openssl/evp.h>

static bool
password_to_key_sha1(void *pass, unsigned paslen, void *keybuf, unsigned keybufsize, unsigned *out_keylen, char **out_error)
{
    EVP_MD_CTX *ctx;
    int cnt = 1048576;

    *out_error = "ok";
    if (keybufsize < EVP_MD_size(EVP_sha1())) {
        *out_error = "insufficient buffer space";
        return false;
    }
    *out_keylen = EVP_MD_size(EVP_sha1());

    if (paslen <= 0) {
        *out_error = "empty password";
        return false;
    }

    if ((ctx = EVP_MD_CTX_new()) == NULL) {
        *out_error = "EVP_MD_CTX_new";
        return false;
    }

    if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL)) {
        *out_error = "EVP_DigestInit_ex";
        EVP_MD_CTX_free(ctx);
        return false;
    }

    while (cnt > 0) {
        if (1 != EVP_DigestUpdate(ctx, pass, cnt >= paslen ? paslen : cnt)) {
            *out_error = "EVP_DigestUpdate";
            EVP_MD_CTX_free(ctx);
            return false;
        }
        cnt -= paslen;
    }

    if (1 != EVP_DigestFinal_ex(ctx, keybuf, out_keylen)) {
        *out_error = "EVP_DigestFinal_ex";
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}

bool
password_to_key(int algorithm, void *pass, unsigned pass_size, void *keybuf, unsigned keybufsize, unsigned *out_keylen, char **out_error)
{
    switch (algorithm) {
    case V3O_AUTH_PROTO_SHA1:
        return password_to_key_sha1(pass, pass_size, keybuf, keybufsize, out_keylen, out_error);
        break;
    default:
        *out_error = "unsupported alrgorithm";
        return false;
    }
    return false;
}

static bool
key_to_kul_sha1(void* key,
                unsigned key_size,
                void* engine_id,
                unsigned engine_id_size,
                void* out_kul,
                unsigned out_kul_size,
                unsigned* out_kul_len,
                char** out_error)
{
    EVP_MD_CTX *ctx;

    *out_error = "ok";
    if (out_kul_size < EVP_MD_size(EVP_sha1())) {
        *out_error = "insufficient buffer space";
        return false;
    }
    *out_kul_len = EVP_MD_size(EVP_sha1());

    if (key_size <= 0) {
        *out_error = "empty key";
        return false;
    }

    if (engine_id_size <= 0) {
        *out_error = "empty engine_id";
        return false;
    }

    if ((ctx = EVP_MD_CTX_new()) == NULL) {
        *out_error = "EVP_MD_CTX_new";
        return false;
    }

    if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL)) {
        *out_error = "EVP_DigestInit_ex";
        EVP_MD_CTX_free(ctx);
        return false;
    }

    /*
    func LocalizeKey(h hash.Hash, key []byte, engineID []byte) ([]byte, error) {
            h.Reset()
            r := append([]byte{}, key...)
            r = append(r, engineID...)
            r = append(r, key...)
            _, err := h.Write(r)
            if err != nil {
                    return nil, err
            }
            return h.Sum(nil), nil
    }
    */

    if (1 != EVP_DigestUpdate(ctx, key, key_size)) {
        *out_error = "EVP_DigestUpdate";
        EVP_MD_CTX_free(ctx);
        return false;
    }
    if (1 != EVP_DigestUpdate(ctx, engine_id, engine_id_size)) {
        *out_error = "EVP_DigestUpdate";
        EVP_MD_CTX_free(ctx);
        return false;
    }
    if (1 != EVP_DigestUpdate(ctx, key, key_size)) {
        *out_error = "EVP_DigestUpdate";
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_DigestFinal_ex(ctx, out_kul, out_kul_len)) {
        *out_error = "EVP_DigestFinal_ex";
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);
    return true;
}

bool
key_to_kul(int algorithm,
           void* key,
           unsigned key_size,
           void* engine_id,
           unsigned engine_id_size,
           void* out_kul,
           unsigned out_kul_size,
           unsigned* out_kul_len,
           char** out_error)
{
    switch (algorithm) {
    case V3O_AUTH_PROTO_SHA1:
        return key_to_kul_sha1(key,
                               key_size,
                               engine_id,
                               engine_id_size,
                               out_kul,
                               out_kul_size,
                               out_kul_len,
                               out_error);
        break;
    default:
        *out_error = "unsupported alrgorithm";
        return false;
    }
    return false;
}

extern bool
password_to_kul(int alg,
                void* pass,
                unsigned pass_size,
                void* engine_id,
                unsigned engine_id_size,
                void* out_kul,
                unsigned out_kul_size,
                unsigned* out_kul_len,
                char** out_error)
{
    #define MAXKEY 256
    unsigned char keybuf[MAXKEY];
    unsigned keybuf_len;

    if (!password_to_key(alg, pass, pass_size, keybuf, MAXKEY, &keybuf_len, out_error)) {
        return false;
    }

    if (!key_to_kul(alg, keybuf, keybuf_len, engine_id, engine_id_size,
        out_kul, out_kul_size, out_kul_len, out_error)) {
        return false;
    }

    return true;
#undef MAXKEY
}

bool
expand_kul(int authalg,
           int privalg,
           void* kul,
           unsigned kul_size,
           void* engine_id,
           unsigned engine_id_size,
           void* out_x_kul,
           unsigned out_x_kul_size,
           unsigned* out_x_kul_len,
           char** out_error)
{
    unsigned char extra_key[V3O_PRIVKUL_MAXSIZE];
    unsigned extra_key_len;
    int remains;
    unsigned char* t;

    switch (privalg) {
    case V3O_PRIV_PROTO_AES:
        if (kul_size < 16) {
            *out_error = "kul too small";
            return false;
        }
        if (out_x_kul_size < 16) {
            *out_error = "buffer too small";
            return false;
        }
        memmove(out_x_kul, kul, 16);
        *out_x_kul_len = 16;
        return true;
        break;
    case V3O_PRIV_PROTO_AES256_CISCO:
        if (out_x_kul_size < 32) {
            *out_error = "buffer too small";
            return false;
        }
        remains = 32;
        t = out_x_kul;
        memcpy(t, kul, kul_size > remains ? remains : kul_size);
        t += kul_size > remains ? remains : kul_size;
        remains -= kul_size;
        while (remains > 0) {
            if (!password_to_kul(authalg,
                                 out_x_kul,
                                 t - (unsigned char*)out_x_kul,
                                 engine_id,
                                 engine_id_size,
                                 extra_key,
                                 V3O_PRIVKUL_MAXSIZE,
                                 &extra_key_len,
                                 out_error))
              return false;
            memcpy(t, extra_key, extra_key_len > remains ? remains : extra_key_len);
            t += extra_key_len > remains ? remains : extra_key_len;
            remains -= extra_key_len;
        }
        *out_x_kul_len = 32;
        return true;
        break;
    default:
        *out_error = "unsupported alrgorithm";
        return false;
    }
    return false;
}
