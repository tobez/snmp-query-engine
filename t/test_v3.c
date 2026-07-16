/*
 * Part of `snmp-query-engine`.
 *
 * Copyright 2023, Anton Berezin <tobez@tobez.org>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include "sqe.h"
#include "tap.h"

/* engine id 00 00 00 00 00 00 00 00 00 00 00 02, 12 bytes */
static const unsigned char engine_id[] =
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02";
#define ENGINE_ID_LEN 12

static void
to_hex(char *dst, const unsigned char *buf, unsigned len)
{
    static const char h[] = "0123456789abcdef";
    unsigned i;
    for (i = 0; i < len; i++) {
        dst[2 * i]     = h[(buf[i] >> 4) & 0x0f];
        dst[2 * i + 1] = h[buf[i] & 0x0f];
    }
    dst[2 * len] = 0;
}

/* Known-answer test for one auth protocol: derives Ku from the password and
 * Kul from Ku + engine id, comparing both against the expected hex strings. */
static void
check_kat(const char *name, int proto,
          const char *expect_ku_hex, const char *expect_kul_hex)
{
    unsigned char key[64], kul[64];
    char hex[2 * 64 + 1];
    unsigned len;
    char *err;

    if (!password_to_key(proto, "maplesyrup", strlen("maplesyrup"),
                         key, sizeof(key), &len, &err)) {
        ok(0, "%s password_to_key", name);
        tap_diag("%s", err);
        return;
    }
    ok(1, "%s password_to_key", name);
    if (!ok(len == strlen(expect_ku_hex) / 2, "%s password_to_key length", name))
        tap_diag("got %u, expected %zu", len, strlen(expect_ku_hex) / 2);
    to_hex(hex, key, len);
    if (!ok(strcmp(hex, expect_ku_hex) == 0, "%s password_to_key Ku", name))
        tap_diag("got %s, expected %s", hex, expect_ku_hex);

    if (!key_to_kul(proto, key, len, (void *)engine_id, ENGINE_ID_LEN,
                    kul, sizeof(kul), &len, &err)) {
        ok(0, "%s key_to_kul", name);
        tap_diag("%s", err);
        return;
    }
    ok(1, "%s key_to_kul", name);
    if (!ok(len == strlen(expect_kul_hex) / 2, "%s key_to_kul length", name))
        tap_diag("got %u, expected %zu", len, strlen(expect_kul_hex) / 2);
    to_hex(hex, kul, len);
    if (!ok(strcmp(hex, expect_kul_hex) == 0, "%s key_to_kul Kul", name))
        tap_diag("got %s, expected %s", hex, expect_kul_hex);
}

/* Regression test mirroring request_setopt.c: the localized privacy key is
 * derived from a password with a V3O_PRIVKUL_MAXSIZE-sized buffer, so that
 * buffer must hold a full-length digest (64 bytes for SHA-512). The value
 * equals the corresponding key_to_kul result for the same password/engine id. */
static void
check_privkul(const char *name, int proto, const char *expect_kul_hex)
{
    unsigned char kul[V3O_PRIVKUL_MAXSIZE];
    char hex[2 * V3O_PRIVKUL_MAXSIZE + 1];
    unsigned len;
    char *err;

    if (!password_to_kul(proto, "maplesyrup", strlen("maplesyrup"),
                         (void *)engine_id, ENGINE_ID_LEN,
                         kul, V3O_PRIVKUL_MAXSIZE, &len, &err)) {
        ok(0, "%s password_to_kul", name);
        tap_diag("%s", err);
        return;
    }
    ok(1, "%s password_to_kul", name);
    to_hex(hex, kul, len);
    if (!ok(strcmp(hex, expect_kul_hex) == 0, "%s privkul", name))
        tap_diag("got %s, expected %s", hex, expect_kul_hex);
}

/* Exercises the v3_crypto.c hmac_message rewrite for one protocol the same way
 * the daemon does: ber.c signs an outgoing packet (writes the MAC into the
 * auth-param slot) and snmp.c verifies a reply (zeroes the slot, recomputes,
 * compares). Confirms the protocol lookup, the maclen truncation (12/16/24/32/48
 * bytes) and the buffer handling all line up, including SHA-512's 48-byte MAC. */
static void
check_hmac(const char *name, int proto)
{
    struct snmpv3info v3;
    unsigned char msg[128];
    unsigned char saved[64];
    int maclen = v3_auth_maclen(proto);
    unsigned char *ap;
    unsigned i;
    char *err;

    memset(&v3, 0, sizeof(v3));
    v3.auth_proto = proto;
    if (!password_to_kul(proto, "maplesyrup", strlen("maplesyrup"),
                         (void *)engine_id, ENGINE_ID_LEN,
                         v3.authkul, sizeof(v3.authkul), &v3.authkul_len, &err)) {
        ok(0, "%s hmac setup", name);
        tap_diag("%s", err);
        return;
    }
    for (i = 0; i < sizeof(msg); i++)
        msg[i] = (unsigned char)i;
    ap = msg + 40;  /* auth-param slot somewhere inside the message */

    /* sign (ber.c finalize path): hmac_message zeroes the slot, then fills it */
    if (!ok(hmac_message(&v3, ap, maclen, msg, sizeof(msg), ap) >= 0, "%s hmac sign", name))
        return;
    memcpy(saved, ap, maclen);

    /* verify (snmp.c response path): recompute and compare against the received MAC */
    if (hmac_message(&v3, ap, maclen, msg, sizeof(msg), ap) < 0) {
        ok(0, "%s hmac verify", name);
        return;
    }
    if (!ok(memcmp(saved, ap, maclen) == 0, "%s hmac verify", name))
        tap_diag("hmac not reproducible");
}

int
main(void)
{
    /* Test vectors: password "maplesyrup", engine id 00..0002.
     * SHA-1 values reproduce RFC 3414 A.2; SHA-2 values independently
     * derived (RFC 7860 / RFC 3414 A.2 generalized). */
    check_kat("sha1", V3O_AUTH_PROTO_SHA1,
              "9fb5cc0381497b3793528939ff788d5d79145211",
              "6695febc9288e36282235fc7151f128497b38f3f");
    check_kat("sha224", V3O_AUTH_PROTO_SHA224,
              "282a5867ee9aac639ad59df9572c7d3ac0fbc13a905b6df07dbbf00b",
              "0bd8827c6e29f8065e08e09237f177e410f69b90e1782be682075674");
    check_kat("sha256", V3O_AUTH_PROTO_SHA256,
              "ab51014d1e077f6017df2b12bee5f5aa72993177e9bb569c4dff5a4ca0b4afac",
              "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b");
    check_kat("sha384", V3O_AUTH_PROTO_SHA384,
              "e06eccdf2c68a06ed034723c9c26e0db3b669e1e2efed49150b55377a2e98f383c86fb836857444654b287c93f51ff64",
              "3b298f16164a11184279d5432bf169e2d2a48307de02b3d3f7e2b4f36eb6f0455a53689a3937eea07319a633d2ccba78");
    check_kat("sha512", V3O_AUTH_PROTO_SHA512,
              "7e4396de5aadc77be853819b98c9406265b3a9c37cc3176569847a4e4f6fba63dd3a73d04924d31a63f95a601f9385af6be4ed1b37f87d040f7c6ed6f8d38a91",
              "22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84c099ad1ea87a8db096714d9788bd544047c9021e4229ce27e4c0a69250adfcffbb0b");

    /* privacy-key derivation from a password must fit a full SHA-512 digest */
    check_privkul("sha512-privkul", V3O_AUTH_PROTO_SHA512,
                  "22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84c099ad1ea87a8db096714d9788bd544047c9021e4229ce27e4c0a69250adfcffbb0b");

    /* hmac_message sign/verify round-trip for every supported protocol */
    check_hmac("sha1", V3O_AUTH_PROTO_SHA1);
    check_hmac("sha224", V3O_AUTH_PROTO_SHA224);
    check_hmac("sha256", V3O_AUTH_PROTO_SHA256);
    check_hmac("sha384", V3O_AUTH_PROTO_SHA384);
    check_hmac("sha512", V3O_AUTH_PROTO_SHA512);

    /* localized-key length per protocol */
    is_int(v3_auth_kul_len(V3O_AUTH_PROTO_SHA1), 20, "sha1 kul length");
    is_int(v3_auth_kul_len(V3O_AUTH_PROTO_SHA224), 28, "sha224 kul length");
    is_int(v3_auth_kul_len(V3O_AUTH_PROTO_SHA256), 32, "sha256 kul length");
    is_int(v3_auth_kul_len(V3O_AUTH_PROTO_SHA384), 48, "sha384 kul length");
    is_int(v3_auth_kul_len(V3O_AUTH_PROTO_SHA512), 64, "sha512 kul length");
    is_int(v3_auth_kul_len(V3O_AUTH_PROTO_MD5), -1, "md5 kul length unsupported");
    is_int(v3_auth_kul_len(0), -1, "absent auth proto kul length unsupported");

    is_int(v3_priv_key_len(V3O_PRIV_PROTO_AES), 16, "aes priv key length");
    is_int(v3_priv_key_len(V3O_PRIV_PROTO_AES128), 16, "aes128 priv key length");
    is_int(v3_priv_key_len(V3O_PRIV_PROTO_AES256_CISCO), 32, "aes256c priv key length");
    is_int(v3_priv_key_len(V3O_PRIV_PROTO_DES), -1, "des priv key length unsupported");
    is_int(v3_priv_key_len(0), -1, "absent priv proto key length unsupported");

    return tap_done();
}
