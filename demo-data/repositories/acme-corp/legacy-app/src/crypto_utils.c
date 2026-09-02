/*
 * Legacy inventory application - written ~15 years ago, still running on an
 * internal server. Fictional demo code for ECDAT scanning purposes.
 * Intentionally contains multiple deprecated/weak algorithms.
 */
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/rsa.h>

/* MD5 used for old file integrity checks - broken, needs replacement */
void compute_file_hash(const unsigned char *data, size_t len, unsigned char *out) {
    MD5(data, len, out);
}

/* 3DES used for legacy database column encryption */
void encrypt_legacy_field(DES_cblock *key1, DES_cblock *key2, DES_cblock *key3) {
    DES_key_schedule ks1, ks2, ks3;
    DES_set_key_unchecked(key1, &ks1);
    DES_set_key_unchecked(key2, &ks2);
    DES_set_key_unchecked(key3, &ks3);
}

/* RSA-1024 key still in use for an old internal signing service */
RSA *generate_legacy_rsa_key() {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, e, NULL);
    return rsa;
}
