/*
 * lcputils.c: misc. LCP helper fns
 *
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <safe_lib.h>
#include <snprintf_s.h>
#define PRINT   printf
#include "../../include/config.h"
#include "../../include/hash.h"
#include "../../include/uuid.h"
#include "../../include/lcp3.h"
#include "polelt_plugin.h"
#include "lcputils.h"
#include "pollist2.h"

static uint16_t pkcs_get_hashalg(const unsigned char *data);

void ERROR(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void LOG(const char *fmt, ...)
{
    va_list ap;

    if ( verbose ) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
}

void DISPLAY(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

size_t strlcpy(char *dst, const char *src, size_t siz)
{
    strcpy_s(dst, siz, src);
    return strnlen_s(dst, siz);
}

void print_hex(const char *prefix, const void *data, size_t n)
{
#define NUM_CHARS_PER_LINE 20
    unsigned int i = 0;
    while ( i < n ) {
        if ( i % NUM_CHARS_PER_LINE == 0 && prefix != NULL ) {
            DISPLAY("%s", prefix);
        }
        DISPLAY("%02x ", *(uint8_t *)data++);
        i++;
        if ( i % NUM_CHARS_PER_LINE == 0 ) {
            DISPLAY("\n");
        }
    }
    if ( i % NUM_CHARS_PER_LINE != 0 ) {
        DISPLAY("\n");
    }
}

void parse_comma_sep_ints(char *s, uint16_t ints[], unsigned int *nr_ints)
{
    unsigned int nr = 0;

    while ( true ) {
        char *str = strsep(&s, ",");
        if ( str == NULL || nr == *nr_ints )
            break;
        ints[nr++] = strtoul(str, NULL, 0);
    }
    *nr_ints = nr;
    return;
}

void *read_file(const char *file, size_t *length, bool fail_ok)
{
    LOG("[read_file]\n");
    LOG("read_file: filename=%s\n", file);
    FILE *fp = fopen(file, "rb");
    if ( fp == NULL ) {
        if ( !fail_ok )
            ERROR("Error: failed to open file %s: %s\n", file,
                    strerror(errno));
        return NULL;
    }

    /* find size */
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    if (len <= 0) {
        ERROR("Error: failed to get file length or file is empty.\n");
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    void *data = malloc(len);
    if ( data == NULL ) {
        ERROR("Error: failed to allocate %d bytes memory\n", len);
        fclose(fp);
        return NULL;
    }

    if ( fread(data, len, 1, fp) != 1 ) {
        ERROR("Error: reading file %s\n", file);
        free(data);
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    if ( length != NULL )
        *length = len;
    LOG("read file succeed!\n");
    return data;
}

bool write_file(const char *file, const void *data, size_t size)
{
    LOG("[write_file]\n");
    FILE *fp = fopen(file, "wb");
    if ( fp == NULL ) {
        ERROR("Error: failed to open file %s for writing: %s\n",
                file, strerror(errno));
        return false;
    }
    if ( fwrite(data, size, 1, fp) != 1 ) {
        ERROR("Error: writing file %s\n", file);
        fclose(fp);
        return false;
    }
    fclose(fp);
    LOG("write file succeed!\n");
    return true;
}

bool parse_line_hashes(const char *line, tb_hash_t *hash, uint16_t alg)
{
    /* skip any leading whitespace */
    while ( *line != '\0' && isspace(*line) )
        line++;

    /* rest of line is hex of hash */
    unsigned int i = 0;
    while ( *line != '\0' && *line != '\n' ) {
        char *next;
        switch (alg) {
        case LCP_POLHALG_SHA1: //Legacy value for TPM 1.2
            hash->sha1[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        case TPM_ALG_SHA1:
            hash->sha1[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        case TPM_ALG_SHA256:
            hash->sha256[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        case TPM_ALG_SHA384:
            hash->sha384[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        default:
            ERROR("Error: unsupported alg: 0x%x\n",alg);
            return false;
        }
        if ( next == line )      /* done */
            break;
        line = next;
        /* spaces at end cause strtoul() to interpret as 0, so skip them */
        while ( *line != '\0' && !isxdigit(*line) )
            line++;
    }

    if ( i != get_hash_size(alg) ) {
        ERROR("Error: incorrect number of chars for hash\n");
        return false;
    }

    return true;
}

bool parse_file(const char *filename, bool (*parse_line)(const char *line))
{
    if ( filename == NULL || parse_line == NULL )
        return false;

    LOG("reading hashes file %s...\n", filename);

    FILE *fp = fopen(filename, "r");
    if ( fp == NULL ) {
        ERROR("Error: failed to open file %s (%s)\n", filename, strerror(errno));
        return false;
    }

    static char line[1024];
    while ( true ) {
        char *s = fgets(line, sizeof(line), fp);

        if ( s == NULL ) {
            fclose(fp);
            return true;
        }

        LOG("read line: %s\n", line);

        if ( !(*parse_line)(line) ) {
            fclose(fp);
            return false;
        }
    }

    fclose(fp);
    return false;
}

const char *hash_alg_to_str(uint16_t alg)
{
    static char buf[32];
    switch(alg){
    case TPM_ALG_SHA1:
        return "TPM_ALG_SHA1";
    case TPM_ALG_SHA256:
        return "TPM_ALG_SHA256";
    case TPM_ALG_SHA384:
        return "TPM_ALG_SHA384";
    case TPM_ALG_SHA512:
        return "TPM_ALG_SHA512";
    case TPM_ALG_SM3_256:
        return "TPM_ALG_SM3_256";
    case TPM_ALG_SM2:
        return "TPM_ALG_SM2";
    case LCP_POLHALG_SHA1: //Legacy value for TPM 1.2
        return "LCP_POLHALG_SHA1";
    default:
        snprintf_s_i(buf, sizeof(buf), "unknown (%u)", alg);
        return buf;
    }
}

const char *key_alg_to_str(uint16_t alg)
{
    switch (alg)
    {
    case TPM_ALG_RSA:
        return "TPM_ALG_RSA";
    case TPM_ALG_ECC:
        return "TPM_ALG_ECC";
    default:
        return "";
    }
}

const char *sig_alg_to_str(uint16_t alg)
{
    static char buf[32];
    switch(alg){
    case TPM_ALG_RSASSA:
        return "TPM_ALG_RSASSA";
    case TPM_ALG_ECDSA:
        return "TPM_ALG_ECDSA";
    case TPM_ALG_SM2:
        return "TPM_ALG_SM2";
    case TPM_ALG_RSAPSS:
        return "TPM_ALG_RSAPSS";
    case TPM_ALG_SM3_256:
        return "TPM_ALG_SM3_256";
    case TPM_ALG_NULL:
        return "TPM_ALG_NULL";
    case LCP_POLSALG_RSA_PKCS_15:
        return "LCP_POLSALG_RSA_PKCS_15";
    default:
        snprintf_s_i(buf, sizeof(buf), "unknown (%u)", alg);
        return buf;
    }
}

uint16_t str_to_hash_alg(const char *str)
{
    if (strcmp(str,"sha1") == 0)
        return TPM_ALG_SHA1;
    else if (strcmp(str,"sha256") == 0)
        return TPM_ALG_SHA256;
    else if (strcmp(str,"sha384") == 0)
        return TPM_ALG_SHA384;
    else if (strcmp(str,"sha512") == 0)
        return TPM_ALG_SHA512;
    else if (strcmp(str,"sm3") == 0)
        return TPM_ALG_SM3_256;
    else
        return  TPM_ALG_NULL;
}

uint16_t str_to_lcp_hash_mask(const char *str)
{
    if (strcmp(str,"sha1") == 0)
        return TPM_ALG_MASK_SHA1;
    else if (strcmp(str,"sha256") == 0)
        return TPM_ALG_MASK_SHA256;
    else if (strcmp(str,"sha384") == 0)
        return TPM_ALG_MASK_SHA384;
    else if (strcmp(str,"sha512") == 0)
        return TPM_ALG_MASK_SHA512;
    else if (strcmp(str,"sm3") == 0)
        return TPM_ALG_MASK_SM3_256;
    else if(strncmp(str, "0X", 2) || strncmp(str, "0x", 2))
        return strtoul(str, NULL, 0);
    else
        return  TPM_ALG_MASK_NULL;
}

uint16_t str_to_sig_alg(const char *str) {
    if (strcmp(str,"rsa-pkcs15") == 0)
        return LCP_POLSALG_RSA_PKCS_15;
    if( strcmp(str,"rsa-ssa") == 0 || strcmp(str,"rsassa") == 0 || strcmp(str,"rsa") == 0  )
        return TPM_ALG_RSASSA;
    if ( strcmp(str,"ecdsa") == 0)
        return TPM_ALG_ECDSA;
    if ( strcmp(str,"sm2") == 0)
        return TPM_ALG_SM2;
    if( strcmp(str,"rsa-pss") == 0 || strcmp(str,"rsapss") == 0 )
        return TPM_ALG_RSAPSS;
    if ( strcmp(str,"sm3") == 0)
        return TPM_ALG_SM3_256;
    else {
        LOG("Unrecognized signature alg, assuming TPM_ALG_NULL");
        return TPM_ALG_NULL;
    }
}

uint32_t str_to_sig_alg_mask(const char *str, const uint16_t version, size_t size)
{
    uint16_t lcp_major_ver = version & 0xFF00;
    if( lcp_major_ver == LCP_VER_2_0 ) {
        //signature algorithm mask is undefined in LCPv2
        return SIGN_ALG_MASK_NULL;
    }
    else if( lcp_major_ver == LCP_VER_3_0 ) {
        if (strncmp(str, "rsa-2048-sha1", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_2048_SHA1;
        }
        else if (strncmp(str, "rsa-2048-sha256", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_2048_SHA256;
        }
        else if (strncmp(str, "rsa-3072-sha256", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_3072_SHA256;
        }
        else if (strncmp(str, "rsa-3072-sha384", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_3072_SHA384;
        }
        else if (strncmp(str, "ecdsa-p256", size) == 0) {
            return SIGN_ALG_MASK_ECDSA_P256;
        }
        else if (strncmp(str, "ecdsa-p384", size) == 0) {
            return SIGN_ALG_MASK_ECDSA_P384;
        }
        else if (strncmp(str, "sm3", size) == 0 ||
                 strncmp(str, "sm2", size) == 0) {
            return SIGN_ALG_MASK_SM2;
        }
        else if(strncmp(str, "0X", 2) || strncmp(str, "0x", 2)){
            return strtoul(str, NULL, 0);
        }
        else{
            //Format unrecognized
            return SIGN_ALG_MASK_NULL;
        }
    }
    else
        return SIGN_ALG_MASK_NULL;
}
uint16_t str_to_pol_ver(const char *str)
{
    if( strcmp(str,"2.0") == 0)
       return LCP_VER_2_0;
    else if ( strcmp(str,"2.1") == 0)
        return LCP_VER_2_1;
    else if ( strcmp(str,"2.2") == 0)
        return LCP_VER_2_2;
    else if ( strcmp(str,"2.3") == 0)
        return LCP_VER_2_3;
    else if ( strcmp(str,"2.4") == 0)
        return LCP_VER_2_4;
    else if ( strcmp(str,"3.0") == 0)
        return LCP_VER_3_0;
    else if ( strcmp(str,"3.1") == 0)
        return LCP_VER_3_1;
    else if ( strcmp(str, "3.2") == 0)
        return LCP_VER_3_2;
    else
        return LCP_VER_NULL;
}

uint16_t convert_hash_alg_to_mask(uint16_t hash_alg)
{
    LOG("convert_hash_alg_to_mask hash_alg = 0x%x\n", hash_alg);
    switch(hash_alg){
    case TPM_ALG_SHA1:
        return TPM_ALG_MASK_SHA1;
    case TPM_ALG_SHA256:
        return TPM_ALG_MASK_SHA256;
    case TPM_ALG_SHA384:
        return TPM_ALG_MASK_SHA384;
    case TPM_ALG_SHA512:
        return TPM_ALG_MASK_SHA512;
    case TPM_ALG_SM3_256:
        return TPM_ALG_MASK_SM3_256;
    default:
        return 0;
    }
    return 0;
}

size_t get_lcp_hash_size(uint16_t hash_alg)
{
    switch(hash_alg){
    case TPM_ALG_SHA1:
        return SHA1_DIGEST_SIZE;
    case TPM_ALG_SHA256:
        return SHA256_DIGEST_SIZE;
    case TPM_ALG_SHA384:
        return SHA384_DIGEST_SIZE;
    case TPM_ALG_SHA512:
        return SHA512_DIGEST_SIZE;
    case TPM_ALG_SM3_256:
        return SM3_256_DIGEST_SIZE;
    case LCP_POLHALG_SHA1: //Legacy value for TPM 1.2
        return SHA1_DIGEST_SIZE;
    default:
        return 0;
    }
    return 0;
}

bool verify_ecdsa_signature(const unsigned char *data, size_t data_size,
    const unsigned char *pubkey_x, const unsigned char *pubkey_y, size_t pubkey_size, const uint16_t hashalg, 
    const unsigned char *sig_r, const unsigned char *sig_s)
/*
This function: verifies ecdsa signature using pubkey (lists 2.0 and 2.1 only!)

In: Data - digest of LCP policy list contents:

    LCP_LIST_2_1: hash entire list up to KeyAndSignature field (that includes 
        RevoCation counter) i.e. hash of KeyAndSignatureOffset bytes of the list.

    LCP_LIST_2: hash of entire list up to the r member of the Signature field

    data_size - size of digest (32 bytes for SHA256, 48 for SHA384)

    pubkey_x - public key x coordinate (BE)

    pubkey_y - public key y coordinate (BE)

    hashAlg - hash algorithm used to create digest

    sig_r and sig_s - buffers containing signature bytes BE

    Out: true/false on verification success or failure
*/
{
    ECDSA_SIG *ec_sig = NULL;
    EC_KEY *ec_key = NULL;
    EC_GROUP *ec_group = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    int result;

    LOG("[verify_ecdsa_signature]\n");
    ec_key = EC_KEY_new();
    if ( ec_key == NULL ) {
        ERROR("ERROR: failed to generate EC_KEY.\n");
        result = 0;
        goto EXIT;
    }

    switch (hashalg)
    {
    case TPM_ALG_SHA256:
        ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if ( ec_group == NULL) {
            ERROR("Failed to generate new EC Group.\n");
            goto OPENSSL_ERROR;
        }
        break;
    case TPM_ALG_SHA384:
        ec_group = EC_GROUP_new_by_curve_name(NID_secp384r1);
        if ( ec_group == NULL) {
            ERROR("Failed to allocate new EC Group.\n");
            goto OPENSSL_ERROR;
        }
        break;
    default:
        ERROR("ERROR: incorrect hash alg.\n");
        result = 0;
        goto EXIT;
    }
    result = EC_KEY_set_group(ec_key, ec_group);
    if ( result <= 0) {
        ERROR("Failed to set EC Key group.\n");
        goto OPENSSL_ERROR;
    }
    x = BN_bin2bn(pubkey_x, pubkey_size, NULL);
    y = BN_bin2bn(pubkey_y, pubkey_size, NULL);
    r = BN_bin2bn(sig_r, pubkey_size, NULL);
    s = BN_bin2bn(sig_s, pubkey_size, NULL);
    if ( x == NULL || y == NULL || r == NULL || s == NULL ) {
        ERROR("Failed to convert buffer to OpenSSL BN.\n");
        goto OPENSSL_ERROR;
    }
    result = EC_KEY_set_public_key_affine_coordinates(ec_key, x, y);
    if ( result <= 0) {
        ERROR("Failed to set key coordinates.\n");
        goto OPENSSL_ERROR;
    }
    ec_sig = ECDSA_SIG_new();
    if ( ec_sig == NULL) {
        ERROR("Failed to allocate ECDSA signature.\n");
        goto OPENSSL_ERROR;
    }
    result = ECDSA_SIG_set0(ec_sig, r, s);
    if ( result <= 0) {
        ERROR("Failed to set signature components.\n");
        goto OPENSSL_ERROR;
    }
    result = ECDSA_do_verify(data, data_size, ec_sig, ec_key);
    if ( result < 0 ) {
        ERROR("Error verifying signature.\n");
        goto OPENSSL_ERROR;
    }
    else if (result == 1) {
        LOG("Verification successful.\n");
        goto EXIT;
    }
    else {
        LOG("Signature did not verify.\n");
        goto EXIT;
    }
    return false;
    OPENSSL_ERROR:
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s\n",ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        result = 0;
    EXIT:
        if (ec_sig != NULL)
            OPENSSL_free((void *) ec_sig);
        if (ec_key != NULL)
            OPENSSL_free((void *) ec_key);
        if (ec_group != NULL)
            OPENSSL_free((void *) ec_group);
        if (x != NULL)
            OPENSSL_free((void *) x);
        if (y != NULL)
            OPENSSL_free((void *) y);
        if (r != NULL)
            OPENSSL_free((void *) r);
        if (s != NULL)
            OPENSSL_free((void *) s);
        return result ? true : false;
}

bool verify_rsa_signature(sized_buffer *data, sized_buffer *pubkey, sized_buffer *signature,
                          uint16_t hashAlg, uint16_t sig_alg, uint16_t list_ver)
/*
This function: verifies policy list's rsapss and rsassa signatures using pubkey

In: Data - pointer to sized buffer with signed LCP policy list contents:
    LCP_POLICY_LIST2_1 - entire list up to KeyAndSignature field (that includes
    RevoCation counter) i.e. KeyAndSignatureOffset bytes of data from the list.
    LCP_POLICY_LIST and LCP_POLICY_LIST2 - entire list minus the signature field.

    pubkey - pointer to sized buffer containing public key in BE form
    signature - pointer to sizef buffer containing signature in BE form

    hashAlg - LCP_SIGNATURE2_1->RsaKeyAndSignature.Signature.HashAlg i.e. hash
              alg defined for the list signature. Or TPM_HASHALG_NULL if hashalg
              is not a member of list structure (it will be read from signature)
    sig_alg - signature algorithm of the list
    list_ver - specify list version: LCP_POLICY_LIS, LCP_POLICY_LIST2 or 
    LCP_POLICY_LIST2_1

Out: true/false on verification success or failure
*/
{
    int status;
    EVP_PKEY_CTX *evp_context = NULL;
    EVP_PKEY *evp_key = NULL;
    RSA *rsa_pubkey = NULL;
    BIGNUM *modulus = NULL;
    BIGNUM *exponent = NULL;
    tb_hash_t *digest = NULL;
    unsigned char exp_arr[] = {0x01, 0x00, 0x01};

    LOG("[verify_rsa_signature]\n");
    if (data == NULL || pubkey == NULL || signature == NULL) {
        ERROR("Error: list data, pubkey or signature buffer not defined.\n");
        return false;
    }
    uint8_t decrypted_sig[pubkey->size];

    //1. Create public key
    rsa_pubkey = RSA_new();
    if ( rsa_pubkey == NULL ) {
        ERROR("Error: failed to allocate key\n");
        status = 0;
        goto EXIT;
    }

    modulus = BN_bin2bn(pubkey->data, pubkey->size, NULL);
    exponent = BN_bin2bn(exp_arr, 3, NULL);
    if (modulus == NULL) {
        goto OPENSSL_ERROR;
    }
    if (exponent == NULL) {
        goto OPENSSL_ERROR;
    }

    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        RSA_set0_key(rsa_pubkey, modulus, exponent, NULL);
    #else
        rsa_pubkey->n = modulus;
        rsa_pubkey->e = exponent;
        rsa_pubkey->d = rsa_pubkey->p = rsa_pubkey->q = NULL;
    #endif

    if (MAJOR_VER(list_ver) != MAJOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300)) {
        //Decrypt signature - we will need to to find hashalg
        status = RSA_public_decrypt(pubkey->size, signature->data, decrypted_sig, 
                            rsa_pubkey, RSA_NO_PADDING);
        if (status <= 0) {
            ERROR("Error: failed to decrypt signature.\n");
            goto OPENSSL_ERROR;
        }
        if (verbose) {
            LOG("Decrypted signature: \n");
            print_hex("", decrypted_sig, pubkey->size);
        }
        //In older lists we need to get hashAlg from signature data.
        hashAlg = pkcs_get_hashalg((const unsigned char *) decrypted_sig);
    }

    evp_key = EVP_PKEY_new();
    if ( evp_key == NULL) {
        goto OPENSSL_ERROR;
    }

    status = EVP_PKEY_set1_RSA(evp_key, rsa_pubkey);
    if (status <= 0) {
        goto OPENSSL_ERROR;
    }

    evp_context = EVP_PKEY_CTX_new(evp_key, NULL);
    if ( evp_context == NULL) {
        goto OPENSSL_ERROR;
    }

    status = EVP_PKEY_verify_init(evp_context);
    if ( status <= 0) {
        goto OPENSSL_ERROR;
    }

    if ( sig_alg == TPM_ALG_RSAPSS)
        status = EVP_PKEY_CTX_set_rsa_padding(evp_context, RSA_PKCS1_PSS_PADDING);
    else if (sig_alg == TPM_ALG_RSASSA || sig_alg == LCP_POLSALG_RSA_PKCS_15)
        status = EVP_PKEY_CTX_set_rsa_padding(evp_context, RSA_PKCS1_PADDING);
    else {
        ERROR("Error: unsupported signature algorithm.\n");
        status = 0;
        goto EXIT;
    }
    if ( status <= 0) {
        goto OPENSSL_ERROR;
    }

    switch ( hashAlg) {
        case TPM_ALG_SHA1:
        if ( EVP_PKEY_CTX_set_signature_md(evp_context, EVP_sha1()) <= 0 ) {
            goto OPENSSL_ERROR;
        }
        break;
        case TPM_ALG_SHA256:
        if ( EVP_PKEY_CTX_set_signature_md(evp_context, EVP_sha256()) <= 0 ) {
            goto OPENSSL_ERROR;
        }
        break;
        case TPM_ALG_SHA384:
        if ( EVP_PKEY_CTX_set_signature_md(evp_context, EVP_sha384()) <= 0 ) {
            goto OPENSSL_ERROR;
        }
        break;
        default:
        ERROR("Error: Unknown hash alg.\n");
        status = 0;
        goto EXIT;
    }
    digest = malloc(get_lcp_hash_size(hashAlg));
    if (digest == NULL) {
        ERROR("Error: failed to allocate digest");
        status = 0;
        goto EXIT;
    }
    status = hash_buffer((const unsigned char *) data->data, data->size, digest,
                                                                        hashAlg);
    if (!status) {
        ERROR("Error: failed to hash list contents.\n");
        goto EXIT;
    }
    status = EVP_PKEY_verify(evp_context, signature->data, pubkey->size,
                     (const unsigned char *) digest, get_lcp_hash_size(hashAlg));
    if (status < 0) { //Error occurred
        goto OPENSSL_ERROR;
    }
    else { //EVP_PKEY_verify executed sucessfully
        goto EXIT;
    }
    OPENSSL_ERROR:
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        status = 0;
    EXIT:
        if (evp_context != NULL)
            OPENSSL_free((void *) evp_context);
        if (evp_key != NULL)
            OPENSSL_free((void *) evp_key);
        if (rsa_pubkey != NULL)
            OPENSSL_free((void *) rsa_pubkey);
        if (modulus != NULL)
            OPENSSL_free((void *) modulus);
        if (exponent != NULL)
            OPENSSL_free((void *) exponent);
        if (digest != NULL)
            free(digest);
        return status ? true : false;
}

EVP_PKEY_CTX *rsa_get_sig_ctx(const char *key_path, uint16_t key_size_bytes)
{
    FILE *fp = NULL;
    EVP_PKEY *evp_priv = NULL;
    EVP_PKEY_CTX *context = NULL; //This will be returned

    LOG("[rsa_get_sig_ctx]\n");
    fp = fopen(key_path, "r");
    if (fp == NULL)
        goto ERROR;

    evp_priv = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (evp_priv == NULL)
        goto OPENSSL_ERROR;
    fclose(fp);
    fp = NULL;

    if (EVP_PKEY_size(evp_priv) != key_size_bytes) {
        ERROR("ERROR: key size incorrect\n");
        goto ERROR;
    }

    context = EVP_PKEY_CTX_new(evp_priv, NULL);
    if (context == NULL)
        goto OPENSSL_ERROR;

    OPENSSL_free(evp_priv);
    return context;

    OPENSSL_ERROR:
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
    ERROR:
        if (fp != NULL)
            fclose(fp);
        if (evp_priv != NULL)
            OPENSSL_free(evp_priv);
        if (context != NULL)
            OPENSSL_free(context);
        return NULL;
}

bool rsa_ssa_pss_sign(sized_buffer *signature_block, sized_buffer *data_to_sign,
uint16_t sig_alg, uint16_t hash_alg, EVP_PKEY_CTX *private_key_context)
/*
    This function: signs data using rsa private key context

    In: pointer to a correctly sized buffer to hold signature block, digest of 
    lcp list data, hash alg used to hash data, Openssl private key context

    Out: true on success, false on failure. Also signature_block gets signature block data

*/
{
    LOG("[rsa_ssa_pss_sign]\n");
    int result; //For openssl return codes
    size_t siglen; //Holds length of signature returned by openssl must be 256 or 384
    const EVP_MD *evp_hash_alg;

    if (signature_block == NULL || data_to_sign == NULL || private_key_context == NULL) {
        ERROR("Error: one or more data buffers is not defiend.\n");
        return false;
    }

    //Init sig
    result = EVP_PKEY_sign_init(private_key_context);
    if (result <= 0) {
        goto OPENSSL_ERROR;
    }
    //Set padding
    if (sig_alg == TPM_ALG_RSASSA || sig_alg == LCP_POLSALG_RSA_PKCS_15) {
        result = EVP_PKEY_CTX_set_rsa_padding(private_key_context, RSA_PKCS1_PADDING);
    }
    else if (sig_alg == TPM_ALG_RSAPSS) {
        result = EVP_PKEY_CTX_set_rsa_padding(private_key_context, RSA_PKCS1_PSS_PADDING);
    }
    else {
        ERROR("ERROR: unsupported signature algorithm.\n");
        return false;
    }
    if (result <= 0) {
        goto OPENSSL_ERROR;
    }

    if (sig_alg == TPM_ALG_RSAPSS) {
        result = EVP_PKEY_CTX_set_rsa_pss_saltlen(private_key_context, -1);
        if (result <= 0) {
            goto OPENSSL_ERROR;
        }
    }
    switch (hash_alg) {
        case LCP_POLHALG_SHA1: //Legacy value for TPM 1.2
            evp_hash_alg = EVP_sha1();
            break;
        case TPM_ALG_SHA1:
            evp_hash_alg = EVP_sha1();
            break;
        case TPM_ALG_SHA256:
            evp_hash_alg = EVP_sha256();
            break;
        case TPM_ALG_SHA384:
            evp_hash_alg = EVP_sha384();
            break;
        default:
            ERROR("Unsupported hash alg.\n");
            return false;
    }
    //Set signature md parameter
    result = EVP_PKEY_CTX_set_signature_md(private_key_context, evp_hash_alg);
    if (result <= 0) {
        goto OPENSSL_ERROR;
    }
    //Calculate signature size (dry run)
    result = EVP_PKEY_sign(private_key_context, NULL, &siglen, data_to_sign->data,
                                                   get_lcp_hash_size(hash_alg));
    if (result <= 0) {
        goto OPENSSL_ERROR;
    }
    if (siglen != signature_block->size) {
        ERROR("ERROR: signature size incorrect.\n");
        return false;
    }
    //Do the signing
    result = EVP_PKEY_sign(private_key_context, signature_block->data, &siglen,
                               data_to_sign->data, get_lcp_hash_size(hash_alg));
    if (result <= 0) {
        goto OPENSSL_ERROR;
    }
    //All good, function end
    return true;

    //Error handling
    OPENSSL_ERROR:
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        return false;
}

uint16_t pkcs_get_hashalg(const unsigned char *data)
/*
From:
http://mpqs.free.fr/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp_EMC_Corporation_Public-Key_Cryptography_Standards_(PKCS).pdf#page=40
   EM=00∥01∥FF∥…∥FF∥00∥T - PKCS1.5 padding starts with 00 01 || 0xFF for padding ||
   00 || T - this is the DER encoded hash identifier and hash message
   T - SHA-1:       30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 ∥ H
   T - SHA-256:     30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 ∥ H
   T - SHA-384:     30 41 30 0D 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 ∥ H
   T - SHA-512:     30 51 30 0D 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 ∥ H

   E.g.
   SHA-256
   30 31 - sequence 0x31 bytes
      30 0D - sequence 0x0D bytes
         06 09 - OID (object ID) - 9 bytes
            60 86 48 01 65 03 04 02 01 - OID: SHA-256: FIPS180-3
         05 00 - parameters and size
      04 20 - octet of strings size 0x20 bytes
         H  - hash of a secret message
*/
{
    uint8_t der_oid = 0x06;
    size_t oid_size;

    if (data == NULL)
        return TPM_ALG_NULL;

    data += 2; //Skip 00 01
    //Skip 0xFFs padding and 00 after it
    do {
        data++;
    } while (*data == 0xFF);
    //Then move to der_oid
    data += 5;
    if (*data != der_oid)
        return TPM_ALG_NULL;
    data += 1;
    //Read oid size:
    oid_size = *data;
    if (oid_size == 0x05)
        return TPM_ALG_SHA1; //Only Sha1 has this size
    //Move to the last byte to see what alg is used
    data += oid_size;
    switch (*data)
    {
    case 0x01:
        return TPM_ALG_SHA256;
    case 0x02:
        return TPM_ALG_SHA384;
    case 0x03:
        return TPM_ALG_SHA512;
    default:
        return TPM_ALG_NULL;
    }
}

void buffer_reverse_byte_order(uint8_t *buffer, size_t length)
/*Works in place, modifies passed buffer*/
{
    uint8_t temp;
    int left_index = 0;
    int right_index = length - 1;
    while (right_index > left_index) {
        temp = buffer[right_index];
        buffer[right_index] = buffer[left_index];
        buffer[left_index] = temp;
        left_index++;
        right_index--;
    }
}

sized_buffer *allocate_sized_buffer(size_t size) {
    /*
        Allocate size bytes of memory for a buffer and return it
        or NULL on failure.
    */
    sized_buffer *buffer = NULL;
    if (size == 0) {
        ERROR("Error: buffer size must be at least 1.\n");
        return NULL;
    }
    buffer = malloc(size + offsetof(sized_buffer, data));
    if (buffer == NULL) {
        ERROR("Error: failed to allocate buffer.\n");
        return NULL;
    }
    return buffer;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
