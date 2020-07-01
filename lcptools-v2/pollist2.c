/*
 * pollist2.c:
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
#include <string.h>
#include <safe_lib.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "../include/lcp3_hlp.h"
#include "polelt_plugin.h"
#include "lcputils.h"
#include "pollist2.h"
#include "pollist2_1.h"
#include "polelt.h"
#include "pollist1.h"

//F-ction prototypes:
static bool verify_tpm20_ecdsa_sig(const lcp_policy_list_t2 *pollist, uint16_t keySize);
static bool verify_tpm20_rsa_sig(const lcp_policy_list_t2 *pollist);
static lcp_signature_t2 *read_ecdsa_pubkey(const char *pubkey_file);
static bool ecdsa_sign_list2_data(lcp_policy_list_t2 *pollist, const char* privkey_file);
static bool rsa_sign_list2_data(lcp_policy_list_t2 *pollist, const char *privkey_file, 
                                                              uint16_t hash_alg);
static lcp_policy_list_t2 *policy_list2_ecdsa_sign_init(lcp_policy_list_t2 *pollist,
                                            uint16_t rev_ctr,
                                            const char *pubkey_file,
                                            const char *privkey_file);
static lcp_policy_list_t2 *policy_list2_rsa_sign_init(lcp_policy_list_t2 *pollist,
                                          uint16_t rev_ctr,
                                          uint16_t hash_alg,
                                          const char *pubkey_file,
                                          const char *privkey_file);


lcp_list_t *read_policy_list_file(const char *file, bool fail_ok, bool *no_sigblock_ok)
{
    LOG("[read_policy_list_file]\n");
    if ( file == NULL || *file == '\0' || no_sigblock_ok == NULL ) {
        return NULL;
    }
    /* read existing file, if it exists */
    size_t len;
    lcp_list_t *pollist = read_file(file, &len, fail_ok);
    if ( pollist == NULL ) {
        return NULL;
    }
    uint16_t  version;
    memcpy_s((void*)&version,sizeof(version),(const void *)pollist,sizeof(uint16_t));
    if ( MAJOR_VER(version) == 1 ){
        LOG("read_policy_list_file: version=0x0100\n");
        bool no_sigblock;
        if ( !verify_tpm12_policy_list(&(pollist->tpm12_policy_list),
                      len, &no_sigblock, true) ) {
            free(pollist);
            return NULL;
        }

        if ( !*no_sigblock_ok && no_sigblock ) {
            ERROR("Error: policy list does not have sig_block\n");
            free(pollist);
            return NULL;
        }

        /* if there is no sig_block then create one w/ all 0s so that
           get_policy_list_size() will work correctly; it will be stripped
           when writing it back */
        lcp_signature_t *sig = get_tpm12_signature(&(pollist->tpm12_policy_list));
        if ( sig != NULL && no_sigblock ) {
            LOG("input file has no sig_block\n");
            size_t keysize = sig->pubkey_size;
            pollist = realloc(pollist, len + keysize);
            if ( pollist == NULL )
                return NULL;
            memset_s((void *)pollist + len, keysize, 0);
        }
        *no_sigblock_ok = no_sigblock;
        LOG("read policy list file succeed!\n");
        return pollist;
    }
    else if ( MAJOR_VER(version) == 2 ) {
        LOG("read_policy_list_file: version=0x0200\n");
        bool no_sigblock;
        if ( !verify_tpm20_policy_list(&(pollist->tpm20_policy_list),
                     len, &no_sigblock, true) ) {
            free(pollist);
            return NULL;
        }

        if ( !*no_sigblock_ok && no_sigblock ) {
            ERROR("Error: policy list does not have sig_block\n");
            free(pollist);
            return NULL;
        }

        /* if there is no sig_block then create one w/ all 0s so that
           get_policy_list_size() will work correctly; it will be stripped
           when writing it back */
        lcp_signature_t2 *sig = get_tpm20_signature(&(pollist->tpm20_policy_list));
        if ( sig != NULL && no_sigblock ) {
            LOG("input file has no sig_block\n");
            size_t keysize = 0;
            if ( pollist->tpm20_policy_list.sig_alg == TPM_ALG_RSASSA ) {
                LOG("read_policy_list_file: sig_alg == TPM_ALG_RSASSA\n");
                keysize = sig->rsa_signature.pubkey_size;
                pollist = realloc(pollist, len + keysize);
            }
            else if ( pollist->tpm20_policy_list.sig_alg == TPM_ALG_ECDSA ) {
                LOG("read_policy_list_file: sig_alg == TPM_ALG_ECDSA\n");
                keysize = sig->ecc_signature.pubkey_size;
                pollist = realloc(pollist, len + keysize);
            }

            if ( pollist == NULL )
                return NULL;
            memset_s((void *)pollist + len, keysize, 0);
        }
        *no_sigblock_ok = no_sigblock;

        LOG("read policy list file succeed!\n");
        return pollist;
    }
    DISPLAY("ERROR: unknown version.\n");
    return NULL; //if it got here, there must've been an error
}

bool verify_tpm20_policy_list(const lcp_policy_list_t2 *pollist, size_t size,
        bool *no_sigblock, bool size_is_exact)
{
    LOG("[verify_tpm20_policy_list]\n");
    if ( pollist == NULL )
        return false;

    if ( size < sizeof(*pollist) ) {
        ERROR("Error: data is too small (%u)\n", size);
        return false;
    }

    if ( MAJOR_VER(pollist->version) != MAJOR_VER(LCP_TPM20_POLICY_LIST_VERSION) ||
         MINOR_VER(pollist->version) > MINOR_VER(LCP_TPM20_POLICY_LIST2_MAX_MINOR) ) {
        ERROR("Error: unsupported version 0x%04x\n", pollist->version);
        return false;
    }

    if ( pollist->sig_alg != TPM_ALG_NULL &&
            pollist->sig_alg != TPM_ALG_RSASSA &&
            pollist->sig_alg != TPM_ALG_ECDSA &&
            pollist->sig_alg != TPM_ALG_SM2 ) {
        ERROR("Error: unsupported sig_alg %u\n", pollist->sig_alg);
        return false;
    }

    /* verify policy_elements_size */
    size_t base_size = offsetof(lcp_policy_list_t2, policy_elements);
    /* no sig, so size should be exact */
    if ( pollist->sig_alg == TPM_ALG_NULL ) {
        if ( size_is_exact &&
                base_size + pollist->policy_elements_size != size ) {
            ERROR("Error: size incorrect (no sig): 0x%x != 0x%x\n",
                    base_size + pollist->policy_elements_size, size);
            return false;
        }
        else if ( !size_is_exact &&
                base_size + pollist->policy_elements_size > size ) {
            ERROR("Error: size incorrect (no sig): 0x%x > 0x%x\n",
                    base_size + pollist->policy_elements_size, size);
            return false;
        }
    }
    /* verify size exactly later, after check sig field */
    else if ( pollist->sig_alg == TPM_ALG_RSASSA ) {
        LOG("verify_tpm20_policy_list: sig_alg == TPM_ALG_RSASSA\n");
        if ( base_size + sizeof(lcp_rsa_signature_t) +
                pollist->policy_elements_size  > size ) {
            ERROR("Error: size incorrect (sig min): 0x%x > 0x%x\n",
                    base_size + sizeof(lcp_rsa_signature_t) +
                    pollist->policy_elements_size, size);
            return false;
        }
    }
    else if ( pollist->sig_alg == TPM_ALG_ECDSA) {
        LOG("verify_tpm20_policy_list: sig_alg == TPM_ALG_ECDSA\n");
        if ( base_size + sizeof(lcp_ecc_signature_t) +
                pollist->policy_elements_size  > size ) {
            ERROR("Error: size incorrect (sig min): 0x%x > 0x%x\n",
                    base_size + sizeof(lcp_rsa_signature_t) +
                    pollist->policy_elements_size, size);
            return false;
        }
    }
    else if ( pollist->sig_alg == TPM_ALG_SM2 ) {
        LOG ("verify_tpm20_policy_list: sig_alg == TPM_ALG_SM2\n");
        return false;
    }

    /* verify sum of policy elements' sizes */
    uint32_t elts_size = 0;
    const lcp_policy_element_t *elt = pollist->policy_elements;
    while ( elts_size < pollist->policy_elements_size ) {
        if ( elts_size + elt->size > pollist->policy_elements_size ) {
            ERROR("Error: size incorrect (elt size): 0x%x > 0x%x\n",
                    elts_size + elt->size, pollist->policy_elements_size);
            return false;
        }
        elts_size += elt->size;
        elt = (void *)elt + elt->size;
    }
    if ( elts_size != pollist->policy_elements_size ) {
        ERROR("Error: size incorrect (elt size): 0x%x != 0x%x\n",
                elts_size, pollist->policy_elements_size);
        return false;
    }

    /* verify sig */
    if ( pollist->sig_alg == TPM_ALG_RSASSA ||
         pollist->sig_alg == TPM_ALG_ECDSA ||
         pollist->sig_alg == TPM_ALG_SM2 ) {
        lcp_signature_t2 *sig = (lcp_signature_t2 *)
            ((void *)&pollist->policy_elements + pollist->policy_elements_size);

        /* check size w/ sig_block */
        if ( !size_is_exact &&
             (base_size + pollist->policy_elements_size +
              get_tpm20_signature_size(sig, pollist->sig_alg) >
              size + sig->rsa_signature.pubkey_size)
              )
        {
            ERROR("Error: size incorrect (sig): 0x%x > 0x%x\n",
                    base_size + pollist->policy_elements_size +
                    get_tpm20_signature_size(sig, pollist->sig_alg),
                    size + sig->rsa_signature.pubkey_size);
            return false;
        }
        else if ( size_is_exact && base_size + pollist->policy_elements_size +
                get_tpm20_signature_size(sig,pollist->sig_alg) != size ) {
            /* check size w/o sig_block */
            if ( base_size + pollist->policy_elements_size +
                    get_tpm20_signature_size(sig, pollist->sig_alg) !=
                    size + sig->rsa_signature.pubkey_size ) {
                ERROR("Error: size incorrect (sig exact): 0x%x != 0x%x\n",
                        base_size + pollist->policy_elements_size +
                        get_tpm20_signature_size(sig, pollist->sig_alg),
                        size + sig->rsa_signature.pubkey_size);
                return false;
            }
            else {
                if ( no_sigblock != NULL )
                    *no_sigblock = true;
            }
        }
        else {
            if ( no_sigblock != NULL )
                *no_sigblock = false;
            if ( !verify_tpm20_pollist_sig(pollist) ) {
                ERROR("Error: signature does not verify\n");
                return false;
            }
        }
    }
    else {
        if ( no_sigblock != NULL )
            *no_sigblock = false;
    }

    LOG("verify tpm20 policy list succeed!\n");
    return true;

}

void display_tpm20_policy_list(const char *prefix,
        const lcp_policy_list_t2 *pollist, bool brief)
{
    if ( pollist == NULL )
        return;

    if ( prefix == NULL )
        prefix = "";

    DISPLAY("%s version: 0x%x\n", prefix, pollist->version);
    DISPLAY("%s sig_alg: 0x%x, %s\n", prefix, pollist->sig_alg, sig_alg_to_str(pollist->sig_alg));
    DISPLAY("%s policy_elements_size: 0x%x (%u)\n", prefix,
            pollist->policy_elements_size, pollist->policy_elements_size);

    char new_prefix[strnlen_s(prefix, 20)+8];
    strcpy_s(new_prefix, sizeof(new_prefix), prefix);
    strcat_s(new_prefix, sizeof(new_prefix), "    ");
    unsigned int i = 0;
    size_t elts_size = pollist->policy_elements_size;
    const lcp_policy_element_t *elt = pollist->policy_elements;
    while ( elts_size > 0 ) {
        DISPLAY("%s policy_element[%u]:\n", prefix, i++);
        display_policy_element(new_prefix, elt, brief);
        elts_size -= elt->size;
        elt = (void *)elt + elt->size;
    }

    lcp_signature_t2 *sig = get_tpm20_signature(pollist);
    if ( sig != NULL ) {
        DISPLAY("%s signature:\n", prefix);
        display_tpm20_signature(new_prefix, sig, pollist->sig_alg, brief);
    }
}

lcp_policy_list_t2 *create_empty_tpm20_policy_list(void)
{
    LOG("[create_empty_tpm20_policy_list]\n");
    lcp_policy_list_t2 *pollist = malloc(offsetof(lcp_policy_list_t,
                policy_elements));
    if ( pollist == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        return NULL;
    }
    pollist->version = LCP_TPM20_POLICY_LIST_VERSION;
    pollist->sig_alg = TPM_ALG_NULL;
    pollist->policy_elements_size = 0;

    LOG("create policy list succeed!\n");
    return pollist;
}

lcp_policy_list_t2 *add_tpm20_policy_element(lcp_policy_list_t2 *pollist,
        const lcp_policy_element_t *elt)
{
    LOG("[add_tpm20_policy_element]\n");
    if ( pollist == NULL || elt == NULL )
        return NULL;

    /* adding a policy element requires growing the policy list */
    size_t old_size = get_tpm20_policy_list_size(pollist);
    lcp_policy_list_t2 *new_pollist = realloc(pollist, old_size + elt->size);
    if ( new_pollist == NULL ) {
        ERROR("Error: failed to allocate memory\n");
        free(pollist);
        return NULL;
    }

    /* realloc() copies over previous contents */
    /* we add at the beginning of the elements list (don't want to overwrite
       a signature) */
    memmove_s((void *)&new_pollist->policy_elements + elt->size,
            old_size - offsetof(lcp_policy_list_t2, policy_elements),
            &new_pollist->policy_elements,
            old_size - offsetof(lcp_policy_list_t2, policy_elements));
    memcpy_s(&new_pollist->policy_elements, elt->size, elt, elt->size);
    new_pollist->policy_elements_size += elt->size;

    LOG("add tpm20 policy element succeed\n");
    return new_pollist;
}

bool del_tpm20_policy_element(lcp_policy_list_t2 *pollist, uint32_t type)
{
    if ( pollist == NULL )
        return false;

    /* find first element of specified type (there should only be one) */
    size_t elts_size = pollist->policy_elements_size;
    lcp_policy_element_t *elt = pollist->policy_elements;
    while ( elts_size > 0 ) {
        if ( elt->type == type ) {
            /* move everything up */
            size_t tot_size = get_tpm20_policy_list_size(pollist);
            size_t elt_size = elt->size;
            memmove_s(elt, pollist->policy_elements_size, (void *)elt + elt_size,
                    tot_size - ((void *)elt + elt_size - (void *)pollist));
            pollist->policy_elements_size -= elt_size;

            return true;
        }
        elts_size -= elt->size;
        elt = (void *)elt + elt->size;
    }

    return false;
}

bool verify_tpm20_ecdsa_sig(const lcp_policy_list_t2 *pollist, uint16_t keySize)
{
    /*This function prepares signature and key buffers that are later passed
    to the function that does actual verification.*/
    size_t bytes_to_hash;
    size_t digest_size;
    uint16_t hash_alg;
    bool result;
    unsigned char qx[keySize];
    unsigned char qy[keySize];
    unsigned char r_part[keySize];
    unsigned char s_part[keySize];
    tb_hash_t digest;
    lcp_ecc_signature_t *sig = NULL;
    LOG("[verify_tpm20_ecdsa_sig]\n");
    if (pollist == NULL) {
        ERROR("Error: policy list not defined.\n");
        return false;
    }
    if (keySize != MIN_ECC_KEY_SIZE && keySize != MAX_ECC_KEY_SIZE) {
        ERROR("Error: incorrect key size.\n");
        return false;
    }
    sig = (lcp_ecc_signature_t *) get_tpm20_signature(pollist);
    if (sig->pubkey_size != keySize) {
        ERROR("Error: sig->pubkey_size and keySize parameter are not the same.\n");
        return false;
    }
    if (keySize == MIN_ECC_KEY_SIZE) {
        hash_alg = TPM_ALG_SHA256;
        digest_size = SHA256_DIGEST_SIZE;
    }
    else {
        hash_alg = TPM_ALG_SHA384;
        digest_size = SHA384_DIGEST_SIZE;
    }
    bytes_to_hash = get_tpm20_policy_list_size(pollist) - (2*sig->pubkey_size);
    result = hash_buffer((const unsigned char *) pollist, bytes_to_hash, &digest, hash_alg);
    if (!result) {
        ERROR("Error: failed to hash list data.\n");
        return false;
    }
    //Copy key and sig buffers to arrays
    memcpy_s((void *)qx, keySize, (void *)sig->qx, keySize);
    memcpy_s((void *)qy, keySize, (void *)sig->qx+keySize, keySize);
    memcpy_s((void *)r_part, keySize, (void *)sig->qx+(2*keySize), keySize);
    memcpy_s((void *)s_part, keySize, (void *)sig->qx+(3*keySize), keySize);
    //Reverse arrays because openssl needs BE data
    buffer_reverse_byte_order(qx, keySize);
    buffer_reverse_byte_order(qy, keySize);
    buffer_reverse_byte_order(r_part, keySize);
    buffer_reverse_byte_order(s_part, keySize);
    return verify_ecdsa_signature((const unsigned char *) &digest, digest_size,
                                     qx, qy, keySize, hash_alg, r_part, s_part);
}

bool verify_tpm20_rsa_sig(const lcp_policy_list_t2 *pollist)
/*

*/
{
    sized_buffer *list_data = NULL;
    sized_buffer *public_key = NULL;
    sized_buffer *signature = NULL;
    lcp_signature_t2 *sig = NULL;
    bool result;

    LOG("[verify_tpm20_rsa_sig]");
    if (pollist == NULL) {
        ERROR("Error: policy list is not defined.\n");
        return false;
    }
    sig = get_tpm20_signature(pollist);
    if (sig == NULL) {
        ERROR("Error: failed to get signature.\n");
        return false;
    }

    list_data = allocate_sized_buffer((get_tpm20_policy_list_size(pollist) -
                                               sig->rsa_signature.pubkey_size));
    if (list_data == NULL) {
        ERROR("Error: failed to allocate buffer for list_data.\n");
        return false;
    }
    public_key = allocate_sized_buffer(sig->rsa_signature.pubkey_size);
    if (public_key == NULL) {
        ERROR("Error: failed to allocate buffer for public_key.\n");
        free(list_data);
        return false;
    }
    signature = allocate_sized_buffer(sig->rsa_signature.pubkey_size);
    if (signature == NULL) {
        ERROR("Error: failed to allocate buffer for signature.\n");
        free(list_data);
        free(public_key);
        return false;
    }

    list_data->size = get_tpm20_policy_list_size(pollist) - sig->rsa_signature.pubkey_size;
    public_key->size = sig->rsa_signature.pubkey_size;
    signature->size = sig->rsa_signature.pubkey_size;

    memcpy_s((void *) list_data->data, list_data->size, (const void *) pollist,
                                                               list_data->size);
    memcpy_s((void *) public_key->data, public_key->size,
             (const void *) sig->rsa_signature.pubkey_value,
             sig->rsa_signature.pubkey_size);
    memcpy_s((void *) signature->data, signature->size,
                  (const void *) get_tpm20_sig_block(pollist), signature->size);
    //Key and sig must be BE for openssl, and are LE in list, so reverse:
    buffer_reverse_byte_order((uint8_t *) public_key->data, public_key->size);
    buffer_reverse_byte_order((uint8_t *) signature->data, signature->size);

    //Any value for hashalg, it will be overwritten inside function
    result = verify_rsa_signature(list_data, public_key, signature, TPM_ALG_NULL,
                                            pollist->sig_alg, pollist->version);
    free(list_data);
    free(public_key);
    free(signature);
    return result;
}

bool verify_tpm20_pollist_sig(const lcp_policy_list_t2 *pollist)
{
    LOG("[verify_tpm20_pollist_sig]\n");
    if (pollist == NULL) {
        ERROR("Error: policy list is not defined.\n");
        return false;
    }

    lcp_signature_t2 *sig = get_tpm20_signature(pollist);
    if ( sig == NULL )
        return true;

    if ( pollist->sig_alg == TPM_ALG_RSASSA ) {
        return verify_tpm20_rsa_sig(pollist);
    }
    else if ( pollist->sig_alg == TPM_ALG_ECDSA ) {
        return verify_tpm20_ecdsa_sig(pollist, sig->ecc_signature.pubkey_size);
    }
    else if ( pollist->sig_alg == TPM_ALG_SM2 ) {
        LOG("verify_tpm20_pollist_sig: sig_alg == TPM_ALG_SM2\n");
        return false;
    }

    return false;
}

void display_tpm20_signature(const char *prefix, const lcp_signature_t2 *sig,
        const uint16_t sig_alg, bool brief)
{
    if( sig_alg == TPM_ALG_RSASSA) {
        char new_prefix[strnlen_s(prefix, 20)+8];
        strcpy_s(new_prefix, sizeof(new_prefix), prefix);
        strcat_s(new_prefix, sizeof(new_prefix), "\t");

        DISPLAY("%s revocation_counter: 0x%x (%u)\n", prefix,
                sig->rsa_signature.revocation_counter,
                sig->rsa_signature.revocation_counter);
        DISPLAY("%s pubkey_size: 0x%x (%u)\n", prefix,
                sig->rsa_signature.pubkey_size,
                sig->rsa_signature.pubkey_size);

        if ( brief )
            return;

        DISPLAY("%s pubkey_value:\n", prefix);
        print_hex(new_prefix, sig->rsa_signature.pubkey_value,
                sig->rsa_signature.pubkey_size);
        DISPLAY("%s sig_block:\n", prefix);
        print_hex(new_prefix, (void *)&sig->rsa_signature.pubkey_value +
                sig->rsa_signature.pubkey_size, sig->rsa_signature.pubkey_size);
    }
    else if ( sig_alg == TPM_ALG_ECDSA ) {
        char new_prefix[strnlen_s(prefix, 20)+8];
        strcpy_s(new_prefix, sizeof(new_prefix), prefix);
        strcat_s(new_prefix, sizeof(new_prefix), "\t");

        DISPLAY("%s revocation_counter: 0x%x (%u)\n", prefix,
                sig->ecc_signature.revocation_counter,
                sig->ecc_signature.revocation_counter);
        DISPLAY("%s pubkey_size: 0x%x (%u)\n", prefix,
                sig->ecc_signature.pubkey_size,
                sig->ecc_signature.pubkey_size);
        DISPLAY("%s reserved: 0x%x (%u)\n", prefix,
                sig->ecc_signature.reserved, sig->ecc_signature.reserved);

        if ( brief )
            return;

        DISPLAY("%s qx:\n", prefix);
        print_hex(new_prefix, (void *)&sig->ecc_signature.qx,
                sig->ecc_signature.pubkey_size);
        DISPLAY("%s qy:\n", prefix);
        print_hex(new_prefix, (void *)&sig->ecc_signature.qx +
                sig->ecc_signature.pubkey_size, sig->ecc_signature.pubkey_size);
        DISPLAY("%s r:\n", prefix);
        print_hex(new_prefix, (void *)&sig->ecc_signature.qx +
                (2*sig->ecc_signature.pubkey_size), sig->ecc_signature.pubkey_size);
        DISPLAY("%s s:\n", prefix);
        print_hex(new_prefix, (void *)&sig->ecc_signature.qx +
                (3*sig->ecc_signature.pubkey_size), sig->ecc_signature.pubkey_size);
    }
    else if ( sig_alg == TPM_ALG_SM2 ) {
        LOG("display_tpm20_signature: sig_alg == TPM_ALG_SM2\n");
    }
}

lcp_policy_list_t2 *add_tpm20_signature(lcp_policy_list_t2 *pollist,
        const lcp_signature_t2 *sig, const uint16_t sig_alg)
{
    LOG("[add_tpm20_signature]\n");
    if ( pollist == NULL || sig == NULL ) {
        LOG("add_tpm20_signature: pollist == NULL || sig == NULL\n");
        return NULL;
    }

    if ( sig_alg == TPM_ALG_RSASSA) {
        LOG("add_tpm20_signature: sig_alg == TPM_ALG_RSASSA\n");
        /* adding a signature requires growing the policy list */
        size_t old_size = get_tpm20_policy_list_size(pollist);
        size_t sig_size = sizeof(lcp_rsa_signature_t) +
                                 2*sig->rsa_signature.pubkey_size;
        LOG("add_tpm20_signature: sizeof(lcp_rsa_signature_t)=%d\n",
                sizeof(lcp_rsa_signature_t));
        lcp_policy_list_t2 *new_pollist = realloc(pollist, old_size + sig_size);
        if ( new_pollist == NULL ) {
            ERROR("Error: failed to allocate memory\n");
            free(pollist);
            return NULL;
        }

        /* realloc() copies over previous contents */

        size_t sig_begin = old_size;
        /* if a signature already exists, replace it */
        lcp_signature_t2 *curr_sig = get_tpm20_signature(new_pollist);
        if ( curr_sig != NULL )
            sig_begin = (void *)curr_sig - (void *)new_pollist;
        memcpy_s((void *)new_pollist + sig_begin, sig_size, sig, sig_size);
        new_pollist->sig_alg = sig_alg;
        return new_pollist;
    }
    else if ( sig_alg == TPM_ALG_ECDSA ) {
        LOG("add_tpm20_signature: sig_alg == TPM_ALG_ECDSA\n");
        /* adding a signature requires growing the policy list */
        size_t old_size = get_tpm20_policy_list_size(pollist);
        size_t sig_size = sizeof(lcp_ecc_signature_t) +
                4*sig->ecc_signature.pubkey_size;
        lcp_policy_list_t2 *new_pollist = realloc(pollist, old_size + sig_size);
        if ( new_pollist == NULL ) {
            ERROR("Error: failed to allocate memory\n");
            free(pollist);
            return NULL;
        }

        /* realloc() copies over previous contents */

        size_t sig_begin = old_size;
        /* if a signature already exists, replace it */
        lcp_signature_t2 *curr_sig = get_tpm20_signature(new_pollist);
        if ( curr_sig != NULL )
            sig_begin = (void *)curr_sig - (void *)new_pollist;

        memcpy_s((void *)new_pollist + sig_begin, sig_size, sig, sig_size);
        new_pollist->sig_alg = sig_alg;
        LOG("add tpm20 signature succeed!\n");
        return new_pollist;
    }
    else if ( sig_alg == TPM_ALG_SM2 ) {
        LOG("add_tpm20_signature: sig_alg == TPM_ALG_SM2\n");
        return NULL;
    }
    return NULL;
}

unsigned char *get_tpm20_sig_block(const lcp_policy_list_t2 *pollist)
{
    if ( pollist->sig_alg == TPM_ALG_RSASSA ) {
        lcp_signature_t2 *sig = get_tpm20_signature(pollist);
        if ( sig == NULL )
            return NULL;
        return (unsigned char *)&sig->rsa_signature.pubkey_value +
                sig->rsa_signature.pubkey_size;
    }
    else if ( pollist->sig_alg == TPM_ALG_ECDSA ) {
        lcp_signature_t2 *sig = get_tpm20_signature(pollist);
        if ( sig == NULL )
            return NULL;
        return (unsigned char *)&sig->ecc_signature.qx +
                sig->ecc_signature.pubkey_size;
    }
    else if ( pollist->sig_alg == TPM_ALG_SM2 ) {
        LOG("get_tpm_20_sig_block: sig_alg == TPM_ALG_SM2\n");
        return NULL;
    }

    return NULL;
}

void calc_tpm20_policy_list_hash(const lcp_policy_list_t2 *pollist,
        lcp_hash_t2 *hash, uint16_t hash_alg)
{
    LOG("[calc_tpm20_policy_list_hash]\n");
    uint8_t *buf_start = (uint8_t *)pollist;
    size_t len = get_tpm20_policy_list_size(pollist);

    if ( pollist->sig_alg == TPM_ALG_RSASSA ) {
        LOG("calc_tpm20_policy_list_hash: sig_alg == TPM_ALG_RSASSA\n");
        lcp_signature_t2 *sig = get_tpm20_signature(pollist);
        if ( sig == NULL )
            return;
        buf_start = sig->rsa_signature.pubkey_value;
        len = sig->rsa_signature.pubkey_size;
    }
    else if ( pollist->sig_alg == TPM_ALG_ECDSA ) {
        LOG("calc_tpm20_policy_list_hash: sig_alg == TPM_ALG_ECDSA\n");
        lcp_signature_t2 *sig = get_tpm20_signature(pollist);
        if ( sig == NULL )
            return;
        buf_start = sig->ecc_signature.qx + sig->ecc_signature.pubkey_size;
        len = sig->ecc_signature.pubkey_size;
    }

    hash_buffer(buf_start, len, (tb_hash_t *)hash, hash_alg);
}

bool write_tpm20_policy_list_file(const char *file,
                const lcp_policy_list_t2 *pollist)
{
    LOG("[write_tpm20_policy_list_file]\n");
    size_t len = get_tpm20_policy_list_size(pollist);

    /* check if sig_block all 0's--if so then means there was no sig_block
       when file was read but empty one was added, so don't write it */
    lcp_signature_t2 *sig = get_tpm20_signature(pollist);
    if ( sig != NULL ) {
        if ( pollist->sig_alg == TPM_ALG_RSASSA ) {
            LOG("write_tpm20_policy_list_file: sig_alg == TPM_ALG_RSASSA\n");
            uint8_t *sig_block = (uint8_t *)&sig->rsa_signature.pubkey_value +
                                         sig->rsa_signature.pubkey_size;
            while ( sig_block < ((uint8_t *)pollist + len) ) {
                if ( *sig_block++ != 0 )
                    break;
            }
            /* all 0's */
            if ( sig_block == ((uint8_t *)pollist + len) ) {
                LOG("output file has no sig_block\n");
                len -= sig->rsa_signature.pubkey_size;
            }
        }
    }

    return write_file(file, pollist, len);
}

lcp_signature_t2 *read_rsa_pubkey_file(const char *file)
{
    LOG("read_rsa_pubkey_file\n");
    FILE *fp = fopen(file, "r");
    if ( fp == NULL ) {
        ERROR("Error: failed to open .pem file %s: %s\n", file,
                strerror(errno));
        return NULL;
    }

    RSA *pubkey = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    if ( pubkey == NULL ) {
        ERR_load_crypto_strings();
        ERROR("Error: failed to read .pem file %s: %s\n", file,
                ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
        fclose(fp);
        return NULL;
    }

    unsigned int keysize = RSA_size(pubkey);
    if ( keysize == 0 ) {
        ERROR("Error: public key size is 0\n");
        RSA_free(pubkey);
        fclose(fp);
        return NULL;
    }

    lcp_signature_t2 *sig = malloc(sizeof(lcp_rsa_signature_t) + 2*keysize);
    if ( sig == NULL ) {
        ERROR("Error: failed to allocate sig\n");
        RSA_free(pubkey);
        fclose(fp);
        return NULL;
    }
    const BIGNUM *modulus = NULL;
    memset_s(sig, sizeof(lcp_rsa_signature_t) + 2*keysize, 0);
    sig->rsa_signature.pubkey_size = keysize;

    /* OpenSSL Version 1.1.0 and later don't allow direct access to RSA 
       stuct */
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        RSA_get0_key(pubkey, &modulus, NULL, NULL);
    #else
        modulus = pubkey->n;
    #endif

    unsigned char key[keysize];
    BN_bn2bin(modulus, key);
    /* openssl key is big-endian and policy requires little-endian, so reverse
       bytes */
    for ( unsigned int i = 0; i < keysize; i++ )
        sig->rsa_signature.pubkey_value[i] = *(key + (keysize - i - 1));

    if ( verbose ) {
        LOG("read_rsa_pubkey_file: signature:\n");
        display_tpm20_signature("    ", sig, TPM_ALG_RSASSA, false);
    }

    LOG("read rsa pubkey succeed!\n");
    RSA_free(pubkey);
    fclose(fp);
    return sig;
}

lcp_signature_t2 *read_ecdsa_pubkey(const char *pubkey_file)
{
    lcp_signature_t2 *sig = NULL;
    FILE *fp = NULL;
    const EC_KEY *pubkey = NULL;
    const EC_POINT *pubpoint = NULL;
    const EC_GROUP *pubgroup = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *ctx = NULL;
    uint8_t *qx = NULL;
    uint8_t *qy = NULL;

    uint16_t keySize;
    uint16_t keySizeBytes;
    int result;

    LOG("read ecdsa pubkey file for signature 2.1.\n");
    fp = fopen(pubkey_file, "r");
    if ( fp == NULL) {
        ERROR("ERROR: cannot open file.\n");
        goto ERROR;
    }
    pubkey = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
    if ( pubkey == NULL ) {
        goto OPENSSL_ERROR;
    }
    //Close the file
    fclose(fp);
    fp = NULL;

    pubpoint = EC_KEY_get0_public_key(pubkey);
    if ( pubpoint == NULL ) {
        goto OPENSSL_ERROR;
    }
    pubgroup = EC_KEY_get0_group(pubkey);
    if ( pubgroup == NULL ) {
        goto OPENSSL_ERROR;
    }

    x = BN_new();
    y = BN_new();
    ctx = BN_CTX_new();
    if ( x == NULL|| y == NULL || ctx == NULL) {
        goto OPENSSL_ERROR;
    }
    result = EC_POINT_get_affine_coordinates_GFp(pubgroup, pubpoint, x, y, ctx);
    if (result <= 0) {
        goto OPENSSL_ERROR;
    }
    keySize = BN_num_bytes(x)*8;
    if (BN_num_bytes(x) != BN_num_bytes(y)) {
        ERROR("ERROR: key coordinates are not the same length.");
        goto ERROR;
    }
    if ( keySize != 256 && keySize != 384 ) {
        ERROR("ERROR: keySize 0x%X is not 0x%X or 0x%X.\n", keySize/8, MIN_ECC_KEY_SIZE,
                                                              MAX_ECC_KEY_SIZE);
        goto ERROR;
    }

    keySizeBytes = BN_num_bytes(x);
    //BE arrays for data from openssl
    qx = malloc(sizeof(lcp_ecc_signature_t) + (2*keySizeBytes));
    if (qx == NULL) {
        ERROR("Failed to allocate memory for public key.\n");
        goto ERROR;
    }
    qy = malloc(sizeof(lcp_ecc_signature_t) + (2*keySizeBytes));
    if (qy == NULL) {
        ERROR("Failed to allocate memory for public key.\n");
        goto ERROR;
    }

    if ( keySize/8 != BN_num_bytes(x) || keySize/8 != BN_num_bytes(y) ) {
        ERROR("ERROR: keySize 0x%X is not 0x%X or 0x%X.\n", keySizeBytes,
                                            MIN_ECC_KEY_SIZE, MAX_ECC_KEY_SIZE);
        goto ERROR;
    }

    sig = calloc(1, sizeof(lcp_ecc_signature_t)+(4*keySizeBytes)); //qx, qy, r and s
    if (sig == NULL) {
        ERROR("Error: failed to allocate signature.\n");
        return NULL;
    }

    sig->ecc_signature.pubkey_size = keySizeBytes; //in bytes
    sig->ecc_signature.reserved = 0x0;

    if (!BN_bn2bin(x, qx)) {
        goto OPENSSL_ERROR;
    }
    if (!BN_bn2bin(y, qy)) {
        goto OPENSSL_ERROR;
    }

    //Flip BE to LE
    buffer_reverse_byte_order((uint8_t *) qx, keySizeBytes);
    buffer_reverse_byte_order((uint8_t *) qy, keySizeBytes);

    //Start copying - ecc_signature.qx has length 4*keysize
    result = memcpy_s(
        (void *) sig->ecc_signature.qx, 4*keySizeBytes, qx, keySizeBytes
    );
    if ( result != EOK ) {
        ERROR("ERROR: Cannot copy key data to LCP list\n");
        goto ERROR;
    }
    result = memcpy_s(
        (void *) sig->ecc_signature.qx + keySizeBytes, 3*keySizeBytes, qy, keySizeBytes
    );
    if ( result != EOK ) {
        ERROR("ERROR: Cannot copy key data to LCP list\n");
        goto ERROR;
    }
    //All good, free resuources:
    free(qx);
    free(qy);
    OPENSSL_free((void *) pubkey);
    OPENSSL_free((void *) pubpoint);
    OPENSSL_free((void *) pubgroup);
    OPENSSL_free((void *) ctx);
    OPENSSL_free((void *) x);
    OPENSSL_free((void *) y);
    return sig;

    //Errors:
    OPENSSL_ERROR:
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
    ERROR:
        //Free all allocated mem
        if (fp != NULL)
            fclose(fp);
        if (sig != NULL)
            free(sig);
        if (qx != NULL)
            free(qx);
        if (qy != NULL)
            free(qy);
        if (pubkey != NULL)
            OPENSSL_free((void *) pubkey);
        if (pubpoint != NULL)
            OPENSSL_free((void *) pubpoint);
        if (pubgroup != NULL)
            OPENSSL_free((void *) pubgroup);
        if (ctx != NULL)
            OPENSSL_free((void *) ctx);
        if (x != NULL)
            OPENSSL_free((void *) x);
        if (y != NULL)
            OPENSSL_free((void *) y);
        return NULL;
}

bool ecdsa_sign_list2_data(lcp_policy_list_t2 *pollist, const char* privkey_file)
{
    /*
    This function: Performs the signing operation on the policy list data 
    using OpenSSL functions.

    In: pointer to policy list structure to sign, path to private key

    Out: True on success, false on failure
    */

    LOG("[ecdsa_sign_tpm20_list_data]\n");

    lcp_signature_t2 *sig = NULL;
    FILE *fp = NULL;
    EC_KEY *ec_priv = NULL;
    EVP_PKEY *evp_priv_key = NULL;
    ECDSA_SIG *ecdsasig = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    tb_hash_t digest;
    size_t digest_size;
    size_t bytes_to_hash_num;
    uint16_t hashalg;
    uint16_t keysize;
    uint16_t BN_r_size;
    uint16_t BN_s_size;
    int evp_size;
    int status; //For openssl that return ints status
    bool result;
    unsigned char *sig_r = NULL;
    unsigned char *sig_s = NULL;

    if (pollist == NULL) {
        ERROR("Error: policy list not initialized.\n");
        return NULL;
    }
    sig = get_tpm20_signature(pollist);
    if ( sig == NULL) {
        ERROR("ERROR: failed to get lcp signature.\n");
        goto ERROR;
    }

    keysize = sig->ecc_signature.pubkey_size; //Is in bytes
    if (keysize == MIN_ECC_KEY_SIZE) {
        hashalg = TPM_ALG_SHA256;
        digest_size = SHA256_DIGEST_SIZE;
    }
    else {
        hashalg = TPM_ALG_SHA384;
        digest_size = SHA384_DIGEST_SIZE;
    }

    fp = fopen(privkey_file, "r");
    if ( fp == NULL ) {
        ERROR("Error: failed to open .pem file %s: %s\n", privkey_file,
        strerror(errno));
        goto ERROR;
    }
    //Init evp private key
    ec_priv = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    if ( ec_priv == NULL) {
        goto OPENSSL_ERROR;
    }
    //Close file
    fclose(fp);
    fp = NULL;

    evp_priv_key = EVP_PKEY_new();
    if (evp_priv_key == NULL) {
        goto OPENSSL_ERROR;
    }

    if (!EVP_PKEY_assign_EC_KEY(evp_priv_key, ec_priv)) {
        goto OPENSSL_ERROR;
    }
    evp_size = EVP_PKEY_bits(evp_priv_key);
    if (keysize != evp_size/8) {
        ERROR("ERROR: incorrect private key size - 0x%X, expected 0x%x\n",
                                                             evp_size/8, keysize);
        goto ERROR;
    }
    //We will hash all list up to the signature block
    bytes_to_hash_num = get_tpm20_policy_list_size(pollist) - (2 * keysize);
    if (verbose) {
        LOG("Data to hash:\n");
        print_hex("       ", (const unsigned char *) pollist, bytes_to_hash_num);
    }
    result = hash_buffer((const unsigned char *) pollist, bytes_to_hash_num,
                                                            &digest, hashalg);
    if ( !result ) {
        ERROR("Error: failed to hash list\n");
        goto ERROR;
    }
    if ( verbose ) {
        LOG("List data digest:\n");
        print_hex("", &digest, digest_size);
    }

    ecdsasig = ECDSA_do_sign((const unsigned char *)&digest, digest_size, ec_priv);
    if ( ecdsasig == NULL) {
        goto OPENSSL_ERROR;
    }

    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
        ECDSA_SIG_get0(ecdsasig, &r, &s);
    #else
        r = ecdsasig->r;
        s = ecdsasig->s;
    #endif

    BN_r_size = BN_num_bytes(r);
    BN_s_size = BN_num_bytes(s);
    if (BN_r_size != keysize || BN_s_size != keysize) {
        ERROR("ERROR: Signature size incorrect.\n");
        goto ERROR;
    }
    sig_r = malloc(keysize);
    if (sig_r == NULL) {
        ERROR("Error: failed to allocate memory for signature data.\n");
        goto ERROR;
    }
    sig_s = malloc(keysize);
    if (sig_s == NULL) {
        ERROR("Error: failed to allocate memory for signature data.\n");
        goto ERROR;
    }
    status = BN_bn2bin(r,sig_r);
    if (!status)
        goto OPENSSL_ERROR;
    status = BN_bn2bin(s,sig_s);
    if (!status)
        goto OPENSSL_ERROR;

    buffer_reverse_byte_order((uint8_t *) sig_r, keysize);
    buffer_reverse_byte_order((uint8_t *) sig_s, keysize);

    status = memcpy_s (
        (void *) sig->ecc_signature.qx+(2*keysize),
        2*keysize, sig_r, BN_r_size
    );
    if (status != EOK) {
        ERROR("ERROR: failed to copy signature data to LCP signature.\n");
        goto ERROR;
    }
    status = memcpy_s (
        (void *) sig->ecc_signature.qx+(3*keysize),
        keysize, sig_s, BN_r_size
    );

    if (status != EOK) {
        ERROR("ERROR: failed to copy signature data to LCP signature.\n");
        goto ERROR;
    }

    if (verbose) {
        DISPLAY("LCP_SIGNATURE2: \n");
        display_tpm20_signature("    ", sig, TPM_ALG_ECDSA, false);
    }
    //Free resuources:
    free(sig_r);
    free(sig_s);
    OPENSSL_free((void*) ec_priv);
    OPENSSL_free((void*) evp_priv_key);
    OPENSSL_free((void*) r);
    OPENSSL_free((void*) s);
    OPENSSL_free((void*) ecdsasig);
    return true;

    OPENSSL_ERROR:
        ERR_load_crypto_strings();
        ERROR("OpenSSL error: %s", ERR_error_string(ERR_get_error(), NULL));
        ERR_free_strings();
    ERROR:
        if (fp != NULL)
            fclose(fp);
        if (sig_r != NULL)
            free(sig_r);
        if (sig_s != NULL)
            free(sig_s);
        if (ec_priv != NULL)
            OPENSSL_free((void *) ec_priv);
        if (evp_priv_key != NULL)
            OPENSSL_free((void *) evp_priv_key);
        if (ecdsasig != NULL)
            OPENSSL_free((void *) ecdsasig);
        if (r != NULL)
            OPENSSL_free((void *) r);
        if (s != NULL)
            OPENSSL_free((void *) s);
        return false;
}

bool rsa_sign_list2_data(lcp_policy_list_t2 *pollist, const char *privkey_file,
                                                              uint16_t hash_alg)
/*
    This function: Performs the signing operation on the policy list data 
    using OpenSSL functions.

    In: pointer to policy list structure to sign, path to private key, hash 
    algorithm to use.

    Out: True on success, false on failure
*/
{
    sized_buffer *signature_block = NULL; //Will hold signature block
    sized_buffer *data_to_sign = NULL; //Will hold digest of list data
    bool status;
    size_t key_size;
    size_t list_data_len;
    EVP_PKEY_CTX *private_key_context = NULL;

    LOG("rsa_sign_list_data\n");
    if ( pollist == NULL || privkey_file == NULL ) {
        ERROR("Error: policy list or private key are not defined.\n");
        return false;
    }

    lcp_signature_t2 *sig = get_tpm20_signature(pollist);
    if ( sig == NULL ) {
        ERROR("Error: failed to get lcp signature.\n");
        return false;
    }

    key_size = sig->rsa_signature.pubkey_size;
    //List is signed up to but not including its signature block field.
    list_data_len = get_tpm20_policy_list_size(pollist) - key_size;

    signature_block = allocate_sized_buffer(key_size);
    if (signature_block == NULL) {
        ERROR("Error failed to allocate buffer.\n");
        return false;
    }

    data_to_sign = allocate_sized_buffer(get_lcp_hash_size(hash_alg));
    if (data_to_sign == NULL) {
        ERROR("Error failed to allocate buffer.\n");
        status = false;
        goto END;
    }
    if (verbose) {
        DISPLAY("Data to hash:\n");
        print_hex("       ", (const unsigned char *) pollist, list_data_len);
    }
    signature_block->size = key_size;
    data_to_sign->size = get_lcp_hash_size(hash_alg);
    status = hash_buffer((const unsigned char *) pollist, list_data_len,
                                    (tb_hash_t *) data_to_sign->data, hash_alg);
    if ( !status ) {
        ERROR("Error: failed to hash list\n");
        //status is false
        goto END;
    }

    if ( verbose ) {
        LOG("digest:\n");
        print_hex("", (const void *) data_to_sign->data, get_hash_size(hash_alg));
    }

    private_key_context = rsa_get_sig_ctx(privkey_file, key_size);
    if (private_key_context == NULL) {
        ERROR("Error: failed to initialize EVP context.\n");
        status = false;
        goto END;
    }
    //Now sign:
    status = rsa_ssa_pss_sign(signature_block, data_to_sign, pollist->sig_alg,
                                                 hash_alg, private_key_context);
    if (!status) {
        ERROR("Error: failed to sign list data.\n");
        //status is false
        goto END;
    }

    //Flip signature endianness
    buffer_reverse_byte_order((uint8_t *) signature_block->data, signature_block->size);
    memcpy_s((void *) sig->rsa_signature.pubkey_value+key_size, key_size,
                    (const void *) signature_block->data, signature_block->size);
    if ( verbose ) {
        LOG("Signature: \n");
        display_tpm20_signature("    ", sig, pollist->sig_alg, false);
    }
    END:
        //Free resources and return
        if (signature_block != NULL) {
            free(signature_block);
        }
        if (data_to_sign != NULL) {
            free(data_to_sign);
        }
        OPENSSL_free((void *) private_key_context);
        return status;
}

lcp_policy_list_t2 *policy_list2_ecdsa_sign_init(lcp_policy_list_t2 *pollist,
                                            uint16_t rev_ctr,
                                            const char *pubkey_file,
                                            const char *privkey_file)
{
    /*
    This function: Initializes signing process using ECDSA algorithm:
    1)Reads public key file
    2)Generates signature structure and adds it to list
    3)Calls a function to sign the list using private key
    
    In: Policy list structure, revocation counter (user input), paths to public
    and private key

    Out: policy list structure containing public key and signature data or 
    NULL on failure.
    */
    lcp_signature_t2 *sig = NULL;
    bool result;

    LOG("LCP_POLICY_LIST2 sign using ECDSA.\n");
    if (pollist == NULL) {
        ERROR("Error: lcp policy list is not defined.\n");
        return NULL;
    }
    sig = read_ecdsa_pubkey(pubkey_file);
    if (sig == NULL) {
        ERROR("Error: failed to read ec public key.\n");
        return NULL;
    }
    sig->ecc_signature.revocation_counter = rev_ctr;
    if (verbose) {
        DISPLAY("lcp_signature_t2: \n");
        display_tpm20_signature("    ", sig, TPM_ALG_ECDSA, false);
    }
    pollist = add_tpm20_signature(pollist, sig, TPM_ALG_ECDSA);
    if (pollist == NULL) {
        ERROR("Error: failed to add lcp_signature_2_1 to list.\n");
        free(sig);
        return NULL;
    }
    result = ecdsa_sign_list2_data(pollist, privkey_file);
    if (!result) {
        ERROR("Error: failed to sign list data.\n");
        free(sig);
        return NULL;
    }
    free(sig);
    return pollist;
}

lcp_policy_list_t2 *policy_list2_rsa_sign_init(lcp_policy_list_t2 *pollist,
                                          uint16_t rev_ctr,
                                          uint16_t hash_alg,
                                          const char *pubkey_file,
                                          const char *privkey_file)
{
    /*
    This function: Initializes signing process using RSA algorithm:
    1)Reads public key file
    2)Generates signature structure and adds it to list
    3)Calls a function to sign the list using private key
    
    In: Policy list structure, revocation counter, hash alg, paths to public
    and private key

    Out: policy list structure containing public key and signature data or 
    NULL on failure.
    */
    lcp_signature_t2 *sig = NULL;
    bool result;
    LOG("LCP_POLICY_LIST2 sign using RSA-SSA\n");
    if (pollist == NULL) {
        return NULL;
    }
    //pollist->sig_alg = sig_alg;
    sig = read_rsa_pubkey_file(pubkey_file);
    if (sig == NULL) {
        ERROR("Error: failed to read public key.\n");
        free(pollist);
        return NULL;
    }

    if ( (sig->rsa_signature.pubkey_size != 128 /* 1024 bits */)
        && (sig->rsa_signature.pubkey_size != 256 /* 2048 bits */)
        && (sig->rsa_signature.pubkey_size != 384 /* 3072 bits */) ) {
        ERROR("Error: public key size is not 1024/2048/3072 bits\n");
        free(sig);
        free(pollist);
        return NULL;
    }
    //Add signature to list
    sig->rsa_signature.revocation_counter = rev_ctr;
    pollist = add_tpm20_signature(pollist, sig, TPM_ALG_RSASSA);
    if (pollist == NULL) {
        free(sig);
        free(pollist);
        return NULL;
    }
    //Sign list data
    result = rsa_sign_list2_data(pollist, privkey_file, hash_alg);
    if (!result) {
        ERROR("Error: failed to sign policy list data.\n");
        free(sig);
        free(pollist);
        return NULL;
    }
    free(sig);
    return pollist;
}

bool sign_lcp_policy_list_t2(sign_user_input user_input)
{
    /*
    This function: starts signing procedure for the LCP list.

    In: structure with user input containing required info: pub and priv key paths,
    sig algs, list file.

    Out: true on success false on failure.
    */
    bool no_sigblock_ok;
    bool write_ok;
    lcp_policy_list_t2 *pollist = NULL;

    pollist = (lcp_policy_list_t2 *) read_policy_list_file(user_input.list_file, false, &no_sigblock_ok);
    if (pollist == NULL) {
        ERROR("Error: failed to read policy list file.\n");
        return false;
    }
    //We checked user-set sigalg in main, so just check if sigalg is not rsapss
    if (user_input.sig_alg == TPM_ALG_RSAPSS) {
        ERROR("Error: TPM_ALG_RSAPSS algorithm unsupported for LCP_POLICY_LIST2.\n"
              "Use LCP_POLICY_LIST2_1 (lcp list version 0x300).\n");
        free(pollist);
        return false;
    }
    //Depending on the sig alg we call one of two functions
    switch (user_input.sig_alg)
    {
    case TPM_ALG_RSASSA:
        pollist = policy_list2_rsa_sign_init(pollist, 
                                        user_input.rev_ctr,
                                        user_input.hash_alg,
                                        user_input.pubkey_file,
                                        user_input.privkey_file);
        break;
    case TPM_ALG_ECDSA:
        pollist = policy_list2_ecdsa_sign_init(pollist, user_input.rev_ctr,
                               user_input.pubkey_file, user_input.privkey_file);
        break;
    default:
        //Error
        DISPLAY("Unsupported signature algorithm\n");
        free(pollist);
        return false;
    }
    if (pollist == NULL) {
        ERROR("Error: failed to sign policy list\n");
        return false;
    }
    write_ok =  write_tpm20_policy_list_file(user_input.list_file, pollist);
    free(pollist);

    return write_ok;
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
