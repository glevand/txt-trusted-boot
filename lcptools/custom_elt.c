/*
 * custom_elt.c: custom (user/ISV/etc. -defined) policy element
 *               (LCP_MLE_ELEMENT) plugin
 *
 * Copyright (c) 2009, Intel Corporation
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
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#define _GNU_SOURCE
#include <getopt.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp2.h"
#include "polelt_plugin.h"
#include "lcputils2.h"

#define NULL_UUID   { 0x00000000, 0x0000, 0x0000, 0x0000, \
                      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }

static uuid_t    uuid = NULL_UUID;
static size_t    data_len;
static uint8_t  *data;

static char *skipspace(const char *s)
{
    while (*s != '\0' && isspace(*s))
        s++;
    return (char *)s;
}

static bool string_to_uuid(const char *s, uuid_t *uuid)
{
    int i;
    char *next;

    *uuid = (uuid_t){ 0x3aa86d4a, 0xa35d, 0x453d, 0x7a9a,
                      { 0x1b, 0xb4, 0xa3, 0xe3, 0xa4, 0x9f } };
    s = skipspace(s);

    /* Fetch data1 */
    if ( *s++ != '{' )
        return false;
    s = skipspace(s);
    uuid->data1 = (uint32_t)strtoul(s, &next, 16);
    if ( next == s )
        return false;
    else
        next = skipspace(next);
    s = next;

    /* Fetch data2 */
    if ( *s++ != ',' )
        return false;
    s = skipspace(s);
    uuid->data2 = (uint16_t)strtoul(s, &next, 16);
    if ( next == s )
        return false;
    else
        next = skipspace(next);
    s = next;

    /* Fetch data3 */
    if ( *s++ != ',' )
        return false;
    s = skipspace(s);
    uuid->data3 = (uint16_t)strtoul(s, &next, 16);
    if ( next == s )
        return false;
    else
        next = skipspace(next);
    s = next;

    /* Fetch data4 */
    if ( *s++ != ',' )
        return false;
    s = skipspace(s);
    uuid->data4 = (uint16_t)strtoul(s, &next, 16);
    if ( next == s )
        return false;
    else
        next = skipspace(next);
    s = next;

    /* Fetch data5 */
    if ( *s++ != ',' )
        return false;
    s = skipspace(s);
    if ( *s++ != '{' )
        return false;
    s = skipspace(s);
    for ( i = 0; i < 6; i++ ) {
        uuid->data5[i] = (uint8_t)strtoul(s, &next, 16);
        if ( next == s )
            return false;
        else
            next = skipspace(next);
        s = next;
        if ( i < 5 ) {
            /* Check "," */
            if ( *s++ != ',' )
                return false;
            s = skipspace(s);
        }
        else {
            /* Check "}}" */
            if ( *s++ != '}' )
                return false;
            s = skipspace(s);
            if ( *s++ != '}' )
                return false;
            s = skipspace(s);
        }
    }

    if ( *s != '\0' )
        return false;

    return true;
}

static bool cmdline_handler(int c, const char *opt)
{
    if ( c == 'u' ) {
        if ( !string_to_uuid(opt, &uuid) ) {
            ERROR("Error:  uuid is not well formed: %s\n", opt);
            return false;
        }
        LOG("cmdline opt: uuid:");
        if ( verbose ) {
            print_uuid(&uuid);
            LOG("\n");
        }
        return true;
    }
    else if ( c != 0 ) {
        ERROR("Error: unknown option for custom type\n");
        return false;
    }

    /* data file */
    LOG("cmdline opt: data file: %s\n", opt);
    data = read_file(opt, &data_len, false);
    if ( data == NULL )
        return false;

    return true;
}

static lcp_policy_element_t *create(void)
{
    if ( are_uuids_equal(&uuid, &((uuid_t)NULL_UUID)) ) {
        ERROR("Error:  no uuid specified\n");
        free(data);
        return NULL;
    }

    size_t data_size =  sizeof(lcp_mle_element_t) + sizeof(uuid) + data_len;

    lcp_policy_element_t *elt = malloc(sizeof(*elt) + data_size);
    if ( elt == NULL ) {
        ERROR("Error: failed to allocate element\n");
        free(data);
        return NULL;
    }

    memset(elt, 0, sizeof(*elt) + data_size);
    elt->size = sizeof(*elt) + data_size;

    lcp_custom_element_t *custom = (lcp_custom_element_t *)&elt->data;
    custom->uuid = uuid;
    memcpy(custom->data, data, data_len);

    free(data);
    data = NULL;

    return elt;
}

static void display(const char *prefix, const lcp_policy_element_t *elt)
{
    lcp_custom_element_t *custom = (lcp_custom_element_t *)elt->data;

    DISPLAY("%s uuid: ", prefix);
    print_uuid(&custom->uuid);
    DISPLAY("\n");
    DISPLAY("%s data:\n", prefix);
    print_hex(prefix, custom->data, elt->size - sizeof(*elt) -
              sizeof(custom->uuid));
}


static struct option opts[] = {
    {"uuid",         required_argument,    NULL,     'u'},
    {0, 0, 0, 0}
};

static polelt_plugin_t plugin = {
    "custom",
    opts,
    "      custom\n"
    "        --uuid <UUID>               UUID in format:\n"
    "                                    {0xaabbccdd, 0xeeff, 0xgghh, 0xiijj,\n"
    "                                    {0xkk 0xll, 0xmm, 0xnn, 0xoo, 0xpp}}\n"
    "        <FILE>                      file containing element data\n",
    LCP_POLELT_TYPE_CUSTOM,
    &cmdline_handler,
    &create,
    &display
};

REG_POLELT_PLUGIN(&plugin)


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
