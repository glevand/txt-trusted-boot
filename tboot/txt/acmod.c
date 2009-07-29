/*
 * acmod.c: support functions for use of Intel(r) TXT Authenticated
 *          Code (AC) Modules
 *
 * Copyright (c) 2003-2008, Intel Corporation
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

#ifndef IS_INCLUDED     /* defined in txt-test/dump-acm.c */
#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <printk.h>
#include <compiler.h>
#include <string.h>
#include <processor.h>
#include <misc.h>
#include <uuid.h>
#include <multiboot.h>
#include <mle.h>
#include <txt/acmod.h>
#include <txt/config_regs.h>
#include <txt/mtrrs.h>
#include <txt/heap.h>
#include <txt/smx.h>
#endif    /* IS_INCLUDED */


static acm_info_table_t *get_acmod_info_table(acm_hdr_t* hdr)
{
    uint32_t user_area_off;

    /* overflow? */
    if ( plus_overflow_u32(hdr->header_len, hdr->scratch_size) ) {
        printk("ACM header length plus scratch size overflows\n");
        return NULL;
    }

    if ( multiply_overflow_u32((hdr->header_len + hdr->scratch_size), 4) ) {
        printk("ACM header length and scratch size in bytes overflows\n");
        return NULL;
    }

    /* this fn assumes that the ACM has already passed at least the initial */
    /* is_acmod() checks */

    user_area_off = (hdr->header_len + hdr->scratch_size) * 4;

    /* overflow? */
    if ( plus_overflow_u32(user_area_off, sizeof(acm_info_table_t)) ) {
        printk("user_area_off plus acm_info_table_t size overflows\n");
        return NULL;
    }

    /* check that table is within module */
    if ( user_area_off + sizeof(acm_info_table_t) > hdr->size*4 ) {
        printk("ACM info table size too large: %x\n",
               user_area_off + (uint32_t)sizeof(acm_info_table_t));
        return NULL;
    }

    /* overflow? */
    if ( plus_overflow_ul((unsigned long)hdr, user_area_off) ) {
        printk("hdr plus user_area_off overflows\n");
        return NULL;
    }

    return (acm_info_table_t *)((unsigned long)hdr + user_area_off);
}

static acm_chipset_id_list_t *get_acmod_chipset_list(acm_hdr_t* hdr)
{
    acm_info_table_t* info_table;
    uint32_t size, id_list_off;
    acm_chipset_id_list_t *chipset_id_list;

    /* this fn assumes that the ACM has already passed the is_acmod() checks */

    info_table = get_acmod_info_table(hdr);
    if ( info_table == NULL )
        return NULL;
    id_list_off = info_table->chipset_id_list;

    size = hdr->size * 4;

    /* overflow? */
    if ( plus_overflow_u32(id_list_off, sizeof(acm_chipset_id_t)) ) {
        printk("id_list_off plus acm_chipset_id_t size overflows\n");
        return NULL;
    }

    /* check that chipset id table is w/in ACM */
    if ( id_list_off + sizeof(acm_chipset_id_t) > size ) {
        printk("ACM chipset id list is too big: chipset_id_list=%x\n",
               id_list_off);
        return NULL;
    }

    /* overflow? */
    if ( plus_overflow_ul((unsigned long)hdr, id_list_off) ) {
        printk("hdr plus id_list_off overflows\n");
        return NULL;
    }

    chipset_id_list = (acm_chipset_id_list_t *)
                             ((unsigned long)hdr + id_list_off);

    /* overflow? */
    if ( multiply_overflow_u32(chipset_id_list->count,
             sizeof(acm_chipset_id_t)) ) {
        printk("size of acm_chipset_id_list overflows\n");
        return NULL;
    }
    if ( plus_overflow_u32(id_list_off + sizeof(acm_chipset_id_t),
        chipset_id_list->count * sizeof(acm_chipset_id_t)) ) {
        printk("size of all entries overflows\n");
        return NULL;
    }

    /* check that all entries are w/in ACM */
    if ( id_list_off + sizeof(acm_chipset_id_t) + 
         chipset_id_list->count * sizeof(acm_chipset_id_t) > size ) {
        printk("ACM chipset id entries are too big:"
               " chipset_id_list->count=%x\n", chipset_id_list->count);
        return NULL;
    }

    return chipset_id_list;
}

void print_txt_caps(const char *prefix, txt_caps_t caps)
{
    printk("%scapabilities: 0x%08x\n", prefix, caps._raw);
    printk("%s    rlp_wake_getsec: %d\n", prefix, caps.rlp_wake_getsec);
    printk("%s    rlp_wake_monitor: %d\n", prefix, caps.rlp_wake_monitor);
    printk("%s    ecx_pgtbl: %d\n", prefix, caps.ecx_pgtbl);
}

static void print_acm_hdr(acm_hdr_t *hdr, const char *mod_name)
{
    acm_info_table_t *info_table;
    acm_chipset_id_list_t *chipset_id_list;

    printk("AC module header dump for %s:\n",
           (mod_name == NULL) ? "?" : mod_name);

    /* header */
    printk("\t type: 0x%x ", hdr->module_type);
    if ( hdr->module_type == ACM_TYPE_CHIPSET )
        printk("(ACM_TYPE_CHIPSET)\n");
    else
        printk("(unknown)\n");
    printk("\t length: 0x%x (%u)\n", hdr->header_len, hdr->header_len);
    printk("\t version: %u\n", hdr->header_ver);
    printk("\t chipset_id: 0x%x\n", (uint32_t)hdr->chipset_id);
    printk("\t flags: 0x%x\n", (uint32_t)hdr->flags._raw);
    printk("\t\t pre_production: %d\n", (int)hdr->flags.pre_production);
    printk("\t\t debug_signed: %d\n", (int)hdr->flags.debug_signed);
    printk("\t vendor: 0x%x\n", hdr->module_vendor);
    printk("\t date: 0x%08x\n", hdr->date);
    printk("\t size*4: 0x%x (%u)\n", hdr->size*4, hdr->size*4);
    printk("\t code_control: 0x%x\n", hdr->code_control);
    printk("\t entry point: 0x%08x:%08x\n", hdr->seg_sel,
           hdr->entry_point);
    printk("\t scratch_size: 0x%x (%u)\n", hdr->scratch_size,
           hdr->scratch_size);

    /* info table */
    printk("\t info_table:\n");
    info_table = get_acmod_info_table(hdr);
    if ( info_table == NULL ) {
        printk("\t\t <invalid>\n");
        return;
    }
    printk("\t\t uuid: "); print_uuid(&info_table->uuid); printk("\n");
    if ( are_uuids_equal(&(info_table->uuid), &((uuid_t)ACM_UUID_V3)) )
        printk("\t\t     ACM_UUID_V3\n");
    else
        printk("\t\t     unknown\n");
    printk("\t\t chipset_acm_type: 0x%x ",
           (uint32_t)info_table->chipset_acm_type);
    if ( info_table->chipset_acm_type == ACM_CHIPSET_TYPE_SINIT )
        printk("(SINIT)\n");
    else if ( info_table->chipset_acm_type == ACM_CHIPSET_TYPE_BIOS )
        printk("(BIOS)\n");
    else
        printk("(unknown)\n");
    printk("\t\t version: %u\n", (uint32_t)info_table->version);
    printk("\t\t length: 0x%x (%u)\n", (uint32_t)info_table->length,
           (uint32_t)info_table->length);
    printk("\t\t chipset_id_list: 0x%x\n", info_table->chipset_id_list);
    printk("\t\t os_sinit_data_ver: 0x%x\n", info_table->os_sinit_data_ver);
    printk("\t\t min_mle_hdr_ver: 0x%08x\n", info_table->min_mle_hdr_ver);
    print_txt_caps("\t\t ", info_table->capabilities);
    printk("\t\t acm_ver: %u\n", (uint32_t)info_table->acm_ver);

    /* chipset list */
    printk("\t chipset list:\n");
    chipset_id_list = get_acmod_chipset_list(hdr);
    if ( chipset_id_list == NULL ) {
        printk("\t\t <invalid>\n");
        return;
    }
    printk("\t\t count: %u\n", chipset_id_list->count);
    for ( unsigned int i = 0; i < chipset_id_list->count; i++ ) {
        printk("\t\t entry %u:\n", i);
        acm_chipset_id_t *chipset_id = &(chipset_id_list->chipset_ids[i]);
        printk("\t\t     flags: 0x%x\n", chipset_id->flags);
        printk("\t\t     vendor_id: 0x%x\n", (uint32_t)chipset_id->vendor_id);
        printk("\t\t     device_id: 0x%x\n", (uint32_t)chipset_id->device_id);
        printk("\t\t     revision_id: 0x%x\n",
               (uint32_t)chipset_id->revision_id);
        printk("\t\t     extended_id: 0x%x\n", chipset_id->extended_id);
    }
}

uint32_t get_supported_os_sinit_data_ver(acm_hdr_t* hdr)
{
    /* assumes that it passed is_sinit_acmod() */

    acm_info_table_t *info_table = get_acmod_info_table(hdr);
    if ( info_table == NULL )
        return 0;

    return info_table->os_sinit_data_ver;
}

txt_caps_t get_sinit_capabilities(acm_hdr_t* hdr)
{
    /* assumes that it passed is_sinit_acmod() */

    acm_info_table_t *info_table = get_acmod_info_table(hdr);
    if ( info_table == NULL || info_table->version < 3 )
        return (txt_caps_t){ 0 };

    return info_table->capabilities;
}

static bool is_acmod(void *acmod_base, uint32_t acmod_size, uint8_t *type)
{
    acm_hdr_t *acm_hdr;
    acm_info_table_t *info_table;

    acm_hdr = (acm_hdr_t *)acmod_base;

    /* first check size */
    if ( acmod_size < sizeof(acm_hdr_t) ) {
        printk("ACM size is too small: acmod_size=%x,"
               " sizeof(acm_hdr)=%x\n", acmod_size,
               (uint32_t)sizeof(acm_hdr) );
        return false;
    }

    /* then check overflow */
    if ( multiply_overflow_u32(acm_hdr->size, 4) ) {
        printk("ACM header size in bytes overflows\n");
        return false;
    }

    /* then check size equivalency */
    if ( acmod_size != acm_hdr->size * 4 ) {
        printk("ACM size is too small: acmod_size=%x,"
               " acm_hdr->size*4=%x\n", acmod_size, acm_hdr->size*4);
        return false;
    }

    /* then check type and vendor */
    if ( (acm_hdr->module_type != ACM_TYPE_CHIPSET) ||
         (acm_hdr->module_vendor != ACM_VENDOR_INTEL) ) {
        printk("ACM type/vendor mismatch: module_type=%x,"
               " module_vendor=%x\n", acm_hdr->module_type,
               acm_hdr->module_vendor);
        return false;
    }

    info_table = get_acmod_info_table(acm_hdr);
    if ( info_table == NULL )
        return false;

    /* check if ACM UUID is present */
    if ( !are_uuids_equal(&(info_table->uuid), &((uuid_t)ACM_UUID_V3)) ) {
        printk("unknown UUID: "); print_uuid(&info_table->uuid); printk("\n");
        return false;
    }

    if ( type != NULL )
        *type = info_table->chipset_acm_type;

    if ( info_table->version < 3 ) {
        printk("ACM info_table version unsupported (%u)\n",
               (uint32_t)info_table->version);
        return false;
    }
    /* there is forward compatibility, so this is just a warning */
    else if ( info_table->version > 3 )
        printk("ACM info_table version mismatch (%u)\n",
               (uint32_t)info_table->version);

    return true;
}

bool is_sinit_acmod(void *acmod_base, uint32_t acmod_size)
{
    uint8_t type;

    if ( !is_acmod(acmod_base, acmod_size, &type) )
        return false;

    if ( type != ACM_CHIPSET_TYPE_SINIT ) {
        printk("ACM is not an SINIT ACM (%x)\n", type);
        return false;
    }

    return true;
}

bool does_acmod_match_chipset(acm_hdr_t* hdr)
{
    acm_chipset_id_list_t *chipset_id_list;
    acm_chipset_id_t *chipset_id;
    txt_didvid_t didvid;

    /* this fn assumes that the ACM has already passed the is_acmod() checks */

    chipset_id_list = get_acmod_chipset_list(hdr);
    if ( chipset_id_list == NULL )
        return false;

    /* get chipset device and vendor id info */
    didvid._raw = read_pub_config_reg(TXTCR_DIDVID);
    printk("chipset ids: vendor=%x, device=%x, revision=%x\n",
           didvid.vendor_id, didvid.device_id, didvid.revision_id);

    printk("%x ACM chipset id entries:\n", chipset_id_list->count);
    for ( int i = 0; i < chipset_id_list->count; i++ ) {
        chipset_id = &(chipset_id_list->chipset_ids[i]);
        printk("\tvendor=%x, device=%x, flags=%x, revision=%x, "
               "extended=%x\n", (uint32_t)chipset_id->vendor_id,
               (uint32_t)chipset_id->device_id, chipset_id->flags,
               (uint32_t)chipset_id->revision_id, chipset_id->extended_id);

        if ( (didvid.vendor_id == chipset_id->vendor_id ) &&
             (didvid.device_id == chipset_id->device_id ) &&
             ( ( ( (chipset_id->flags & 0x1) == 0) && 
                 (didvid.revision_id == chipset_id->revision_id) ) ||
               ( ( (chipset_id->flags & 0x1) == 1) &&
                 ((didvid.revision_id & chipset_id->revision_id) != 0 ) ) ) )
            return true;
    }

    printk("ACM does not match chipset\n");

    return false;
}

#ifndef IS_INCLUDED
acm_hdr_t *copy_sinit(acm_hdr_t *sinit)
{
    void *sinit_region_base;
    uint32_t sinit_region_size;
    txt_heap_t *txt_heap;
    bios_data_t *bios_data;

    /* get BIOS-reserved region from LT.SINIT.BASE config reg */
    sinit_region_base =
        (void*)(unsigned long)read_pub_config_reg(TXTCR_SINIT_BASE);
    sinit_region_size = (uint32_t)read_pub_config_reg(TXTCR_SINIT_SIZE);

    /*
     * check if BIOS already loaded an SINIT module there
     */
    txt_heap = get_txt_heap();
    bios_data = get_bios_data_start(txt_heap);
    /* BIOS has loaded an SINIT module, so verify that it is valid */
    if ( bios_data->bios_sinit_size != 0 ) {
        printk("BIOS has already loaded an SINIT module\n");
        /* is it a valid SINIT module? */
        if ( is_sinit_acmod(sinit_region_base,
                            bios_data->bios_sinit_size) ) {
            /* no other SINIT was provided so must use one BIOS provided */
            if ( sinit == NULL )
                return (acm_hdr_t *)sinit_region_base;

            /* is it newer than the one we've been provided? */
            if ( ((acm_hdr_t *)sinit_region_base)->date >= sinit->date ) {
                printk("BIOS-provided SINIT is newer, so using it\n");
                return (acm_hdr_t *)sinit_region_base;    /* yes */
            }
            else
                printk("BIOS-provided SINIT is older: date=%x\n",
                       ((acm_hdr_t *)sinit_region_base)->date);
        }
    }
    /* our SINIT is newer than BIOS's (or BIOS did not have one) */

    /* BIOS SINIT not present or not valid and none provided */
    if ( sinit == NULL )
        return NULL;

    /* overflow? */
    if ( multiply_overflow_u32(sinit->size, 4) ) {
        printk("sinit size in bytes overflows\n");
        return NULL;
    }

    /* make sure our SINIT fits in the reserved region */
    if ( (sinit->size * 4) > sinit_region_size ) {
        printk("BIOS-reserved SINIT size (%x) is too small for loaded "
               "SINIT (%x)\n", sinit_region_size, sinit->size*4);
        return NULL;
    }

    /* copy it there */
    memcpy(sinit_region_base, sinit, sinit->size*4);

    printk("copied SINIT (size=%x) to %p\n", sinit->size*4,
           sinit_region_base);

    return (acm_hdr_t *)sinit_region_base;
}
#endif    /* IS_INCLUDED */


/*
 * Do some AC module sanity checks because any violations will cause
 * an TXT.RESET.  Instead detect these, print a desriptive message,
 * and skip SENTER/ENTERACCS
 */
bool verify_acmod(acm_hdr_t *acm_hdr)
{
    getsec_parameters_t params;
    uint32_t size;

    /* assumes this already passed is_acmod() test */

    size = acm_hdr->size * 4;        /* hdr size is in dwords, we want bytes */

    /*
     * AC mod must start on 4k page boundary
     */

    if ( (unsigned long)acm_hdr & 0xfff ) {
        printk("AC mod base not 4K aligned (%p)\n", acm_hdr);
        return false;
    }
    printk("AC mod base alignment OK\n");

    /* AC mod size must:
     * - be multiple of 64
     * - greater than ???
     * - less than max supported size for this processor
     */

    if ( (size == 0) || ((size % 64) != 0) ) { 
        printk("AC mod size %x bogus\n", size);
        return false;
    }

    if ( get_parameters(&params) == -1 ) {
        printk("get_parameters() failed\n");
        return false;
    }

    if ( size > params.acm_max_size ) {
        printk("AC mod size too large: %x (max=%x)\n", size,
               params.acm_max_size);
        return false;
    }

    printk("AC mod size OK\n");

    /*
     * perform checks on AC mod structure
     */

    /* print it for debugging */
    print_acm_hdr(acm_hdr, "SINIT");

    /* entry point is offset from base addr so make sure it is within module */
    if ( acm_hdr->entry_point >= size ) {
        printk("AC mod entry (%08x) >= AC mod size (%08x)\n",
               acm_hdr->entry_point, size);
        return false;
    }

    /* overflow? */
    if ( plus_overflow_u32(acm_hdr->seg_sel, 8) ) {
        printk("seg_sel plus 8 overflows\n");
        return false;
    }

    if ( !acm_hdr->seg_sel           ||       /* invalid selector */
         (acm_hdr->seg_sel & 0x07)   ||       /* LDT, PL!=0 */
         (acm_hdr->seg_sel + 8 > acm_hdr->gdt_limit) ) {
        printk("AC mod selector [%04x] bogus\n", acm_hdr->seg_sel);
        return false;
    }

    /*
     * check for compatibility with this MLE
     */

    acm_info_table_t *info_table = get_acmod_info_table(acm_hdr);
    if ( info_table == NULL )
        return false;

    /* check MLE header versions */
    if ( info_table->min_mle_hdr_ver > MLE_HDR_VER ) {
        printk("AC mod requires a newer MLE (0x%08x)\n",
               info_table->min_mle_hdr_ver);
        return false;
    }

    /* check capabilities */
    /* we need to match one of rlp_wake_{getsec, monitor} */
    txt_caps_t caps_mask = { 0 };
    caps_mask.rlp_wake_getsec = caps_mask.rlp_wake_monitor = 1;

    if ( ( ( MLE_HDR_CAPS & caps_mask._raw ) &
           ( info_table->capabilities._raw & caps_mask._raw) ) == 0 ) {
        printk("SINIT and MLE not support compatible RLP wake mechanisms\n");
        return false;
    }
    /* we also expect ecx_pgtbl to be set */
    if ( !info_table->capabilities.ecx_pgtbl ) {
        printk("SINIT does not support launch with MLE pagetable in ECX\n");
        /* TODO when SINIT ready
         * return false;
         */
    }

    /* check for version of OS to SINIT data */
    /* we don't support old versions */
    if ( info_table->os_sinit_data_ver < 4 ) {
        printk("SINIT's os_sinit_data version unsupported (%u)\n",
               info_table->os_sinit_data_ver);
        return false;
    }
    /* only warn if SINIT supports more recent version than us */
    else if ( info_table->os_sinit_data_ver > 4 ) {
        printk("SINIT's os_sinit_data version unsupported (%u)\n",
               info_table->os_sinit_data_ver);
    }

	return true;
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
