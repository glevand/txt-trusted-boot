/*
 * efi_memmap.c: EFI memory map parsing functions
 *
 * Copyright (c) 2006-2020, Intel Corporation
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

#include <string.h>
#include <stdbool.h>
#include <printk.h>
#include <uuid.h>
#include <loader.h>
#include <misc.h>
#include <efi_memmap.h>

static bool efi_mmap_available = false;
static efi_memmap_t* efi_mmap = (efi_memmap_t*)TBOOT_EFI_MEMMAP_COPY_ADDR;

static bool insert_after_region(uint32_t pos, uint64_t addr, uint64_t size,
                                uint32_t type, uint64_t attr);
static bool region_is_free(uint32_t region_type);

/**
 * @brief Copy memory map from mbi to defined memory space to allow insertion
 *        of new entries
 * 
 * @param lctx loader context with mbi
 */
bool efi_memmap_copy(loader_ctx *lctx)
{
    uint32_t descr_addr, descr_ver, descr_size, mmap_size;
    descr_addr = find_efi_memmap(lctx, &descr_size,
                                 &descr_ver, &mmap_size);

    if (descr_addr == 0 || descr_ver != EFI_MEMORY_DESCRIPTOR_VERSION) {
        printk(TBOOT_WARN"Failed to get EFI memory map\n");
        return false;
    }

    efi_mmap->size = mmap_size;
    efi_mmap->descr_size = descr_size;
    tb_memcpy(efi_mmap->descr, (void*)descr_addr, mmap_size);
    efi_mmap_available = true;

    return true;
}

/**
 * @brief Get address of memory map descriptors
 * 
 * @param descr_size return size of each descriptor
 * @param descr_vers return descriptor version
 * @param mmap_size  return sum of all descriptors size
 */
uint32_t efi_memmap_get_addr(uint32_t *descr_size, uint32_t *descr_vers,
                             uint32_t *mmap_size)
{
    if (!efi_mmap_available) {
        return 0;
    }
    if (descr_size != NULL) {
        *descr_size = efi_mmap->descr_size;
    }
    if (descr_vers != NULL) {
        *descr_vers = EFI_MEMORY_DESCRIPTOR_VERSION;
    }
    if (mmap_size != NULL) {
        *mmap_size = efi_mmap->size;
    }
    return (uint32_t)efi_mmap->descr;
}

/**
 * @brief Walk through memory map descriptors
 * 
 * @param prev pointer to previous descriptor, when NULL start interating from 
 *             first one
 */
efi_mem_descr_t* efi_memmap_walk(efi_mem_descr_t* prev)
{
    if (!efi_mmap_available) {
        printk(TBOOT_WARN"EFI memory map not available\n");
        return NULL;
    }

    if (prev == NULL) {
        return (efi_mem_descr_t*)efi_mmap->descr;
    } else if ((uint32_t)prev < (uint32_t)efi_mmap->descr) {
        /* 
         * Should never happens, just to prevent overflow in below
         * substraction
          */
        return NULL;
    } else {
        uint32_t next = (uint32_t)prev + efi_mmap->descr_size;
        if (next - (uint32_t)efi_mmap->descr < efi_mmap->size) {
            return (efi_mem_descr_t*)next;
        } else {
            return NULL;
        }
    }
}

/**
 * @brief Mark given memory region as reserved
 * 
 * Region will be changed to EFI_RESERVED_TYPE, if given region already has type
 * that indicates that it is not free, type will not be changed. Non-free means
 * other than loader, boot, runtime and conventional memory types.
 * 
 * Region has to be aligned to page size, function will round non-aligned
 * values. Base address is rounded down, length - up.
 * 
 * @param base   starting address
 * @param length length of region to reserve
 */
bool efi_memmap_reserve(uint64_t base, uint64_t length)
{
    if (length == 0 || !efi_mmap_available) {
        return true;
    }

    /* Round to page size */
    uint64_t mask = ~((1ULL << EFI_PAGE_SHIFT) - 1ULL);
    base &= mask;
    if (length & ~mask) {
        length &= mask;
        length += (1ULL << EFI_PAGE_SHIFT);
    }

    uint64_t end = base + length;
    efi_mem_descr_t* desc = NULL;
    uint32_t i = 0;

    while ((desc = efi_memmap_walk(desc)) != NULL) {
        uint64_t desc_base = desc->physical_start;
        uint64_t desc_length = desc->num_pages << EFI_PAGE_SHIFT;
        uint64_t desc_end = desc_base + desc_length;

        /* if already unusable, no need to deal with */
        if (desc->type < EFI_LOADER_CODE ||
                desc->type > EFI_CONVENTIONAL_MEMORY) {
            goto cont;
        }

        /* if the range is before the current ram range, skip the ram range */
        if (end <= desc_base) {
            goto cont;
        }
        /* if the range is after the current ram range, skip the ram range */
        if (base >= desc_end) {
            goto cont;
        }

        /* case 1: the current ram range is within the range:
           base, desc_base, desc_end, end */
        if ((base <= desc_base) && (desc_end <= end)) {
            desc->type = EFI_RESERVED_TYPE;
        }
        /* case 2: overlapping:
           base, e820_base, end, e820_end */
        else if ((desc_base >= base) && (end > desc_base) && (desc_end > end)) {
            /* split the current ram map */
            if (!insert_after_region(i-1, desc_base, (end - desc_base),
                                     EFI_RESERVED_TYPE, desc->attribute)) {
                return false;
            }
            /* fixup the current ram map */
            desc = efi_memmap_walk(desc); 
            ++i;
            desc->physical_start = end;
            desc->num_pages = (desc_end - end) >> EFI_PAGE_SHIFT;
            /* no need to check more */
            break;
        }
        /* case 3: overlapping:
           desc_base, base, desc_end, end */
        else if ((base > desc_base) && (desc_end > base) && (end >= desc_end)) {
            /* fixup the current ram map */
            desc->num_pages = (base - desc_base) >> EFI_PAGE_SHIFT;
            /* split the current ram map */
            if (!insert_after_region(i, base, (desc_end - base),
                                     EFI_RESERVED_TYPE, desc->attribute)) {
                return false;
            }
            desc = efi_memmap_walk(desc); 
            ++i;
        }
        /* case 4: the range is within the current ram range:
           desc_base, base, end, desc_end */
        else if ((base > desc_base) && (desc_end > end)) {
            /* fixup the current ram map */
            desc->num_pages = (base - desc_base) >> EFI_PAGE_SHIFT;
            /* split the current ram map */
            if (!insert_after_region(i, base, length, EFI_RESERVED_TYPE,
                                     desc->attribute)) {
                return false;
            }
            ++i;
            /* fixup the rest of the current ram map */
            if (!insert_after_region(i, end, (desc_end - end), desc->type,
                                     desc->attribute)) {
                return false;
            }
            desc = efi_memmap_walk(desc);
            desc = efi_memmap_walk(desc); 
            ++i;
            /* no need to check more */
            break;
        }
        else {
            printk(TBOOT_ERR"we should never get here\n");
            return false;
        }

        cont:
        ++i;
    }

    return true;
}

/**
 * @brief Print whole memory map
 */
void efi_memmap_dump(void)
{
    efi_mem_descr_t* desc = NULL;
    while ((desc = efi_memmap_walk(desc)) != NULL) {
        printk(TBOOT_INFO" %016llx - %016llx (%-2d | 0x%llx)\n",
               desc->physical_start,
               desc->physical_start + (desc->num_pages << EFI_PAGE_SHIFT),
               desc->type, desc->attribute);
    }
}

/**
 * @brief Find in memory map highest avaliable free space that meets given
 *        requirements
 * 
 * Free space is a region in memory map of following types:
 *   - EFI_LOADER_CODE
 *   - EFI_LOADER_DATA
 *   - EFI_CONVENTIONAL_MEMORY
 * Boot services memory is excluded because it can be occupied by tables
 * that Linux may want to access later, ex. EFI_MEMORY_ATTRIBUTES_TABLE
 * 
 * @param size     minimal size
 * @param limit    highest possible address
 * @param ram_base return address of found region
 * @param ram_size return size of found region, bigger or equal @p size
 */
bool efi_memmap_get_highest_sized_ram(uint64_t size, uint64_t limit,
                                      uint64_t *ram_base, uint64_t *ram_size)
{
    uint64_t last_fit_base = 0, last_fit_size = 0;

    if (ram_base == NULL || ram_size == NULL || !efi_mmap_available) {
        return false;
    }

    efi_mem_descr_t* desc = NULL;
    while ((desc = efi_memmap_walk(desc)) != NULL) {
        if (region_is_free(desc->type)) {
            uint64_t base = desc->physical_start;
            uint64_t length = desc->num_pages * (1 << EFI_PAGE_SHIFT);

            /* over 4GB so use the last region that fit */
            if ( base + length > limit )
                break;
            if ( size <= length ) {
                last_fit_base = base;
                last_fit_size = length;
            }
        }
    }

    printk("get_highest_sized_ram: size %llx -> base %llx, size %llx\n",
           size, *ram_base, *ram_size);

    if (last_fit_size == 0) {
        return false;
    } else {
        *ram_base = last_fit_base;
        *ram_size = last_fit_size;
        return true;
    }
}

static bool insert_after_region(uint32_t pos, uint64_t addr, uint64_t size,
                                uint32_t type, uint64_t attr)
{
    /* no more room */
    if (efi_mmap->size / efi_mmap->descr_size + 1 > EFI_MEMMAP_MAX_ENTRIES)
        return false;

    pos *= efi_mmap->descr_size;

    /* shift (copy) everything up one entry */
    for (uint32_t i = efi_mmap->size; i > pos; i -= efi_mmap->descr_size) {
        uint32_t bytes = efi_mmap->descr_size;
        void* to = efi_mmap->descr + i;
        void* from = efi_mmap->descr + i - bytes;
        tb_memcpy(to, from, bytes);
    }

    efi_mem_descr_t* desc = (efi_mem_descr_t*)(efi_mmap->descr + pos +
                            efi_mmap->descr_size);
    tb_memset(desc, 0, efi_mmap->descr_size);
    desc->type = type;
    desc->physical_start = addr;
    desc->num_pages = size >> EFI_PAGE_SHIFT;
    desc->attribute = attr;
    efi_mmap->size += efi_mmap->descr_size;

    return true;
}

static bool region_is_free(uint32_t region_type)
{
    if (region_type == EFI_LOADER_CODE || region_type == EFI_LOADER_DATA ||
            region_type == EFI_CONVENTIONAL_MEMORY) {
        return true;
    } else {
        return false;
    }
}