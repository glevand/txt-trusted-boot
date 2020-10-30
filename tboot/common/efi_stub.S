/*
 * efi_stub.S: Stub that handles situation when binary is executed
               directly from EFI
 *
 * Copyright (c) 2020, Intel Corporation
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

        .code64
no_mb2_msg:
        .string16 "This binary can be run only with multiboot2 protocol.\r\n"
verification_fail_msg:
        .string16 "TBOOT: SecureBoot signature verification fail.\r\n"
verification_ok_msg:
        .string16 "TBOOT: SecureBoot signature verification ok.\r\n"
no_shim_msg:
        .string16 "TBOOT: SHIM not found, skipping SecureBoot verification\r\n"
no_secure_boot_msg:
        .string16 "TBOOT: SecureBoot disabled\r\n"

efivar_secure_boot:
        .string16 "SecureBoot"
efivar_setup_mode:
        .string16 "SetupMode"

        .text
        .globl efi_start
efi_start:
        // *SystemTable in RDX
        mov 0x40(%rdx), %rcx // ConOut
        lea no_mb2_msg(%rip), %rdx // string
        sub $40, %rsp
        call *0x08(%rcx)  // OutputString()
        add $40, %rsp
        mov $1, %rax
        ret

#include <multiboot.h>
#include <config.h>
#include <processor.h>
#include <msr.h>

#define cs_sel      1<<3
#define ds_sel      2<<3

#define EFI_NOT_FOUND ((1 << 63) | 14)

        .align 8
shim_lock_guid:
        .long 0x605dab50
        .short 0xe046
        .short 0x4300
        .byte 0xab
        .byte 0xb6
        .byte 0x3d
        .byte 0xd8
        .byte 0x10
        .byte 0xdd
        .byte 0x8b
        .byte 0x23

        .align 8
efi_variable_guid:
        .long 0x8be4df61
        .short 0x93ca
        .short 0x11d2
        .byte 0xaa
        .byte 0x0d
        .byte 0x00
        .byte 0xe0
        .byte 0x98
        .byte 0x03
        .byte 0x2b
        .byte 0x8c

        .globl efi_start_mb2
efi_start_mb2:
        // RAX - bootlader magic, RBX - MBI
        cmp $MB2_LOADER_MAGIC, %rax
        jnz fatal_error

        push %rbx

        // look for EFI 64-bit system table pointer and image handle
        sub $16, %rsp // make space
        xor %rdx, %rdx
        mov (%rbx), %ecx // total size in RCX
        add $8, %rbx // move to first entry
        sub $8, %rcx
l1:
        cmp $MB2_TAG_TYPE_EFI64, (%ebx) // check type
        jz found_system_table
        cmp $MB2_TAG_TYPE_EFI64_IH, (%ebx) // check type
        jz found_image_hande
1:
        cmp $3, %rdx // check if it's time to finish searching
        jz check_secure_boot_state
        mov 0x04(%rbx), %eax // entry size
        add $7, %rax
        and $0xFFFFFFFFFFFFFFF8, %rax // align to 8
        sub %rax, %rcx
        jz fatal_error
        add %rax, %rbx // next entry
        jmp l1

found_system_table:
        or $1, %rdx
        mov 0x08(%rbx), %rax
        mov %rax, (%rsp)
        jmp 1b
found_image_hande:
        or $2, %rdx
        mov 0x08(%rbx), %rax
        mov %rax, 0x08(%rsp)
        jmp 1b

check_secure_boot_state:
        mov (%rsp), %rbx // *SystemTable in rbx
        mov 0x58(%rbx), %rbx // *RuntimeServices in rbx

        /* Check SecureBoot variable */
        lea efivar_secure_boot(%rip), %rcx
        call get_variable
        mov $EFI_NOT_FOUND, %rdx
        cmp %rdx, %rax
        jz no_secureboot // SecureBoot variable not found
        test %rax, %rax
        jnz fatal_error // other error
        test %rcx, %rcx
        jz no_secureboot // SecureBoot disabled

        /* Check SetupMode variable */
        lea efivar_setup_mode(%rip), %rcx
        call get_variable
        test %rax, %rax // error
        jnz fatal_error
        test %rcx, %rcx // setup mode enabled
        jnz no_secureboot

        jmp verify_signature

get_variable: // rbx - RuntimeServices, rcx - [in] VariableName, [out] Data
        lea efi_variable_guid(%rip), %rdx // guid
        mov $0, %r8 // Attributes
        push $1
        mov %rsp, %r9 // DataSize
        sub $8, %rsp
        push %rsp // Data
        sub $32, %rsp // reserve space in stack
        call *0x48(%rbx) // GetVariable()
        add $40, %rsp
        pop %rcx // Data
        add $8, %rsp
        and $0xFF, %rcx
        ret

no_secureboot:
        mov (%rsp), %rbx // *SystemTable in rbx
        mov 0x40(%rbx), %rcx // ConOut
        lea no_secure_boot_msg(%rip), %rdx // string
        sub $40, %rsp
        call *0x08(%rcx)  // OutputString()
        add $40, %rsp
        jmp get_mmap

verify_signature:
        mov (%rsp), %rbx // *SystemTable in rbx
        mov 0x60(%rbx), %rbx // *BootServices in rbx

        /* Get shim_verify() pointer */
        lea shim_lock_guid(%rip), %rcx // Protocol
        xor %rdx, %rdx // Registration
        sub $8, %rsp
        mov %rsp, %r8 // Interface
        sub $40, %rsp
        call *0x140(%rbx) // LocateProtocol()
        add $40, %rsp
        test %rax, %rax
        jnz no_shim
        pop %rdx // shim_verify() in rdx

        /* Iterate over modules in mbi */
        mov 0x10(%rsp), %rbx // *mbi in rbx
        mov (%rbx), %ecx // total size in rcx
        add $8, %rbx // move to first entry
        sub $8, %rcx
l2:
        cmp $MB2_TAG_TYPE_MODULE, (%ebx) // check type
        jz call_shim
1:
        mov 0x04(%rbx), %eax // entry size
        add $7, %rax
        and $0xFFFFFFFFFFFFFFF8, %rax // align to 8
        sub %rax, %rcx
        jz verification_fail
        add %rax, %rbx // next entry
        jmp l2
call_shim:
        mov 0x08(%rbx), %edi // mod_start
        mov 0x0c(%rbx), %esi // mod_end
        sub %rdi, %rsi // calculate size
        push %rcx
        push %rdx
        call *(%rdx) // shim_verify()
        pop %rdx
        pop %rcx
        test %rax, %rax
        jnz verification_fail
        jz verification_ok
no_shim:
        mov 0x40(%rbx), %rcx // ConOut
        lea no_shim_msg(%rip), %rdx // string
        sub $40, %rsp
        call *0x08(%rcx)  // OutputString()
        add $40, %rsp
        jmp get_mmap
verification_fail:
        pop %rbx // *SystemTable in rbx
        mov 0x40(%rbx), %rcx // ConOut
        lea verification_fail_msg(%rip), %rdx // string
        sub $40, %rsp
        call *0x08(%rcx)  // OutputString()
        add $40, %rsp
        1: jmp 1b
verification_ok:
        mov (%rsp), %rbx // *SystemTable in rbx
        mov 0x40(%rbx), %rcx // ConOut
        lea verification_ok_msg(%rip), %rdx // string
        sub $40, %rsp
        call *0x08(%rcx)  // OutputString()
        add $40, %rsp
        jmp get_mmap

get_mmap:
        pop %rbx // *SystemTable in rbx
        mov 0x60(%rbx), %rbx // *BootServices in rbx
        sub $8, %rsp
        mov %rsp, %rcx // MemoryMapSize
        movq $TBOOT_EFI_MEMMAP_COPY_SIZE, (%rcx)
        mov $(TBOOT_EFI_MEMMAP_COPY_ADDR + 8), %rdx // MemoryMap
        sub $8, %rsp
        mov %rsp, %r8 // MapKey
        sub $8, %rsp
        mov %rsp, %r9 // DescriptorSize
        sub $8, %rsp
        push %rsp // DescriptorVersion
        sub $32, %rsp // reserve space in stack
        call *0x38(%rbx) // GetMemoryMap()
        add $40, %rsp
        test %rax, %rax
        jnz fatal_error
        pop %rax // DescriptorVersion
        cmp $1, %rax // only version 1 supported
        jnz fatal_error

        // get DescriptorSize, MemoryMapSize and MapKey
        pop %rax // DescriptorSize
        mov %eax, (TBOOT_EFI_MEMMAP_COPY_ADDR + 4)
        pop %rdx // MapKey
        pop %rax // MemoryMapSize
        mov %eax, (TBOOT_EFI_MEMMAP_COPY_ADDR)

exit_bs:
        pop %rcx // ImageHandle
        sub $40, %rsp
        call *0xe8(%rbx) // ExitBootServices()
        add $40, %rsp
        test %rax, %rax
        jz switch_to_32bit

fatal_error:
        1: jmp 1b

switch_to_32bit:
        cli
        wbinvd
        lgdt    gdt_descr(%rip)
        mov     $(ds_sel),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%fs
        mov     %ecx,%gs
        mov     %ecx,%ss
        /* Jump to low identity mapping in compatibility mode. */
        ljmp *compatibility_mode_far(%rip)
        ud2

compatibility_mode_far:
        .long     compat_mode_entry
        .word     cs_sel

        .code32

compat_mode_entry:
        /* Disable PCID */
        movl %cr4, %eax
        andl $~CR4_PCIDE, %eax
        movl %eax, %cr4

        /* Disable paging and therefore leave 64 bit mode. */
        movl %cr0, %eax
        andl $~CR0_PG, %eax
        movl %eax, %cr0

        /* Clear MSR_EFER[LME], disabling long mode */
        movl    $MSR_EFER,%ecx
        rdmsr
        btcl    $_EFER_LME,%eax
        wrmsr

jump_to_ep:
        pop %ebx // mbi pointer
        add $4, %esp
        mov $MB2_EFI_LOADER_MAGIC, %eax // mb2 magic
        jmp start
        ud2