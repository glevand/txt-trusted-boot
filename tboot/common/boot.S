/*
 * boot.S: assembly bootstrapping code for tboot module
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

#include <multiboot.h>
#include <config.h>
#include <msr.h>
#include <page.h>
#include <processor.h>

#define BSP_STACK_SIZE		0x2000
#define AP_STACK_SIZE		0x0800

#define cs_sel      1<<3
#define ds_sel      2<<3
#define cs16_sel    4<<3
#define ds16_sel    5<<3

/* opcode prefixes for 16bit data and addressing */
#define DATA16      .byte 0x66
#define ADDR16      .byte 0x67

/* TXT config regs addrs/offsets */
#define TXT_PRIV_CONFIG_REGS_BASE      0xfed20000
#define TXTCR_STS                      0x0000
#define TXTCR_ERRORCODE                0x0030
#define TXTCR_CMD_RESET                0x0038
#define TXTCR_CMD_UNLOCK_MEM_CONFIG    0x0218
#define TXTCR_HEAP_BASE                0x0300

/* OsSinitData field offsets */
#define MLE_PGTBL_OFF          8

/* errorcode for post-launch memory layout verfication failure */
#define LAYOUT_ERR             0xc0008001

#define sym_offs(sym)     ((sym) - TBOOT_BASE_ADDR)

        .macro mb2ht_args arg:req, args:vararg
        .long \arg
        .ifnb \args
        mb2ht_args \args
        .endif
        .endm

        .macro mb2ht_init type:req, req:req, args:vararg
        .balign MULTIBOOT2_TAG_ALIGN, 0xc2 /* Avoid padding with long nops. */
.Lmb2ht_init_start\@:
        .short \type
        .short \req
        .long .Lmb2ht_init_end\@ - .Lmb2ht_init_start\@
        .ifnb \args
        mb2ht_args \args
        .endif
.Lmb2ht_init_end\@:
        .endm

.section ".tboot_multiboot_header","w"
        .align 4
/* multiboot header */
multiboot_header:
#define MULTIBOOT_HEADER_FLAGS (MULTIBOOT_HEADER_MODS_ALIGNED | \
                                MULTIBOOT_HEADER_WANT_MEMORY)
        /* magic number for multiboot header */
        .long MULTIBOOT_HEADER_MAGIC
        /* flags for bootloader */
        .long MULTIBOOT_HEADER_FLAGS
        /* checksum: negated sum of above */
        .long -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)

/* multiboot2 header */
        .align 8
multiboot2_header:
        .long MB2_HEADER_MAGIC
        .long MB2_ARCH_X86
        .long multiboot2_header_end - multiboot2_header
        /* checksum */
        .long -(MB2_HEADER_MAGIC + MB2_ARCH_X86 + (multiboot2_header_end - multiboot2_header))

        /* Multiboot2 entry point. */
        mb2ht_init MB2_HDR_TAG_ENTRY_ADDR, MB2_HDR_TAG_REQUIRED, start

        /* The address tag. */
        mb2ht_init MB2_HDR_TAG_ADDR, MB2_HDR_TAG_REQUIRED, \
                   multiboot2_header, /* header_addr */ \
                   _mle_start,        /* load_addr */ \
                   __bss_start,       /* load_end_addr */ \
                   _end               /* bss_end_addr */

        /* Multiboot2 header end tag. */
        mb2ht_init MB2_HDR_TAG_END, MB2_HDR_TAG_REQUIRED
multiboot2_header_end:	

        .size multiboot2_header, . - multiboot2_header
        .type multiboot2_header, @object


        /*
         * Manually defined PE header, based on XEN version created by Daniel Kiper.
         */
.section ".tboot_efi_pe_header","w"
        .align 4

efi_pe_head:
        /*
         * Legacy EXE header.
         *
         * Most of it is copied from binutils package, version 2.30,
         * include/coff/pe.h:struct external_PEI_filehdr and
         * bfd/peXXigen.c:_bfd_XXi_only_swap_filehdr_out().
         *
         * Page is equal 512 bytes here.
         * Paragraph is equal 16 bytes here.
         */
        .short  0x5a4d                               /* EXE magic number. */
        .short  0x90                                 /* Bytes on last page of file. */
        .short  0x3                                  /* Pages in file. */
        .short  0                                    /* Relocations. */
        .short  0x4                                  /* Size of header in paragraphs. */
        .short  0                                    /* Minimum extra paragraphs needed. */
        .short  0xffff                               /* Maximum extra paragraphs needed. */
        .short  0                                    /* Initial (relative) SS value. */
        .short  0xb8                                 /* Initial SP value. */
        .short  0                                    /* Checksum. */
        .short  0                                    /* Initial IP value. */
        .short  0                                    /* Initial (relative) CS value. */
        .short  0x40                                 /* File address of relocation table. */
        .short  0                                    /* Overlay number. */
        .fill   4, 2, 0                              /* Reserved words. */
        .short  0                                    /* OEM identifier. */
        .short  0                                    /* OEM information. */
        .fill   10, 2, 0                             /* Reserved words. */
        .long   pe_header - efi_pe_head              /* File address of the PE header. */

        /*
         * Standard/Minimal DOS code/data.
         *
         * It is copied from binutils package, version 2.30,
         * include/coff/pe.h:struct external_PEI_filehdr and
         * bfd/peXXigen.c:_bfd_XXi_only_swap_filehdr_out().
         *
         * Do not change DOS code/data size!!! Some buggy applications
         * ignore PE header address from EXE header and look for PE header
         * at 0x80 file offset. The size of this code assures that it is
         * found at exactly that address.
         */
        .long   0x0eba1f0e
        .long   0xcd09b400
        .long   0x4c01b821
        .long   0x685421cd
        .long   0x70207369
        .long   0x72676f72
        .long   0x63206d61
        .long   0x6f6e6e61
        .long   0x65622074
        .long   0x6e757220
        .long   0x206e6920
        .long   0x20534f44
        .long   0x65646f6d
        .long   0x0a0d0d2e
        .long   0x24
        .long   0

        /*
         * PE/COFF header.
         *
         * The PE/COFF format is defined by Microsoft, and is available from
         * http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
         *
         * Some ideas are taken from Linux kernel and Xen ARM64.
         */

pe_header:
        .ascii  "PE\0\0"                             /* PE signature. */
        .short  0x8664                               /* Machine: IMAGE_FILE_MACHINE_AMD64 */
        .short  1                                    /* NumberOfSections. */
        .long   0                                    /* TimeDateStamp. */
        .long   0                                    /* PointerToSymbolTable. */
        .long   0                                    /* NumberOfSymbols. */
        .short  section_table - optional_header      /* SizeOfOptionalHeader. */
        .short  0x226                                /* Characteristics:
                                                      *   IMAGE_FILE_EXECUTABLE_IMAGE |
                                                      *   IMAGE_FILE_LARGE_ADDRESS_AWARE |
                                                      *   IMAGE_FILE_DEBUG_STRIPPED |
                                                      *   IMAGE_FILE_LINE_NUMS_STRIPPED
                                                      */

optional_header:
        .short  0x20b                                /* PE format: PE32+ */
        .byte   0x02                                 /* MajorLinkerVersion. */
        .byte   0x1e                                 /* MinorLinkerVersion. */
        .long   __pe_text_raw_end - efi_pe_head_end              /* SizeOfCode. */
        .long   0                                    /* SizeOfInitializedData. */
        .long   0                                    /* SizeOfUninitializedData. */
        .long   sym_offs(efi_start)                  /* AddressOfEntryPoint. */
        .long   sym_offs(start)                      /* BaseOfCode. */
        .quad   0                                    /* ImageBase. */
        .long   4096                                 /* SectionAlignment. */
        .long   4096                       /* FileAlignment. */
        .short  2                                    /* MajorOperatingSystemVersion. */
        .short  0                                    /* MinorOperatingSystemVersion. */
        .short  0                          /* MajorImageVersion. */
        .short  0                       /* MinorImageVersion. */
        .short  2                                    /* MajorSubsystemVersion. */
        .short  0                                    /* MinorSubsystemVersion. */
        .long   0                                    /* Win32VersionValue. */
        .long   __pe_SizeOfImage                     /* SizeOfImage. */
        .long   efi_pe_head_end - efi_pe_head        /* SizeOfHeaders. */
        .long   0                                    /* CheckSum. */
        .short  0xa                                  /* Subsystem: EFI application. */
        .short  0                                    /* DllCharacteristics. */
        .quad   0                                    /* SizeOfStackReserve. */
        .quad   0                                    /* SizeOfStackCommit. */
        .quad   0                                    /* SizeOfHeapReserve. */
        .quad   0                                    /* SizeOfHeapCommit. */
        .long   0                                    /* LoaderFlags. */
        .long   0x6                                  /* NumberOfRvaAndSizes. */

        /* Data Directories. */
        .quad   0                                    /* Export Table. */
        .quad   0                                    /* Import Table. */
        .quad   0                                    /* Resource Table. */
        .quad   0                                    /* Exception Table. */
        .quad   0                                    /* Certificate Table. */
        .quad   0                                    /* Base Relocation Table. */

section_table:
        .ascii  ".text\0\0\0"                        /* Name. */
        .long   __pe_text_raw_end - TBOOT_START  /* VirtualSize. */
        .long   sym_offs(start)                      /* VirtualAddress. */
        .long   __pe_text_raw_end - TBOOT_START  /* SizeOfRawData. */
        .long   sym_offs(start)        /* PointerToRawData. */
        .long   0                                    /* PointerToRelocations. */
        .long   0                                    /* PointerToLinenumbers. */
        .short  0                                    /* NumberOfRelocations. */
        .short  0                                    /* NumberOfLinenumbers. */
        .long   0xe0500020                           /* Characteristics:
                                                      *   IMAGE_SCN_CNT_CODE |
                                                      *   IMAGE_SCN_ALIGN_16BYTES |
                                                      *   IMAGE_SCN_MEM_EXECUTE |
                                                      *   IMAGE_SCN_MEM_READ |
                                                      *   IMAGE_SCN_MEM_WRITE
                                                      */

        .align FILE_ALIGN

efi_pe_head_end:

        .text

ENTRY(start)
ENTRY(_start)
        jmp __start


/* entry point post-launch, to verify memory layout */
/* (must all be w/in one page; since _start is page-aligned, it will be; */
/* which is why we can't call much other code (e.g. printk, TPM fns, etc.) */
ENTRY(_post_launch_entry)
	/* verify phys addr we were entered at is the one we expected
	 * ebx contains the phys addr of the entry point
	 * ecx contains the phy addr of the MLE page table
	 */
	cmp $_post_launch_entry, %ebx
	jne layout_err

	/* verify last entry in MLE page table is the one we expected
	 * this is sufficient because: 1) all addrs must be phys increasing
	 * and 2) tboot is phys contig--therefore if any page were moved to
	 * a different phys addr then the last page would have to be different
	 * from tboot's last page
	 */
	/* get addr of MLE page table from OsSinitData */
	                          /* start of TXT heap (== BiosDataSize) */
	mov (TXT_PRIV_CONFIG_REGS_BASE + TXTCR_HEAP_BASE), %eax
	add (%eax), %eax                   /* skip BiosData */
	add (%eax), %eax                   /* skip OsMleData */
	mov (MLE_PGTBL_OFF+8)(%eax), %eax  /* addr of MLE page table */
	/* get to page table itself (there is only one for tboot) */
	mov (%eax), %eax          /* pgdir ptr -> pgdir */
	/* TODO when SINIT ready */
	/* mov (%ecx), %eax */
	and $PAGE_MASK, %eax
	mov (%eax), %eax          /* pgdir -> pgtbl */
	and $PAGE_MASK, %eax
	/* find last page (pte) */
	mov $_mle_end, %ecx
	sub $_mle_start, %ecx     /* size of MLE */
	shr $PAGE_SHIFT-3, %ecx
	sub $8, %ecx              /* size/4k*8 is offset+1 of last pte */
	add %ecx, %eax
	mov (%eax), %eax          /* pte of last page */
	and $PAGE_MASK, %eax
	/* calc expected addr of last page */
	mov $(_mle_end - 1), %ebx /* addr of last byte of MLE... */
	and $PAGE_MASK, %ebx      /* ...rounded to page start */
	/* are they equal? */
	cmp %ebx, %eax
	je __start                /* yes, so continue with normal launch */

layout_err:       /* layout check failed so TXT RESET */
	                 /* set a special error code */
	movl $LAYOUT_ERR, (TXT_PRIV_CONFIG_REGS_BASE + TXTCR_ERRORCODE)
	                 /* unlock memory config (and serialize) */
	movl $1, (TXT_PRIV_CONFIG_REGS_BASE + TXTCR_CMD_UNLOCK_MEM_CONFIG)
	movl (TXT_PRIV_CONFIG_REGS_BASE + TXTCR_STS), %eax
	                 /* TXT RESET */
	movl $1, (TXT_PRIV_CONFIG_REGS_BASE + TXTCR_CMD_RESET)
	mov $6, %eax
	mov $0xcf9, %edx
	out %al, (%dx)   /* for debug chipsets where TXT RESET may not work */
	ud2


ENTRY(__start)
        /* Set up a few descriptors: on entry only CS is guaranteed good. */
        lgdt    %cs:gdt_descr
        mov     $(ds_sel),%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%fs
        mov     %ecx,%gs
        mov     %ecx,%ss
        ljmp    $(cs_sel),$(1f)
1:	leal	bsp_stack,%esp

        /* Reset EFLAGS (subsumes CLI and CLD). */
        pushl   $0
        popf

        /* preserve EAX to be a param to begin_launch--it should
         *  contain either MULTIBOOT_MAGIC or MULTIBOOT2_MAGIC--we'll need
         * to figure out which */
        mov     %eax,%edx

        /* Initialize BSS (no nasty surprises!) */
        mov     $__bss_start,%edi
        mov     $_end,%ecx
        sub     %edi,%ecx
        xor     %eax,%eax
        rep     stosb

        /* Load IDT */
        lidt    idt_descr

        /* enable MCE */
        mov     %cr4,%eax
        or      $CR4_MCE,%eax
        mov     %eax,%cr4

        /* pass multiboot info struct, magic and call measured launch code */
        push    %edx
        push    %ebx
        call    begin_launch
        ud2

/*
 * vmexit handler
 */
ENTRY(vmx_asm_vmexit_handler)
        call vmx_vmexit_handler
	/* fall through to loop if callee returns (shouldn't happen) */

ENTRY(_mini_guest)
1:	pause
	cmp $0, (aps_exit_guest)
	je 1b
	/* VMCALL out of guest */
	.byte 0x0f,0x01,0xc1
	jmp 1b

#include "shutdown.S"

/*
 * entry point for GETSEC[WAKEUP]
 */
ENTRY(_txt_wakeup)
	# prepare this thread for C code
        /* Set up a few descriptors: on entry only CS is guaranteed good. */
        lgdt    %cs:gdt_descr
        mov     $0x10, %ecx
        mov     %ecx, %ds
        mov     %ecx, %es
        mov     %ecx, %fs
        mov     %ecx, %gs
        mov     %ecx, %ss
        ljmp    $(cs_sel), $(1f)

        /* Load IDT */
1:	lidt    idt_descr

        /* enable MCE */
        mov     %cr4,%eax
        or      $CR4_MCE,%eax
        mov     %eax,%cr4

	# get initial 32-bit local APIC ID for this processor
	mov	$0x0b, %eax
	xor	%edx, %edx
	cpuid

	# set stack as id-based offset from AP stack base
	# spin hlt if we exceed, since C code can't handle shared stack
	cmp	$NR_CPUS, %edx
	jl      3f
	# TBD: increment global counter so BSP can tell we exceeded NR_CPUS
2:	cli
	hlt
	jmp     2b
3:	mov     $AP_STACK_SIZE, %eax
	mul	%edx
	mov	$ap_stacks, %ecx
	sub	%eax, %ecx
	mov	%ecx, %esp

	call	txt_cpu_wakeup


/*
 * entry point for switch to real mode and jump
 * entry point in %ebx
 */
ENTRY(_prot_to_real)
	/* disable interrupts */
	cli
	mov     0x4(%esp), %ebx

	/* deal with parameter, real mode program entry point */
	mov     %ebx, %eax
	and     $0xffff0, %eax
	shr     $4, %eax
	mov     %ax, _real_mode_entry_point + 4
	and     $0xfff0000f, %ebx
	mov     %ebx, _real_mode_entry_point

	/* load proper segments for real mode */
	mov     $(ds16_sel), %ax
	mov     %ax, %ds
	mov     %ax, %es
	mov     %ax, %fs
	mov     %ax, %gs
	mov     %ax, %ss
	lidt    real_idt_desc
	xor     %eax, %eax
	ljmp    $(cs16_sel), $(1f)

	.code16
1:	mov     %eax, %cr0
	mov     $0x0, %ax
	mov     %ax, %ds
	mov     %ax, %es
	mov     %ax, %fs
	mov     %ax, %gs
	mov     %ax, %ss

	.code32

	DATA16
	ADDR16
	ljmp    *_real_mode_entry_point

/*
 * interrupt handler
 */

int_handler:
	call handle_exception
	ud2

/*
 * descriptors and descriptor tables
 */

	.align 8

/* GDT */
gdt_descr:
	.word	gdt_table_end - gdt_table - 1
	.long	gdt_table

        .align PAGE_SIZE, 0

ENTRY(gdt_table)
		/* unused */
        .quad	0x0000000000000000
cs_descr:	/* cs */
	.word	0xffff		/* limit = 4GB */
	.word	0x00		/* base = 0 */
	.word	0x9b00		/* read + exec + accessed */
	.word	0x00cf		/* granularity = 4096 */
ds_descr:	/* ds */
	.word	0xffff		/* limit = 4GB */
	.word	0x00		/* base = 0 */
	.word	0x9300		/* read + write + accessed */
	.word	0x00cf		/* granularity = 4096 */
tss_descr:	/* tss */
	.word	0xffff		/* limit = 4GB */
	.word	0x00		/* base = 0 */
	.word	0x8900		/* system segment, 32b available TSS */
	.word	0x008f		/* granularity = 4096 */
cs16_desc:	/* cs16 */
	.word	0xffff		/* limit = 4GB */
	.word   0x0000      /* base = 0 */
	.word   0x9b00      /* read + exec + accessed */
	.word	0x008f      /* granularity = 4096, D = 0 */
ds16_desc:  /* ds16 */
	.word   0xffff      /* limit = 4GB */
	.word   0x0000      /* base = 0 */
	.word   0x9300      /* read + exec + accessed */
	.word   0x008f      /* granularity = 4096, D = 0 */
		/* end (unused) */
	.quad   0x0000000000000000
ENTRY(gdt_table_end)

/* IDT */
idt_descr:
	.word	idt_table_end - idt_table - 1
	.long	idt_table

	.align	8

idt_table:
	.rept 18
		.word	int_handler - _start
		.word	cs_sel
		.word	0x8e00   /* present, DPL=0, 32b, interrupt */
		.word	(int_handler - _start + TBOOT_START) >> 16
	.endr
	/* for machine-check exception */
		.word	int_handler - _start
		.word	cs_sel
		.word	0x8f00   /* present, DPL=0, 32b, trap */
		.word	(int_handler - _start + TBOOT_START) >> 16
	.rept 237
		.word	int_handler - _start
		.word	cs_sel
		.word	0x8e00   /* present, DPL=0, 32b, interrupt */
		.word	(int_handler - _start + TBOOT_START) >> 16
	.endr
idt_table_end:

/* Real Mode IDT */
real_idt_desc:
	.word   0x03ff
	.long   0

#include "wakeup.S"


/*
 * stacks
 */

.section ".bss.stack_aligned","w"

bsp_stack_end:
        .fill BSP_STACK_SIZE, 1, 0
bsp_stack:

ap_stacks_end:
        .fill AP_STACK_SIZE * NR_CPUS, 1, 0
ap_stacks:


/*
 * page table and VMCS data for AP bringup
 */

        .align PAGE_SIZE, 0
.section ".bss.page_aligned","w"
ENTRY(idle_pg_table)
        .fill 1*PAGE_SIZE,1,0

        .align PAGE_SIZE, 0
ENTRY(host_vmcs)
        .fill 1*PAGE_SIZE,1,0

        .align PAGE_SIZE, 0
/* the input info when os/vmm kerneltrap into tboot */
ENTRY(ap_vmcs)
        .fill NR_CPUS * PAGE_SIZE, 1, 0


/*
 * misc. bss data
 */
.section ".bss"

_real_mode_entry_point:
	.long   0
	.word   0

.section ".data"

ENTRY(s3_flag)
	.long 0

/*
 * shared data page with kernel (i.e. Xen)
 * (put at end so that not split e820 region for tboot)
 */
.section ".tboot_shared","w"
        .align PAGE_SIZE, 0

ENTRY(_tboot_shared)
	.fill	PAGE_SIZE,1,0
        .align PAGE_SIZE, 0

ENTRY(_end)
