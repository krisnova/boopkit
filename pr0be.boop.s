	.text
	.file	"pr0be.boop.c"
	.file	1 "/home/nova/boopkit" "pr0be.boop.c"
	.file	2 "/home/nova/boopkit" "./vmlinux.h"
	.file	3 "/home/nova/boopkit" "./boopkit.h"
	.file	4 "/usr/include/bpf" "bpf_helper_defs.h"
	.section	"tracepoint/tcp/tcp_bad_csum","ax",@progbits
	.globl	tcp_bad_csum                    # -- Begin function tcp_bad_csum
	.p2align	3
	.type	tcp_bad_csum,@function
tcp_bad_csum:                           # @tcp_bad_csum
.Lfunc_begin0:
	.loc	1 68 0                          # pr0be.boop.c:68:0
	.cfi_sections .debug_frame
	.cfi_startproc
# %bb.0:
	#DEBUG_VALUE: tcp_bad_csum:args <- $r1
	r2 = 1
.Ltmp0:
.Ltmp1:
	#DEBUG_VALUE: tcp_bad_csum:saddrkey <- 1
	.loc	1 74 7 prologue_end             # pr0be.boop.c:74:7
.Ltmp2:
	*(u32 *)(r10 - 140) = r2
	.loc	1 75 3                          # pr0be.boop.c:75:3
.Ltmp3:
	r4 = *(u8 *)(r1 + 29)
	r4 <<= 8
	r2 = *(u8 *)(r1 + 28)
	r4 |= r2
	r2 = *(u8 *)(r1 + 31)
	r2 <<= 8
	r3 = *(u8 *)(r1 + 30)
	r2 |= r3
	r0 = *(u8 *)(r1 + 25)
	r0 <<= 8
	r3 = *(u8 *)(r1 + 24)
	r0 |= r3
	r5 = *(u8 *)(r1 + 27)
	r5 <<= 8
	r3 = *(u8 *)(r1 + 26)
	r5 |= r3
	r7 = *(u8 *)(r1 + 21)
	r7 <<= 8
	r3 = *(u8 *)(r1 + 20)
	r7 |= r3
	r3 = *(u8 *)(r1 + 23)
	r3 <<= 8
	r6 = *(u8 *)(r1 + 22)
	r3 |= r6
	r8 = *(u8 *)(r1 + 17)
	r8 <<= 8
	r6 = *(u8 *)(r1 + 16)
	r8 |= r6
	r6 = *(u8 *)(r1 + 19)
	r6 <<= 8
	r9 = *(u8 *)(r1 + 18)
	r6 |= r9
	r6 <<= 16
	r6 |= r8
	r3 <<= 16
	r3 |= r7
	r5 <<= 16
	r5 |= r0
	r2 <<= 16
	r2 |= r4
	r4 = *(u8 *)(r1 + 41)
	r4 <<= 8
	r0 = *(u8 *)(r1 + 40)
	r4 |= r0
	r0 = *(u8 *)(r1 + 43)
	r0 <<= 8
	r7 = *(u8 *)(r1 + 42)
	r0 |= r7
	r2 <<= 32
	r2 |= r5
	r3 <<= 32
	r3 |= r6
	r0 <<= 16
	r0 |= r4
	r5 = *(u8 *)(r1 + 33)
	r5 <<= 8
	r4 = *(u8 *)(r1 + 32)
	r5 |= r4
	r4 = *(u8 *)(r1 + 35)
	r4 <<= 8
	r6 = *(u8 *)(r1 + 34)
	r4 |= r6
	*(u32 *)(r10 - 112) = r0
	*(u64 *)(r10 - 136) = r3
	*(u64 *)(r10 - 128) = r2
	r4 <<= 16
	r4 |= r5
	r2 = *(u8 *)(r1 + 37)
	r2 <<= 8
	r3 = *(u8 *)(r1 + 36)
	r2 |= r3
	r3 = *(u8 *)(r1 + 38)
	r1 = *(u8 *)(r1 + 39)
.Ltmp4:
.Ltmp5:
	r1 <<= 8
	r1 |= r3
	r1 <<= 16
	r1 |= r2
	r1 <<= 32
	r1 |= r4
	*(u64 *)(r10 - 120) = r1
.Ltmp6:
.Ltmp7:
	#DEBUG_VALUE: tcp_bad_csum:saddrkey <- [DW_OP_plus_uconst 4, DW_OP_deref] $r10
	.loc	1 0 3 is_stmt 0                 # pr0be.boop.c:0:3
	r2 = r10
.Ltmp8:
	r2 += -140
	r3 = r10
	r3 += -136
	.loc	1 76 3 is_stmt 1                # pr0be.boop.c:76:3
.Ltmp9:
	r1 = encapsulatedboop ll
	r4 = 1
	call 2
.Ltmp10:
	.loc	1 77 3                          # pr0be.boop.c:77:3
.Ltmp11:
	r0 = 0
	exit
.Ltmp12:
.Ltmp13:
.Lfunc_end0:
	.size	tcp_bad_csum, .Lfunc_end0-tcp_bad_csum
	.cfi_endproc
                                        # -- End function
	.section	"tracepoint/tcp/tcp_receive_reset","ax",@progbits
	.globl	tcp_receive_reset               # -- Begin function tcp_receive_reset
	.p2align	3
	.type	tcp_receive_reset,@function
tcp_receive_reset:                      # @tcp_receive_reset
.Lfunc_begin1:
	.loc	1 118 0                         # pr0be.boop.c:118:0
	.cfi_startproc
# %bb.0:
	#DEBUG_VALUE: tcp_receive_reset:args <- $r1
	r6 = r1
.Ltmp14:
.Ltmp15:
	#DEBUG_VALUE: tcp_receive_reset:args <- $r6
	r1 = 1
.Ltmp16:
.Ltmp17:
	#DEBUG_VALUE: tcp_receive_reset:saddrkey <- 1
	.loc	1 119 7 prologue_end            # pr0be.boop.c:119:7
.Ltmp18:
	*(u32 *)(r10 - 4) = r1
.Ltmp19:
	.loc	1 122 3                         # pr0be.boop.c:122:3
.Ltmp20:
.Ltmp21:
	r3 = *(u64 *)(r6 + 64)
	r1 = tcp_receive_reset.____fmt ll
	r2 = 5
	call 6
.Ltmp22:
.Ltmp23:
	.loc	1 124 3                         # pr0be.boop.c:124:3
.Ltmp24:
	r1 = *(u16 *)(r6 + 22)
	r2 = *(u16 *)(r6 + 24)
	r2 <<= 16
	r2 |= r1
	*(u32 *)(r10 - 136) = r2
.Ltmp25:
.Ltmp26:
	#DEBUG_VALUE: tcp_receive_reset:saddrkey <- [DW_OP_plus_uconst 132, DW_OP_deref] $r10
	.loc	1 0 3 is_stmt 0                 # pr0be.boop.c:0:3
	r2 = r10
.Ltmp27:
	r2 += -4
	r3 = r10
	r3 += -136
	.loc	1 126 3 is_stmt 1               # pr0be.boop.c:126:3
.Ltmp28:
	r1 = encapsulatedboop ll
	r4 = 1
	call 2
.Ltmp29:
	.loc	1 127 3                         # pr0be.boop.c:127:3
.Ltmp30:
	r0 = 0
	exit
.Ltmp31:
.Ltmp32:
.Lfunc_end1:
	.size	tcp_receive_reset, .Lfunc_end1-tcp_receive_reset
	.cfi_endproc
                                        # -- End function
	.type	encapsulatedboop,@object        # @encapsulatedboop
	.section	.maps,"aw",@progbits
	.globl	encapsulatedboop
	.p2align	3
encapsulatedboop:
	.zero	32
	.size	encapsulatedboop, 32

	.type	tcp_receive_reset.____fmt,@object # @tcp_receive_reset.____fmt
	.section	.rodata,"a",@progbits
tcp_receive_reset.____fmt:
	.asciz	"%llx"
	.size	tcp_receive_reset.____fmt, 5

	.type	LICENSE,@object                 # @LICENSE
	.section	license,"aw",@progbits
	.globl	LICENSE
LICENSE:
	.asciz	"GPL"
	.size	LICENSE, 4

	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
	.quad	-1
	.quad	.Lfunc_begin0                   #   base address
	.quad	.Lfunc_begin0-.Lfunc_begin0
	.quad	.Ltmp4-.Lfunc_begin0
	.short	1                               # Loc expr size
	.byte	81                              # DW_OP_reg1
	.quad	0
	.quad	0
.Ldebug_loc1:
	.quad	-1
	.quad	.Lfunc_begin0                   #   base address
	.quad	.Ltmp0-.Lfunc_begin0
	.quad	.Ltmp6-.Lfunc_begin0
	.short	3                               # Loc expr size
	.byte	17                              # DW_OP_consts
	.byte	1                               # 1
	.byte	159                             # DW_OP_stack_value
	.quad	.Ltmp6-.Lfunc_begin0
	.quad	.Lfunc_end0-.Lfunc_begin0
	.short	2                               # Loc expr size
	.byte	122                             # DW_OP_breg10
	.byte	4                               # 4
	.quad	0
	.quad	0
.Ldebug_loc2:
	.quad	-1
	.quad	.Lfunc_begin1                   #   base address
	.quad	.Lfunc_begin1-.Lfunc_begin1
	.quad	.Ltmp14-.Lfunc_begin1
	.short	1                               # Loc expr size
	.byte	81                              # DW_OP_reg1
	.quad	.Ltmp14-.Lfunc_begin1
	.quad	.Lfunc_end1-.Lfunc_begin1
	.short	1                               # Loc expr size
	.byte	86                              # DW_OP_reg6
	.quad	0
	.quad	0
.Ldebug_loc3:
	.quad	-1
	.quad	.Lfunc_begin1                   #   base address
	.quad	.Ltmp16-.Lfunc_begin1
	.quad	.Ltmp25-.Lfunc_begin1
	.short	3                               # Loc expr size
	.byte	17                              # DW_OP_consts
	.byte	1                               # 1
	.byte	159                             # DW_OP_stack_value
	.quad	.Ltmp25-.Lfunc_begin1
	.quad	.Lfunc_end1-.Lfunc_begin1
	.short	3                               # Loc expr size
	.byte	122                             # DW_OP_breg10
	.byte	132                             # 132
	.byte	1                               # 
	.quad	0
	.quad	0
	.section	.debug_abbrev,"",@progbits
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	37                              # DW_AT_producer
	.byte	14                              # DW_FORM_strp
	.byte	19                              # DW_AT_language
	.byte	5                               # DW_FORM_data2
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	16                              # DW_AT_stmt_list
	.byte	23                              # DW_FORM_sec_offset
	.byte	27                              # DW_AT_comp_dir
	.byte	14                              # DW_FORM_strp
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	85                              # DW_AT_ranges
	.byte	23                              # DW_FORM_sec_offset
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	2                               # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
	.byte	64                              # DW_AT_frame_base
	.byte	24                              # DW_FORM_exprloc
	.ascii	"\227B"                         # DW_AT_GNU_all_call_sites
	.byte	25                              # DW_FORM_flag_present
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	39                              # DW_AT_prototyped
	.byte	25                              # DW_FORM_flag_present
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	63                              # DW_AT_external
	.byte	25                              # DW_FORM_flag_present
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	3                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	4                               # Abbreviation Code
	.byte	5                               # DW_TAG_formal_parameter
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	23                              # DW_FORM_sec_offset
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	5                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	6                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	23                              # DW_FORM_sec_offset
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	7                               # Abbreviation Code
	.byte	1                               # DW_TAG_array_type
	.byte	1                               # DW_CHILDREN_yes
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	8                               # Abbreviation Code
	.byte	33                              # DW_TAG_subrange_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	55                              # DW_AT_count
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	9                               # Abbreviation Code
	.byte	38                              # DW_TAG_const_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	10                              # Abbreviation Code
	.byte	36                              # DW_TAG_base_type
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	62                              # DW_AT_encoding
	.byte	11                              # DW_FORM_data1
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	11                              # Abbreviation Code
	.byte	36                              # DW_TAG_base_type
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	62                              # DW_AT_encoding
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	12                              # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	63                              # DW_AT_external
	.byte	25                              # DW_FORM_flag_present
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	13                              # Abbreviation Code
	.byte	19                              # DW_TAG_structure_type
	.byte	1                               # DW_CHILDREN_yes
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	14                              # Abbreviation Code
	.byte	13                              # DW_TAG_member
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	56                              # DW_AT_data_member_location
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	15                              # Abbreviation Code
	.byte	15                              # DW_TAG_pointer_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	16                              # Abbreviation Code
	.byte	19                              # DW_TAG_structure_type
	.byte	1                               # DW_CHILDREN_yes
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	17                              # Abbreviation Code
	.byte	22                              # DW_TAG_typedef
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	18                              # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	19                              # Abbreviation Code
	.byte	21                              # DW_TAG_subroutine_type
	.byte	1                               # DW_CHILDREN_yes
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	39                              # DW_AT_prototyped
	.byte	25                              # DW_FORM_flag_present
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	20                              # Abbreviation Code
	.byte	5                               # DW_TAG_formal_parameter
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	21                              # Abbreviation Code
	.byte	15                              # DW_TAG_pointer_type
	.byte	0                               # DW_CHILDREN_no
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	22                              # Abbreviation Code
	.byte	38                              # DW_TAG_const_type
	.byte	0                               # DW_CHILDREN_no
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	23                              # Abbreviation Code
	.byte	24                              # DW_TAG_unspecified_parameters
	.byte	0                               # DW_CHILDREN_no
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	0                               # EOM(3)
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.long	.Ldebug_info_end0-.Ldebug_info_start0 # Length of Unit
.Ldebug_info_start0:
	.short	4                               # DWARF version number
	.long	.debug_abbrev                   # Offset Into Abbrev. Section
	.byte	8                               # Address Size (in bytes)
	.byte	1                               # Abbrev [1] 0xb:0x339 DW_TAG_compile_unit
	.long	.Linfo_string0                  # DW_AT_producer
	.short	12                              # DW_AT_language
	.long	.Linfo_string1                  # DW_AT_name
	.long	.Lline_table_start0             # DW_AT_stmt_list
	.long	.Linfo_string2                  # DW_AT_comp_dir
	.quad	0                               # DW_AT_low_pc
	.long	.Ldebug_ranges0                 # DW_AT_ranges
	.byte	2                               # Abbrev [2] 0x2a:0x5b DW_TAG_subprogram
	.quad	.Lfunc_begin1                   # DW_AT_low_pc
	.long	.Lfunc_end1-.Lfunc_begin1       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	90
                                        # DW_AT_GNU_all_call_sites
	.long	.Linfo_string26                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	118                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.long	288                             # DW_AT_type
                                        # DW_AT_external
	.byte	3                               # Abbrev [3] 0x43:0x15 DW_TAG_variable
	.long	.Linfo_string3                  # DW_AT_name
	.long	133                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	122                             # DW_AT_decl_line
	.byte	9                               # DW_AT_location
	.byte	3
	.quad	tcp_receive_reset.____fmt
	.byte	4                               # Abbrev [4] 0x58:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc2                    # DW_AT_location
	.long	.Linfo_string28                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	118                             # DW_AT_decl_line
	.long	671                             # DW_AT_type
	.byte	5                               # Abbrev [5] 0x67:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	0
	.long	.Linfo_string27                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	123                             # DW_AT_decl_line
	.long	322                             # DW_AT_type
	.byte	6                               # Abbrev [6] 0x75:0xf DW_TAG_variable
	.long	.Ldebug_loc3                    # DW_AT_location
	.long	.Linfo_string34                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	119                             # DW_AT_decl_line
	.long	288                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	7                               # Abbrev [7] 0x85:0xc DW_TAG_array_type
	.long	145                             # DW_AT_type
	.byte	8                               # Abbrev [8] 0x8a:0x6 DW_TAG_subrange_type
	.long	157                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	9                               # Abbrev [9] 0x91:0x5 DW_TAG_const_type
	.long	150                             # DW_AT_type
	.byte	10                              # Abbrev [10] 0x96:0x7 DW_TAG_base_type
	.long	.Linfo_string4                  # DW_AT_name
	.byte	6                               # DW_AT_encoding
	.byte	1                               # DW_AT_byte_size
	.byte	11                              # Abbrev [11] 0x9d:0x7 DW_TAG_base_type
	.long	.Linfo_string5                  # DW_AT_name
	.byte	8                               # DW_AT_byte_size
	.byte	7                               # DW_AT_encoding
	.byte	12                              # Abbrev [12] 0xa4:0x15 DW_TAG_variable
	.long	.Linfo_string6                  # DW_AT_name
	.long	185                             # DW_AT_type
                                        # DW_AT_external
	.byte	1                               # DW_AT_decl_file
	.byte	133                             # DW_AT_decl_line
	.byte	9                               # DW_AT_location
	.byte	3
	.quad	LICENSE
	.byte	7                               # Abbrev [7] 0xb9:0xc DW_TAG_array_type
	.long	150                             # DW_AT_type
	.byte	8                               # Abbrev [8] 0xbe:0x6 DW_TAG_subrange_type
	.long	157                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	12                              # Abbrev [12] 0xc5:0x15 DW_TAG_variable
	.long	.Linfo_string7                  # DW_AT_name
	.long	218                             # DW_AT_type
                                        # DW_AT_external
	.byte	1                               # DW_AT_decl_file
	.byte	43                              # DW_AT_decl_line
	.byte	9                               # DW_AT_location
	.byte	3
	.quad	encapsulatedboop
	.byte	13                              # Abbrev [13] 0xda:0x35 DW_TAG_structure_type
	.byte	32                              # DW_AT_byte_size
	.byte	1                               # DW_AT_decl_file
	.byte	38                              # DW_AT_decl_line
	.byte	14                              # Abbrev [14] 0xde:0xc DW_TAG_member
	.long	.Linfo_string8                  # DW_AT_name
	.long	271                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	39                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0xea:0xc DW_TAG_member
	.long	.Linfo_string10                 # DW_AT_name
	.long	295                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	40                              # DW_AT_decl_line
	.byte	8                               # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0xf6:0xc DW_TAG_member
	.long	.Linfo_string11                 # DW_AT_name
	.long	312                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	41                              # DW_AT_decl_line
	.byte	16                              # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x102:0xc DW_TAG_member
	.long	.Linfo_string12                 # DW_AT_name
	.long	317                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	42                              # DW_AT_decl_line
	.byte	24                              # DW_AT_data_member_location
	.byte	0                               # End Of Children Mark
	.byte	15                              # Abbrev [15] 0x10f:0x5 DW_TAG_pointer_type
	.long	276                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x114:0xc DW_TAG_array_type
	.long	288                             # DW_AT_type
	.byte	8                               # Abbrev [8] 0x119:0x6 DW_TAG_subrange_type
	.long	157                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	10                              # Abbrev [10] 0x120:0x7 DW_TAG_base_type
	.long	.Linfo_string9                  # DW_AT_name
	.byte	5                               # DW_AT_encoding
	.byte	4                               # DW_AT_byte_size
	.byte	15                              # Abbrev [15] 0x127:0x5 DW_TAG_pointer_type
	.long	300                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x12c:0xc DW_TAG_array_type
	.long	288                             # DW_AT_type
	.byte	8                               # Abbrev [8] 0x131:0x6 DW_TAG_subrange_type
	.long	157                             # DW_AT_type
	.byte	128                             # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	15                              # Abbrev [15] 0x138:0x5 DW_TAG_pointer_type
	.long	288                             # DW_AT_type
	.byte	15                              # Abbrev [15] 0x13d:0x5 DW_TAG_pointer_type
	.long	322                             # DW_AT_type
	.byte	16                              # Abbrev [16] 0x142:0x21 DW_TAG_structure_type
	.long	.Linfo_string17                 # DW_AT_name
	.byte	132                             # DW_AT_byte_size
	.byte	3                               # DW_AT_decl_file
	.byte	29                              # DW_AT_decl_line
	.byte	14                              # Abbrev [14] 0x14a:0xc DW_TAG_member
	.long	.Linfo_string13                 # DW_AT_name
	.long	355                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	32                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x156:0xc DW_TAG_member
	.long	.Linfo_string16                 # DW_AT_name
	.long	385                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	36                              # DW_AT_decl_line
	.byte	4                               # DW_AT_data_member_location
	.byte	0                               # End Of Children Mark
	.byte	7                               # Abbrev [7] 0x163:0xc DW_TAG_array_type
	.long	367                             # DW_AT_type
	.byte	8                               # Abbrev [8] 0x168:0x6 DW_TAG_subrange_type
	.long	157                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	17                              # Abbrev [17] 0x16f:0xb DW_TAG_typedef
	.long	378                             # DW_AT_type
	.long	.Linfo_string15                 # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	10                              # DW_AT_decl_line
	.byte	10                              # Abbrev [10] 0x17a:0x7 DW_TAG_base_type
	.long	.Linfo_string14                 # DW_AT_name
	.byte	8                               # DW_AT_encoding
	.byte	1                               # DW_AT_byte_size
	.byte	7                               # Abbrev [7] 0x181:0xc DW_TAG_array_type
	.long	150                             # DW_AT_type
	.byte	8                               # Abbrev [8] 0x186:0x6 DW_TAG_subrange_type
	.long	157                             # DW_AT_type
	.byte	128                             # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	18                              # Abbrev [18] 0x18d:0xb DW_TAG_variable
	.long	.Linfo_string18                 # DW_AT_name
	.long	408                             # DW_AT_type
	.byte	4                               # DW_AT_decl_file
	.byte	73                              # DW_AT_decl_line
	.byte	15                              # Abbrev [15] 0x198:0x5 DW_TAG_pointer_type
	.long	413                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x19d:0x1a DW_TAG_subroutine_type
	.long	439                             # DW_AT_type
                                        # DW_AT_prototyped
	.byte	20                              # Abbrev [20] 0x1a2:0x5 DW_TAG_formal_parameter
	.long	446                             # DW_AT_type
	.byte	20                              # Abbrev [20] 0x1a7:0x5 DW_TAG_formal_parameter
	.long	447                             # DW_AT_type
	.byte	20                              # Abbrev [20] 0x1ac:0x5 DW_TAG_formal_parameter
	.long	447                             # DW_AT_type
	.byte	20                              # Abbrev [20] 0x1b1:0x5 DW_TAG_formal_parameter
	.long	453                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	10                              # Abbrev [10] 0x1b7:0x7 DW_TAG_base_type
	.long	.Linfo_string19                 # DW_AT_name
	.byte	5                               # DW_AT_encoding
	.byte	8                               # DW_AT_byte_size
	.byte	21                              # Abbrev [21] 0x1be:0x1 DW_TAG_pointer_type
	.byte	15                              # Abbrev [15] 0x1bf:0x5 DW_TAG_pointer_type
	.long	452                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1c4:0x1 DW_TAG_const_type
	.byte	17                              # Abbrev [17] 0x1c5:0xb DW_TAG_typedef
	.long	464                             # DW_AT_type
	.long	.Linfo_string21                 # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	22                              # DW_AT_decl_line
	.byte	10                              # Abbrev [10] 0x1d0:0x7 DW_TAG_base_type
	.long	.Linfo_string20                 # DW_AT_name
	.byte	7                               # DW_AT_encoding
	.byte	8                               # DW_AT_byte_size
	.byte	18                              # Abbrev [18] 0x1d7:0xb DW_TAG_variable
	.long	.Linfo_string22                 # DW_AT_name
	.long	482                             # DW_AT_type
	.byte	4                               # DW_AT_decl_file
	.byte	172                             # DW_AT_decl_line
	.byte	15                              # Abbrev [15] 0x1e2:0x5 DW_TAG_pointer_type
	.long	487                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x1e7:0x11 DW_TAG_subroutine_type
	.long	439                             # DW_AT_type
                                        # DW_AT_prototyped
	.byte	20                              # Abbrev [20] 0x1ec:0x5 DW_TAG_formal_parameter
	.long	504                             # DW_AT_type
	.byte	20                              # Abbrev [20] 0x1f1:0x5 DW_TAG_formal_parameter
	.long	509                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0x1f6:0x1 DW_TAG_unspecified_parameters
	.byte	0                               # End Of Children Mark
	.byte	15                              # Abbrev [15] 0x1f8:0x5 DW_TAG_pointer_type
	.long	145                             # DW_AT_type
	.byte	17                              # Abbrev [17] 0x1fd:0xb DW_TAG_typedef
	.long	520                             # DW_AT_type
	.long	.Linfo_string24                 # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	18                              # DW_AT_decl_line
	.byte	10                              # Abbrev [10] 0x208:0x7 DW_TAG_base_type
	.long	.Linfo_string23                 # DW_AT_name
	.byte	7                               # DW_AT_encoding
	.byte	4                               # DW_AT_byte_size
	.byte	2                               # Abbrev [2] 0x20f:0x46 DW_TAG_subprogram
	.quad	.Lfunc_begin0                   # DW_AT_low_pc
	.long	.Lfunc_end0-.Lfunc_begin0       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	90
                                        # DW_AT_GNU_all_call_sites
	.long	.Linfo_string25                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	68                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.long	288                             # DW_AT_type
                                        # DW_AT_external
	.byte	4                               # Abbrev [4] 0x228:0xf DW_TAG_formal_parameter
	.long	.Ldebug_loc0                    # DW_AT_location
	.long	.Linfo_string28                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	68                              # DW_AT_decl_line
	.long	597                             # DW_AT_type
	.byte	5                               # Abbrev [5] 0x237:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	8
	.long	.Linfo_string27                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	73                              # DW_AT_decl_line
	.long	322                             # DW_AT_type
	.byte	6                               # Abbrev [6] 0x245:0xf DW_TAG_variable
	.long	.Ldebug_loc1                    # DW_AT_location
	.long	.Linfo_string34                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	74                              # DW_AT_decl_line
	.long	288                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	15                              # Abbrev [15] 0x255:0x5 DW_TAG_pointer_type
	.long	602                             # DW_AT_type
	.byte	16                              # Abbrev [16] 0x25a:0x39 DW_TAG_structure_type
	.long	.Linfo_string33                 # DW_AT_name
	.byte	72                              # DW_AT_byte_size
	.byte	1                               # DW_AT_decl_file
	.byte	45                              # DW_AT_decl_line
	.byte	14                              # Abbrev [14] 0x262:0xc DW_TAG_member
	.long	.Linfo_string29                 # DW_AT_name
	.long	464                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	46                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x26e:0xc DW_TAG_member
	.long	.Linfo_string30                 # DW_AT_name
	.long	447                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	48                              # DW_AT_decl_line
	.byte	8                               # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x27a:0xc DW_TAG_member
	.long	.Linfo_string31                 # DW_AT_name
	.long	659                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	49                              # DW_AT_decl_line
	.byte	16                              # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x286:0xc DW_TAG_member
	.long	.Linfo_string32                 # DW_AT_name
	.long	659                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	50                              # DW_AT_decl_line
	.byte	44                              # DW_AT_data_member_location
	.byte	0                               # End Of Children Mark
	.byte	7                               # Abbrev [7] 0x293:0xc DW_TAG_array_type
	.long	367                             # DW_AT_type
	.byte	8                               # Abbrev [8] 0x298:0x6 DW_TAG_subrange_type
	.long	157                             # DW_AT_type
	.byte	28                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	15                              # Abbrev [15] 0x29f:0x5 DW_TAG_pointer_type
	.long	676                             # DW_AT_type
	.byte	16                              # Abbrev [16] 0x2a4:0x81 DW_TAG_structure_type
	.long	.Linfo_string44                 # DW_AT_name
	.byte	72                              # DW_AT_byte_size
	.byte	1                               # DW_AT_decl_file
	.byte	80                              # DW_AT_decl_line
	.byte	14                              # Abbrev [14] 0x2ac:0xc DW_TAG_member
	.long	.Linfo_string29                 # DW_AT_name
	.long	464                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	81                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x2b8:0xc DW_TAG_member
	.long	.Linfo_string35                 # DW_AT_name
	.long	447                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	83                              # DW_AT_decl_line
	.byte	8                               # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x2c4:0xc DW_TAG_member
	.long	.Linfo_string36                 # DW_AT_name
	.long	805                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	84                              # DW_AT_decl_line
	.byte	16                              # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x2d0:0xc DW_TAG_member
	.long	.Linfo_string39                 # DW_AT_name
	.long	805                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	85                              # DW_AT_decl_line
	.byte	18                              # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x2dc:0xc DW_TAG_member
	.long	.Linfo_string40                 # DW_AT_name
	.long	805                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	86                              # DW_AT_decl_line
	.byte	20                              # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x2e8:0xc DW_TAG_member
	.long	.Linfo_string31                 # DW_AT_name
	.long	355                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	87                              # DW_AT_decl_line
	.byte	22                              # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x2f4:0xc DW_TAG_member
	.long	.Linfo_string32                 # DW_AT_name
	.long	355                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	88                              # DW_AT_decl_line
	.byte	26                              # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x300:0xc DW_TAG_member
	.long	.Linfo_string41                 # DW_AT_name
	.long	823                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	89                              # DW_AT_decl_line
	.byte	30                              # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x30c:0xc DW_TAG_member
	.long	.Linfo_string42                 # DW_AT_name
	.long	823                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	90                              # DW_AT_decl_line
	.byte	46                              # DW_AT_data_member_location
	.byte	14                              # Abbrev [14] 0x318:0xc DW_TAG_member
	.long	.Linfo_string43                 # DW_AT_name
	.long	453                             # DW_AT_type
	.byte	1                               # DW_AT_decl_file
	.byte	91                              # DW_AT_decl_line
	.byte	64                              # DW_AT_data_member_location
	.byte	0                               # End Of Children Mark
	.byte	17                              # Abbrev [17] 0x325:0xb DW_TAG_typedef
	.long	816                             # DW_AT_type
	.long	.Linfo_string38                 # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	14                              # DW_AT_decl_line
	.byte	10                              # Abbrev [10] 0x330:0x7 DW_TAG_base_type
	.long	.Linfo_string37                 # DW_AT_name
	.byte	7                               # DW_AT_encoding
	.byte	2                               # DW_AT_byte_size
	.byte	7                               # Abbrev [7] 0x337:0xc DW_TAG_array_type
	.long	367                             # DW_AT_type
	.byte	8                               # Abbrev [8] 0x33c:0x6 DW_TAG_subrange_type
	.long	157                             # DW_AT_type
	.byte	16                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_ranges,"",@progbits
.Ldebug_ranges0:
	.quad	.Lfunc_begin0
	.quad	.Lfunc_end0
	.quad	.Lfunc_begin1
	.quad	.Lfunc_end1
	.quad	0
	.quad	0
	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 13.0.1"          # string offset=0
.Linfo_string1:
	.asciz	"pr0be.boop.c"                  # string offset=21
.Linfo_string2:
	.asciz	"/home/nova/boopkit"            # string offset=34
.Linfo_string3:
	.asciz	"____fmt"                       # string offset=53
.Linfo_string4:
	.asciz	"char"                          # string offset=61
.Linfo_string5:
	.asciz	"__ARRAY_SIZE_TYPE__"           # string offset=66
.Linfo_string6:
	.asciz	"LICENSE"                       # string offset=86
.Linfo_string7:
	.asciz	"encapsulatedboop"              # string offset=94
.Linfo_string8:
	.asciz	"type"                          # string offset=111
.Linfo_string9:
	.asciz	"int"                           # string offset=116
.Linfo_string10:
	.asciz	"max_entries"                   # string offset=120
.Linfo_string11:
	.asciz	"key"                           # string offset=132
.Linfo_string12:
	.asciz	"value"                         # string offset=136
.Linfo_string13:
	.asciz	"saddrval"                      # string offset=142
.Linfo_string14:
	.asciz	"unsigned char"                 # string offset=151
.Linfo_string15:
	.asciz	"__u8"                          # string offset=165
.Linfo_string16:
	.asciz	"rce"                           # string offset=170
.Linfo_string17:
	.asciz	"encapsulated_tcp_boop"         # string offset=174
.Linfo_string18:
	.asciz	"bpf_map_update_elem"           # string offset=196
.Linfo_string19:
	.asciz	"long int"                      # string offset=216
.Linfo_string20:
	.asciz	"long long unsigned int"        # string offset=225
.Linfo_string21:
	.asciz	"__u64"                         # string offset=248
.Linfo_string22:
	.asciz	"bpf_trace_printk"              # string offset=254
.Linfo_string23:
	.asciz	"unsigned int"                  # string offset=271
.Linfo_string24:
	.asciz	"__u32"                         # string offset=284
.Linfo_string25:
	.asciz	"tcp_bad_csum"                  # string offset=290
.Linfo_string26:
	.asciz	"tcp_receive_reset"             # string offset=303
.Linfo_string27:
	.asciz	"ret"                           # string offset=321
.Linfo_string28:
	.asciz	"args"                          # string offset=325
.Linfo_string29:
	.asciz	"pad"                           # string offset=330
.Linfo_string30:
	.asciz	"skbaddr"                       # string offset=334
.Linfo_string31:
	.asciz	"saddr"                         # string offset=342
.Linfo_string32:
	.asciz	"daddr"                         # string offset=348
.Linfo_string33:
	.asciz	"tcp_bad_csum_args_t"           # string offset=354
.Linfo_string34:
	.asciz	"saddrkey"                      # string offset=374
.Linfo_string35:
	.asciz	"skaddr"                        # string offset=383
.Linfo_string36:
	.asciz	"sport"                         # string offset=390
.Linfo_string37:
	.asciz	"unsigned short"                # string offset=396
.Linfo_string38:
	.asciz	"__u16"                         # string offset=411
.Linfo_string39:
	.asciz	"dport"                         # string offset=417
.Linfo_string40:
	.asciz	"family"                        # string offset=423
.Linfo_string41:
	.asciz	"saddr_v6"                      # string offset=430
.Linfo_string42:
	.asciz	"daddr_v6"                      # string offset=439
.Linfo_string43:
	.asciz	"sock_cookie"                   # string offset=448
.Linfo_string44:
	.asciz	"tcp_receive_reset_args_t"      # string offset=460
	.section	.BTF,"",@progbits
	.short	60319                           # 0xeb9f
	.byte	1
	.byte	0
	.long	24
	.long	0
	.long	904
	.long	904
	.long	854
	.long	0                               # BTF_KIND_PTR(id = 1)
	.long	33554432                        # 0x2000000
	.long	3
	.long	1                               # BTF_KIND_INT(id = 2)
	.long	16777216                        # 0x1000000
	.long	4
	.long	16777248                        # 0x1000020
	.long	0                               # BTF_KIND_ARRAY(id = 3)
	.long	50331648                        # 0x3000000
	.long	0
	.long	2
	.long	4
	.long	1
	.long	5                               # BTF_KIND_INT(id = 4)
	.long	16777216                        # 0x1000000
	.long	4
	.long	32                              # 0x20
	.long	0                               # BTF_KIND_PTR(id = 5)
	.long	33554432                        # 0x2000000
	.long	6
	.long	0                               # BTF_KIND_ARRAY(id = 6)
	.long	50331648                        # 0x3000000
	.long	0
	.long	2
	.long	4
	.long	128
	.long	0                               # BTF_KIND_PTR(id = 7)
	.long	33554432                        # 0x2000000
	.long	2
	.long	0                               # BTF_KIND_PTR(id = 8)
	.long	33554432                        # 0x2000000
	.long	9
	.long	25                              # BTF_KIND_STRUCT(id = 9)
	.long	67108866                        # 0x4000002
	.long	132
	.long	47
	.long	12
	.long	0                               # 0x0
	.long	56
	.long	14
	.long	32                              # 0x20
	.long	60                              # BTF_KIND_TYPEDEF(id = 10)
	.long	134217728                       # 0x8000000
	.long	11
	.long	65                              # BTF_KIND_INT(id = 11)
	.long	16777216                        # 0x1000000
	.long	1
	.long	8                               # 0x8
	.long	0                               # BTF_KIND_ARRAY(id = 12)
	.long	50331648                        # 0x3000000
	.long	0
	.long	10
	.long	4
	.long	4
	.long	79                              # BTF_KIND_INT(id = 13)
	.long	16777216                        # 0x1000000
	.long	1
	.long	16777224                        # 0x1000008
	.long	0                               # BTF_KIND_ARRAY(id = 14)
	.long	50331648                        # 0x3000000
	.long	0
	.long	13
	.long	4
	.long	128
	.long	0                               # BTF_KIND_STRUCT(id = 15)
	.long	67108868                        # 0x4000004
	.long	32
	.long	84
	.long	1
	.long	0                               # 0x0
	.long	89
	.long	5
	.long	64                              # 0x40
	.long	101
	.long	7
	.long	128                             # 0x80
	.long	105
	.long	8
	.long	192                             # 0xc0
	.long	111                             # BTF_KIND_VAR(id = 16)
	.long	234881024                       # 0xe000000
	.long	15
	.long	1
	.long	0                               # BTF_KIND_PTR(id = 17)
	.long	33554432                        # 0x2000000
	.long	18
	.long	128                             # BTF_KIND_STRUCT(id = 18)
	.long	67108868                        # 0x4000004
	.long	72
	.long	148
	.long	19
	.long	0                               # 0x0
	.long	152
	.long	20
	.long	64                              # 0x40
	.long	160
	.long	22
	.long	128                             # 0x80
	.long	166
	.long	22
	.long	352                             # 0x160
	.long	172                             # BTF_KIND_INT(id = 19)
	.long	16777216                        # 0x1000000
	.long	8
	.long	64                              # 0x40
	.long	0                               # BTF_KIND_PTR(id = 20)
	.long	33554432                        # 0x2000000
	.long	21
	.long	0                               # BTF_KIND_CONST(id = 21)
	.long	167772160                       # 0xa000000
	.long	0
	.long	0                               # BTF_KIND_ARRAY(id = 22)
	.long	50331648                        # 0x3000000
	.long	0
	.long	10
	.long	4
	.long	28
	.long	0                               # BTF_KIND_FUNC_PROTO(id = 23)
	.long	218103809                       # 0xd000001
	.long	2
	.long	195
	.long	17
	.long	200                             # BTF_KIND_FUNC(id = 24)
	.long	201326593                       # 0xc000001
	.long	23
	.long	0                               # BTF_KIND_PTR(id = 25)
	.long	33554432                        # 0x2000000
	.long	26
	.long	477                             # BTF_KIND_STRUCT(id = 26)
	.long	67108874                        # 0x400000a
	.long	72
	.long	148
	.long	19
	.long	0                               # 0x0
	.long	502
	.long	20
	.long	64                              # 0x40
	.long	509
	.long	27
	.long	128                             # 0x80
	.long	515
	.long	27
	.long	144                             # 0x90
	.long	521
	.long	27
	.long	160                             # 0xa0
	.long	160
	.long	12
	.long	176                             # 0xb0
	.long	166
	.long	12
	.long	208                             # 0xd0
	.long	528
	.long	29
	.long	240                             # 0xf0
	.long	537
	.long	29
	.long	368                             # 0x170
	.long	546
	.long	30
	.long	512                             # 0x200
	.long	558                             # BTF_KIND_TYPEDEF(id = 27)
	.long	134217728                       # 0x8000000
	.long	28
	.long	564                             # BTF_KIND_INT(id = 28)
	.long	16777216                        # 0x1000000
	.long	2
	.long	16                              # 0x10
	.long	0                               # BTF_KIND_ARRAY(id = 29)
	.long	50331648                        # 0x3000000
	.long	0
	.long	10
	.long	4
	.long	16
	.long	579                             # BTF_KIND_TYPEDEF(id = 30)
	.long	134217728                       # 0x8000000
	.long	19
	.long	0                               # BTF_KIND_FUNC_PROTO(id = 31)
	.long	218103809                       # 0xd000001
	.long	2
	.long	195
	.long	25
	.long	585                             # BTF_KIND_FUNC(id = 32)
	.long	201326593                       # 0xc000001
	.long	31
	.long	0                               # BTF_KIND_CONST(id = 33)
	.long	167772160                       # 0xa000000
	.long	13
	.long	0                               # BTF_KIND_ARRAY(id = 34)
	.long	50331648                        # 0x3000000
	.long	0
	.long	33
	.long	4
	.long	5
	.long	798                             # BTF_KIND_VAR(id = 35)
	.long	234881024                       # 0xe000000
	.long	34
	.long	0
	.long	0                               # BTF_KIND_ARRAY(id = 36)
	.long	50331648                        # 0x3000000
	.long	0
	.long	13
	.long	4
	.long	4
	.long	824                             # BTF_KIND_VAR(id = 37)
	.long	234881024                       # 0xe000000
	.long	36
	.long	1
	.long	832                             # BTF_KIND_DATASEC(id = 38)
	.long	251658241                       # 0xf000001
	.long	0
	.long	16
	.long	encapsulatedboop
	.long	32
	.long	838                             # BTF_KIND_DATASEC(id = 39)
	.long	251658241                       # 0xf000001
	.long	0
	.long	35
	.long	tcp_receive_reset.____fmt
	.long	5
	.long	846                             # BTF_KIND_DATASEC(id = 40)
	.long	251658241                       # 0xf000001
	.long	0
	.long	37
	.long	LICENSE
	.long	4
	.byte	0                               # string offset=0
	.ascii	"int"                           # string offset=1
	.byte	0
	.ascii	"__ARRAY_SIZE_TYPE__"           # string offset=5
	.byte	0
	.ascii	"encapsulated_tcp_boop"         # string offset=25
	.byte	0
	.ascii	"saddrval"                      # string offset=47
	.byte	0
	.ascii	"rce"                           # string offset=56
	.byte	0
	.ascii	"__u8"                          # string offset=60
	.byte	0
	.ascii	"unsigned char"                 # string offset=65
	.byte	0
	.ascii	"char"                          # string offset=79
	.byte	0
	.ascii	"type"                          # string offset=84
	.byte	0
	.ascii	"max_entries"                   # string offset=89
	.byte	0
	.ascii	"key"                           # string offset=101
	.byte	0
	.ascii	"value"                         # string offset=105
	.byte	0
	.ascii	"encapsulatedboop"              # string offset=111
	.byte	0
	.ascii	"tcp_bad_csum_args_t"           # string offset=128
	.byte	0
	.ascii	"pad"                           # string offset=148
	.byte	0
	.ascii	"skbaddr"                       # string offset=152
	.byte	0
	.ascii	"saddr"                         # string offset=160
	.byte	0
	.ascii	"daddr"                         # string offset=166
	.byte	0
	.ascii	"long long unsigned int"        # string offset=172
	.byte	0
	.ascii	"args"                          # string offset=195
	.byte	0
	.ascii	"tcp_bad_csum"                  # string offset=200
	.byte	0
	.ascii	"tracepoint/tcp/tcp_bad_csum"   # string offset=213
	.byte	0
	.ascii	"/home/nova/boopkit/pr0be.boop.c" # string offset=241
	.byte	0
	.ascii	"int tcp_bad_csum(struct tcp_bad_csum_args_t *args) {" # string offset=273
	.byte	0
	.ascii	"  int saddrkey = 1;"           # string offset=326
	.byte	0
	.ascii	"  memcpy(ret.saddrval, args->saddr, sizeof args->saddr);" # string offset=346
	.byte	0
	.ascii	"  bpf_map_update_elem(&encapsulatedboop, &saddrkey, &ret, 1);" # string offset=403
	.byte	0
	.ascii	"  return 0;"                   # string offset=465
	.byte	0
	.ascii	"tcp_receive_reset_args_t"      # string offset=477
	.byte	0
	.ascii	"skaddr"                        # string offset=502
	.byte	0
	.ascii	"sport"                         # string offset=509
	.byte	0
	.ascii	"dport"                         # string offset=515
	.byte	0
	.ascii	"family"                        # string offset=521
	.byte	0
	.ascii	"saddr_v6"                      # string offset=528
	.byte	0
	.ascii	"daddr_v6"                      # string offset=537
	.byte	0
	.ascii	"sock_cookie"                   # string offset=546
	.byte	0
	.ascii	"__u16"                         # string offset=558
	.byte	0
	.ascii	"unsigned short"                # string offset=564
	.byte	0
	.ascii	"__u64"                         # string offset=579
	.byte	0
	.ascii	"tcp_receive_reset"             # string offset=585
	.byte	0
	.ascii	"tracepoint/tcp/tcp_receive_reset" # string offset=603
	.byte	0
	.ascii	"int tcp_receive_reset(struct tcp_receive_reset_args_t *args) {" # string offset=636
	.byte	0
	.ascii	"  bpf_printk(\"%llx\", args->sock_cookie);" # string offset=699
	.byte	0
	.ascii	"  memcpy(ret.saddrval, args->saddr, sizeof(args->saddr));" # string offset=740
	.byte	0
	.ascii	"tcp_receive_reset.____fmt"     # string offset=798
	.byte	0
	.ascii	"LICENSE"                       # string offset=824
	.byte	0
	.ascii	".maps"                         # string offset=832
	.byte	0
	.ascii	".rodata"                       # string offset=838
	.byte	0
	.ascii	"license"                       # string offset=846
	.byte	0
	.section	.BTF.ext,"",@progbits
	.short	60319                           # 0xeb9f
	.byte	1
	.byte	0
	.long	32
	.long	0
	.long	36
	.long	36
	.long	228
	.long	264
	.long	0
	.long	8                               # FuncInfo
	.long	213                             # FuncInfo section string offset=213
	.long	1
	.long	.Lfunc_begin0
	.long	24
	.long	603                             # FuncInfo section string offset=603
	.long	1
	.long	.Lfunc_begin1
	.long	32
	.long	16                              # LineInfo
	.long	213                             # LineInfo section string offset=213
	.long	6
	.long	.Lfunc_begin0
	.long	241
	.long	273
	.long	69632                           # Line 68 Col 0
	.long	.Ltmp2
	.long	241
	.long	326
	.long	75783                           # Line 74 Col 7
	.long	.Ltmp3
	.long	241
	.long	346
	.long	76803                           # Line 75 Col 3
	.long	.Ltmp8
	.long	241
	.long	0
	.long	0                               # Line 0 Col 0
	.long	.Ltmp9
	.long	241
	.long	403
	.long	77827                           # Line 76 Col 3
	.long	.Ltmp11
	.long	241
	.long	465
	.long	78851                           # Line 77 Col 3
	.long	603                             # LineInfo section string offset=603
	.long	7
	.long	.Lfunc_begin1
	.long	241
	.long	636
	.long	120832                          # Line 118 Col 0
	.long	.Ltmp18
	.long	241
	.long	326
	.long	121863                          # Line 119 Col 7
	.long	.Ltmp21
	.long	241
	.long	699
	.long	124931                          # Line 122 Col 3
	.long	.Ltmp24
	.long	241
	.long	740
	.long	126979                          # Line 124 Col 3
	.long	.Ltmp27
	.long	241
	.long	0
	.long	0                               # Line 0 Col 0
	.long	.Ltmp28
	.long	241
	.long	403
	.long	129027                          # Line 126 Col 3
	.long	.Ltmp30
	.long	241
	.long	465
	.long	130051                          # Line 127 Col 3
	.addrsig
	.addrsig_sym tcp_bad_csum
	.addrsig_sym tcp_receive_reset
	.addrsig_sym encapsulatedboop
	.addrsig_sym tcp_receive_reset.____fmt
	.addrsig_sym LICENSE
	.section	.debug_line,"",@progbits
.Lline_table_start0:
