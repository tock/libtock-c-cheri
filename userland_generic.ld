/* Userland Generic Layout
 *
 * This linker script is designed for Tock apps where the end microcontroller
 * is not known. Therefore, this script over provisions space on some platforms.
 */

/* NOTE: this is only really a confidence check for the linker script, these are
 * are mostly placeholder values. Set to 2MB for now. */
PROG_LENGTH = 0x00200000;
RAM_LENGTH  = 0x00200000;

ENTRY(_start)

/* Note: On platforms where apps are position-independent and relocatable, the
 * FLASH address here acts as a sentinel value for relocation fixup routines.
 * The application loader will select the actual location in flash where the app
 * is placed. On platforms where apps are compiled for fixed addresses, these
 * addresses will be changed automatically before the linking step.
 *
 */

MEMORY {
    FLASH (rx) : ORIGIN = 0x80000000, LENGTH = PROG_LENGTH
    SRAM (RWX) : ORIGIN = 0x00000000, LENGTH = RAM_LENGTH
}

/* We could specify this per target. But it does not really matter. 16
 * is the largest size we need */
WORD_ALIGN = 16;

/* TODO: This needs doing properly. */
/* I just found APP_HEAP_SIZE in the makefiles. Why don't I see it here? */
/* I will check nothing else is broken, and then just use that. */
HEAP_SIZE = 0x4000;

SECTIONS {

    /* Need to reserve room for the stack in the linker file. This makes the
     * _got addresses used by the compiler match what they will be when the
     * app is loaded into memory. This is not necessary for full PIC supported
     * platforms (like Cortex-M), but is needed when an app is compiled for a
     * fixed address.
     *
     * NOLOAD will ensure that filsize is 0. Not doing this causes problems
     * as some linkers will pad the file and then the elf2tab tool gets
     * very confused because of the way tock abuses physical and virtual
     * address in the elf format in order to achieve relocation.
     *
     * Putting this first ensures that stack overflows are caught.
     */
    .stack (NOLOAD):
    {
        /* Be conservative about our alignment for the stack. Different
         * architectures require different values (8 for ARM, 16 for RISC-V),
         * so we choose the largest value. In practice, this likely will not
         * matter since the start of SRAM is unlikely to be at a very peculiar
         * address.
         */
        . = ALIGN(16);
        _stack = .;
        . = _stack + STACK_SIZE;
        . = ALIGN(16);
    } > SRAM

    /* Section for just the app crt0 header.
     * This must be at sram_orgin to be found by crt0.
     */
    .crt0_header :
    {
        /* elf2tab requires that the `_SRAM_ORIGIN` symbol be present to
		 * mark the first address in the SRAM memory. Since ELF files do
		 * not really need to specify this address as they only care about
		 * loading into flash, we need to manually mark this address for
		 * elf2tab. elf2tab will use it to add a fixed address header in the
		 * TBF header if needed.
		 */
	    _sram_origin = .;
        /**
         * Populate the header expected by `crt0`:
         *
         *  struct hdr {
         *    uint32_t stack_location;
         *    uint32_t stack_size;
         *    uint32_t bss_start;
         *    uint32_t bss_size;
         *    uint32_t rel_start;
         *    uint32_t rel_size;
         *  };
         */
        LONG(_stack - ORIGIN(SRAM));
        LONG(STACK_SIZE);
        LONG(_bss - ORIGIN(SRAM));
        LONG(SIZEOF(.bss));
        LONG(_data_rel_start - ORIGIN(SRAM));
        LONG(_data_rel_fake_end - _data_rel_fake_start);
    } >SRAM AT > FLASH =0xFF

    /* App state section. Used for persistent app data.
     * We put this first so that if the app code changes but the persistent
     * data doesn't, the app_state can be preserved.
     */
    .wfr.app_state :
    {
        KEEP (*(.app_state))
        . = ALIGN(WORD_ALIGN); /* Make sure we're word-aligned here */
    } > SRAM AT > FLASH =0xFF

    /* Text section, Code! */
    .text :
    {
        . = ALIGN(WORD_ALIGN);
        _text = .;
        KEEP (*(.start))
        *(.text*)
        *(.rodata*)
        *(.srodata*) /* for RISC-V */
        KEEP (*(.syscalls))
        _etext = .;
        *(.ARM.extab*)
        . = ALIGN(WORD_ALIGN);
        // TODO: reclaim these like we did the other ELF relocations
        __start___cap_relocs = .;
        *(__cap_relocs*) /* For CHERI */
        __stop___cap_relocs = .;
        . = ALIGN(WORD_ALIGN); /* Make sure we're word-aligned here */
    } > SRAM AT > FLASH =0xFF

    /* Global Offset Table */
    .got :
    {
        . = ALIGN(WORD_ALIGN); /* Make sure we're word-aligned here */
        _got = .;
        *(.got*)
        *(.got.plt*)
        . = ALIGN(WORD_ALIGN);
    } > SRAM AT > FLASH

    /* Data section, static initialized variables
     *  Note: This is placed in Flash after the text section, but needs to be
     *  moved to SRAM at runtime
     */
    .data :
    {
        . = ALIGN(WORD_ALIGN); /* Make sure we're word-aligned here */
        _data = .;
        KEEP(*(.data*))
        /* Include the "small data" in the data section. Otherwise it will be
         * dropped when the TBF is created.
         */
        KEEP(*(.sdata*))
        *(.captable*) /* For CHERI. Weirdly, not BSS */
        /* Mis-align for the purposes of rel */
        . += (4 - (. % WORD_ALIGN)) % WORD_ALIGN;
    } > SRAM AT > FLASH

    /* End of flash. */
    .endflash :
    {
    } > FLASH

    /* Working around is ELF2TAB becoming tiresome at this point. How it
     * currently works:
     *    ELF2 incorrectly uses section headers, not segment headers, to load
     *    data in the resulting binary. Putting the rel in a PT_LOAD segment
     *    therefore has no effect.
     *    ON THE OTHER HAND, ELF2TAB will find any section named exactly "rel.X"
     *    (where X is the name of any other section that has both W and R flags)
     *    and (ignoring where they request being placed) will chuck that section
     *    out at the end of the binary, preceded by a 4-byte length field.
     * This will result in the .rel.X section always being placed after
     * "endofflash". We have to produce the section, but not increment
     * the cursor because we actually want it to overlap where the stack
     * and BSS would be. Overlapping the STACK / BSS allows us to reclaim
     * ram once relocations have been processed. This works because no
     * relocations target the stack/BSS (yet another reason to use rel, not
     * rela).
     */

    _data_rel_start = . + 4;
    /* Must be called .rel.data */
    .rel.data : {
        /* Dynamic relocations. We should not get any rel.plt. Hopefully. */
        _data_rel_fake_start = .;
        KEEP(*(.rel.dyn*));
        _data_rel_fake_end = .;
    } > SRAM = 0xaa
    . = _data_rel_start;


    /* BSS section, static uninitialized variables
     * Note: Also "placing" this section in Flash (with 0 size file size) will help merge
     * the program headers.
     */
    .bss (NOLOAD):
    {
        . = ALIGN(WORD_ALIGN); /* Make sure we're word-aligned here */
        _bss = .;
        KEEP(*(.bss*))
        KEEP(*(.sbss*)) /* for RISC-V */
        *(COMMON)
        . = ALIGN(WORD_ALIGN);
    } > SRAM

    .heap (NOLOAD):
    {
        . += HEAP_SIZE;
    } > SRAM

    /* ARM Exception support
     *
     * This contains compiler-generated support for unwinding the stack,
     * consisting of key-value pairs of function addresses and information on
     * how to unwind stack frames.
     * https://wiki-archive.linaro.org/KenWerner/Sandbox/libunwind
     * (See also https://github.com/tock/libtock-c/issues/48)
     *
     *
     * .ARM.exidx is sorted, so has to go in its own output section.
     *
     * __NOTE__: It's at the end because we currently don't actually serialize
     * it to the binary in elf2tab. If it was before the RAM sections, it would
     * through off our calculations of the header.
     */
    /* This seems to generate an out of range relocation with contiguous loading
     * Almost certainly due to the fake locations for flash and RAM being too
     * far apart.
    PROVIDE_HIDDEN (__exidx_start = .);
    .ARM.exidx :
    {
      /* (C++) Index entries for section unwinding *
      *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > FLASH
    PROVIDE_HIDDEN (__exidx_end = .);
    */
    /* Sections we do not need. */
    /DISCARD/ :
    {
      *(.eh_frame .gnu.hash .dynsym .dynstr .hash .dynamic)
    }
}

ASSERT(_got <= _bss, "
The GOT section must be before the BSS section for crt0 setup to be correct.");
ASSERT(_data <= _bss, "
The data section must be before the BSS section for crt0 setup to be correct.");
