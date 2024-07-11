#include <string.h>
#include <tock.h>

#if defined(STACK_SIZE)
#warning Attempt to compile libtock with a fixed STACK_SIZE.
#warning
#warning Instead, STACK_SIZE should be a variable that is linked in,
#warning usually at compile time via something like this:
#warning   `gcc ... -Xlinker --defsym=STACK_SIZE=2048`
#warning
#warning This allows applications to set their own STACK_SIZE.
#error Fixed STACK_SIZE.
#endif

#ifdef __CHERI_PURE_CAPABILITY__
// Setting this will ensure caprelocs take into account the fact that the process has been relocated
#define CHERI_INIT_GLOBALS_USE_OFFSET
#include "cheri_init_globals.h"
#endif

// The program has been loaded contiguously and does not need data relocating
#define CONTIGUOUS 1

extern int main(void);

// Allow _start to go undeclared
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

// The structure populated by the linker script at the very beginning of the
// text segment. It represents sizes and offsets from the text segment of
// sections that need some sort of loading and/or relocation.
struct hdr {
  uint32_t stack_location;
  uint32_t stack_size;
  uint32_t bss_start;
  uint32_t bss_size;
  uint32_t rel_start;
  uint32_t rel_size;
};

#define OFF_STACK_LOC "0x00"
#define OFF_STACK_SZ  "0x04"
#define OFF_BSS_START "0x08"
#define OFF_BSS_SIZE  "0x0C"
#define OFF_REL_START "0x10"
#define OFF_REL_SIZE  "0x14"

// The structure of the relative data section. This structure comes from the
// compiler.
struct reldata {
  // Number of relative addresses.
  uint32_t len;
  // Array of offsets of the address to be updated relative to the start of the
  // application's memory region. Each address at these offsets needs to be
  // adjusted to be a fixed address relative to the start of the app's actual
  // flash or RAM start address.
  uint32_t data[];
};

__attribute__ ((section(".start"), used))
__attribute__ ((weak))
__attribute__ ((naked))
__attribute__ ((noreturn))
void _start(void* app_start __attribute__((unused)),
            void* mem_start __attribute__((unused)),
            void* memory_len __attribute__((unused)),
            void* app_heap_break __attribute__((unused))) {
#if defined(__thumb__)
  // Assembly written to adhere to any modern thumb arch

  // Allocate stack and data. `brk` to stack_size + got_size + data_size +
  // bss_size from start of memory. Also make sure that the stack starts on an
  // 8 byte boundary per section 5.2.1.2 here:
  // http://infocenter.arm.com/help/topic/com.arm.doc.ihi0042f/IHI0042F_aapcs.pdf

  __asm__ volatile (
    // entry:
    //    r0 = hdr
    //    r1 = mem_start
    //    r2 =
    //    r3 = initial_brk
    // Compute the stack top.
    //
    // struct hdr* myhdr = (struct hdr*) app_start;
    // uint32_t stacktop = mem_start + myhdr->stack_size + myhdr->stack_location
    "ldr  r4, [r0, " OFF_STACK_SZ "]\n"   // r4 = myhdr->stack_size
    "ldr  r5, [r0, " OFF_STACK_LOC "]\n"  // r5 = myhdr->stack_location
    "add  r5, r5, r1\n"
    "add  r4, r4, r5\n"                   // r4 = stacktop
    //
    // Compute the app data size and where initial app brk should go.
    // This includes the GOT, data, and BSS sections. However, we can't be sure
    // the linker puts them back-to-back, but we do assume that BSS is last
    // (i.e. myhdr->got_start < myhdr->bss_start && myhdr->data_start <
    // myhdr->bss_start). With all of that true, then the size is equivalent
    // to the end of the BSS section.
    //
    // uint32_t app_brk = mem_start + myhdr->bss_start + myhdr->bss_size;
    "ldr  r5, [r0, " OFF_BSS_START "]\n"      // r5 = myhdr->bss_start
    "ldr  r6, [r0, " OFF_BSS_SIZE "]\n"      // v3 = myhdr->bss_size
    "add  r5, r5, r1\n"         // r5 = bss_start + mem_start
    "add  r5, r5, r6\n"         // r5 = mem_start + bss_start + bss_size = app_brk
    //
    // Move registers we need to keep over to callee-saved locations
    "movs r6, r0\n"             // r6 = app_start
    "movs r7, r1\n"             // r7 = mem_start

    "mov r1, r5\n"              // r1 = app_brk
#if CONTIGUOUS
    // For the contiguous load, we overlap BSS and relocations so they can
    // be reclaimed. If our relocations are large, we need to move the app
    // break to be past them

    "ldr  r0, [r6, " OFF_REL_START "]\n"
    "ldr  r2, [r6, " OFF_REL_SIZE "]\n"
    "add  r0, r0, r7\n" // r0 = reloc_start
    "add  r2, r2, r0\n" // r2 = reloc_end

    "cmp   r2, r1 \n"
    "it    ge     \n"
    "movge r1, r2\n"      // r1 = reloc_end >= app_brk ? reloc_end : app_brk

#else
    // Now we may want to move the stack pointer. If the kernel set the
    // `app_heap_break` larger than we need (and we are going to call `brk()`
    // to reduce it) then our stack pointer will fit and we can move it now.
    // Otherwise after the first syscall (the memop to set the brk), the return
    // will use a stack that is outside of the process accessible memory.
    //
    "cmp r5, r3\n"              // Compare `app_heap_break` with new brk.
    "bgt skip_set_sp\n"         // If our current `app_heap_break` is larger
                                // then we need to move the stack pointer
                                // before we call the `brk` syscall.
    "mov  sp, r4\n"             // Update the stack pointer.
    //
    "skip_set_sp:\n"            // Back to regularly scheduled programming.
#endif

    //
    // Call `brk` to set to requested memory
    //
    // memop(0, max(app_brk, reloc_end));
    "movs r0, #0\n"
    // r1 setup earlier
    "svc 5\n"                   // memop
    //
    // Setup initial stack pointer for normal execution. If we did this before
    // then this is redundant and just a no-op. If not then no harm in
    // re-setting it.
    "mov  sp, r4\n"
    //
    // Debug support, tell the kernel the stack location
    //
    // memop(10, stacktop);
    "movs r0, #10\n"
    "movs r1, r4\n"
    "svc 5\n"                   // memop
    //
    // Debug support, tell the kernel the heap location
    //
    // memop(11, app_brk);
    "movs r0, #11\n"
    "movs r1, r5\n"
    "svc 5\n"                   // memop

#if CONTIGUOUS
    // Process relocations. These have all been put in one segment for us and should
    // be either Elf64_Rel or Elf32_Rel. Don't process these in C, they overlap the stack

    "ldr  r0, [r6, " OFF_REL_START "]\n"
    "ldr  r1, [r6, " OFF_REL_SIZE "]\n"
    "add  r0, r0, r7\n" // r0 = reloc_start
    "add  r1, r1, r0\n" // r1 = reloc_end

    "mov  r2, #0x17\n" // r2 = R_ARM_RELATIVE.
    "b    loop_footer\n"

    "reloc_loop:\n"
    "ldr   r3, [r0, %[ARCH_BYTES]]\n"    // r3 = info
    "ldr   r4, [r0, 0]\n"  // r4 = offset

    "cmp  r3, r2\n"               // check relocation of right type
    "bne  panic\n"

    "add  r4, r4, r7\n"           // r4 = relocation location
    "ldr   r3, [r4]\n"             // r3 = addend
    "add  r3, r3, r7\n"           // r3 = addend + mem_start
    "str   r3, [r4]\n"             // store new value

    "add  r0, r0, %[RELOC_SZ]\n" // increment reloc_start

    "loop_footer:\n"
    "cmp  r0, r1 \n"
    "bne  reloc_loop\n"

    // And if the break was set too high (e.g. reloc_end > app_brk),
    // move it back
    "cmp r1, r5\n"
    "ble skip_second_brk\n"
    // memop(0, app_brk);
    "mov r0, #0\n"
    "mov r1, r5\n"
    "svc 5\n"                   // memop
    "skip_second_brk:\n"

#else // !CONTIGUOUS
    //
    // Set the special PIC register r9. This has to be set to the address of the
    // beginning of the GOT section. The PIC code uses this as a reference point
    // to enable the RAM section of the app to be at any address.
    "ldr  r0, [r6, #4]\n"       // r0 = myhdr->got_start
    "add  r0, r0, r7\n"         // r0 = myhdr->got_start + mem_start
    "mov  r9, r0\n"             // r9 = r0
#endif
    //
    // Call into the rest of startup.
    // This should never return, if it does, trigger a breakpoint (which will
    // promote to a HardFault in the absence of a debugger)
    "movs r0, r6\n"             // first arg is app_start
    "movs r1, r7\n"             // second arg is mem_start
#if !CONTIGUOUS
    "bl _c_start_pic\n"
#else
    "bl _c_start_noflash\n"
#endif
    "panic: \n"
    "bkpt #255\n"
    :
    : [ARCH_BYTES] "n" (sizeof(size_t)),
    [RELOC_SZ] "n" (sizeof(size_t) * 2)
    );

#elif defined(__riscv)

#ifdef __CHERI_PURE_CAPABILITY__
#define PRFX "c"
#define ZREG "cnull"
#else
#define PRFX ""
#define ZREG "zero"
#endif

  __asm__ volatile (
    // Compute the stack top.
    //
    // struct hdr* myhdr = (struct hdr*) app_start;
    // uint32_t stacktop = mem_start + myhdr->stack_size + myhdr->stack_location

    PRFX "lw   t0, " OFF_STACK_SZ "("PRFX "a0)\n"         // t0 = myhdr->stack_size
    PRFX "lw   t1, " OFF_STACK_LOC "("PRFX "a0)\n"         // t1 = myhdr->stack_location
    "add  t0, t0, a1\n"
    "add  t0, t0, t1\n"

    //
    // Compute the app data size and where initial app brk should go.
    // This includes the GOT, data, and BSS sections. However, we can't be sure
    // the linker puts them back-to-back, but we do assume that BSS is last
    // (i.e. myhdr->got_start < myhdr->bss_start && myhdr->data_start <
    // myhdr->bss_start). With all of that true, then the size is equivalent
    // to the end of the BSS section.
    //
    // uint32_t app_brk = mem_start + myhdr->bss_start + myhdr->bss_size;
    PRFX "lw   t1, " OFF_BSS_START "("PRFX "a0)\n"         // t1 = myhdr->bss_start
    PRFX "lw   t2, " OFF_BSS_SIZE "("PRFX "a0)\n"         // t2 = myhdr->bss_size
    "add  t1, t1, t2\n"         // t1 = bss_start + bss_size
    "add  t1, t1, a1\n"         // t1 = mem_start + bss_start + bss_size = app_brk
    //
    // Move arguments we need to keep over to callee-saved locations.
    "mv   s0, a0\n"             // s0 = void* app_start
    "mv   s1, t0\n"             // s1 = stack_top
    "mv   s2, a1\n"             // s2 = mem_start

    //
    // Setup initial stack pointer for normal execution
    "mv   sp, s1\n"             // sp = stacktop

    // We have overlapped the our BSS/HEAP with our relocations. If our
    // relocations are larger, then we need to move the break to include
    // relocations. Once we have processed relocations, we will move them
    // back.

    PRFX "lw  a0, " OFF_REL_START "("PRFX "s0)\n"
    PRFX "lw  a1, " OFF_REL_SIZE "(" PRFX "s0)\n"
    "add a0, a0, s2          // a0 = reloc_start\n"
    "add s3, a0, a1          // a1 = reloc_end\n"

    "bgt  s3, t1, relocs_larger_than_bss\n"
    "mv   s3, t1\n"
    "relocs_larger_than_bss:\n"

    // s3 is now the larger of the two

    //
    // Now we may want to move the stack pointer. If the kernel set the
    // `app_heap_break` larger than we need (and we are going to call `brk()`
    // to reduce it) then our stack pointer will fit and we can move it now.
    // Otherwise after the first syscall (the memop to set the brk), the return
    // will use a stack that is outside of the process accessible memory.
    //
    "ble s3, a3, skip_brk\n"    // Compare `app_heap_break` with new brk.
                                // Skip setting if we don't need

    // Call `brk` to set to requested memory
    // memop(0, max(end_of_bss,end_of_relocs));
    "li  a4, 5\n"               // a4 = 5   // memop syscall
    "li  a0, 0\n"               // a0 = 0
    "mv  a1, s3\n"              // a1 = app_brk
    "ecall\n"                   // memop
#if __has_feature(capabilities)
    // On CHERI, brk returns a capability to authorise the new break
    "cspecialw ddc, ca1\n"
#endif
    "skip_brk:\n"

    //
    // Debug support, tell the kernel the stack location
    //
    // memop(10, stacktop);
    "li  a4, 5\n"               // a4 = 5   // memop syscall
    "li  a0, 10\n"              // a0 = 10
    "mv  a1, s1\n"              // a1 = stacktop
    "ecall\n"                   // memop
    //
    // Debug support, tell the kernel the heap location
    //
    // memop(11, app_brk);
    "li  a4, 5\n"               // a4 = 5   // memop syscall
    "li  a0, 11\n"              // a0 = 11
    "mv  a1, t1\n"              // a1 = app_brk
    "ecall\n"                   // memop

    // Process relocations. These have all been put in one segment for us and should
    // be either Elf64_Rel or Elf32_Rel. Don't process these in C, they overlap the stack

    ".set ARCH_BYTES, %[ARCH_BYTES]\n"

    /* Store word on 32-bit, or double word on 64-bit */
    ".macro sx val, offset, base\n"
    ".if ARCH_BYTES == 4\n"
    PRFX "sw \\val, \\offset("PRFX "\\base)\n"
    ".else\n"
    PRFX "sd \\val, \\offset("PRFX "\\base)\n"
    ".endif\n"
    ".endmacro\n"

    /* Load word on 32-bit, or double word on 64-bit */
    ".macro lx val, offset, base\n"
    ".if ARCH_BYTES == 4\n"
    PRFX "lw \\val, \\offset("PRFX "\\base)\n"
    ".else\n"
    PRFX "ld \\val, \\offset("PRFX "\\base)\n"
    ".endif\n"
    ".endmacro\n"

    ".set r_offset, 0\n"
    ".set r_info, ARCH_BYTES\n"
    ".set ent_size, (ARCH_BYTES*2)\n"

    PRFX "lw  a0, " OFF_REL_START "("PRFX "s0)\n"
    PRFX "lw  a1, " OFF_REL_SIZE "(" PRFX "s0)\n"
    "add a0, a0, s2          // a0 = reloc_start\n"
    "add a1, a0, a1          // a1 = reloc_end\n"

    "li  t0, 3               // t0 = R_RISCV_RELATIVE. The only relocation\n"
    "// we should see.\n"
    "beq a0, a1, skip_loop\n"
    "reloc_loop:\n"
    // Relocations are relative to a symbol, the table for which we have stripped.
    // However, all the remaining relocations should use the special "0" symbol,
    // and encode the values required in the addend.
    "lx  a2, r_info, a0   // a2 = info\n"
    "lx  a3, r_offset, a0 // a3 = offset\n"
    "bne a2, t0, panic   // Only processing this relocation.\n"
    "add a3, a3, s2      // a3 = offset + reloc_offset\n"
    "lx   a4, 0, a3       // a4 = addend\n"
    "add a4, a4, s2      // a4 = addend + reloc_offset\n"
    "// Store new value\n"
    "sx  a4, 0, a3\n"
    "skip_relocate:\n"
    "add a0, a0, ent_size\n"
    "loop_footer:\n"
    "bne a0, a1, reloc_loop\n"
    "skip_loop:\n"

    // Now relocations have been processed. If we moved our break too much, move it back.
    // t1 still has the end of bss. a1 has the end of the relocs.
    "bgt t1, a1, skip_second_brk\n"
    "li  a4, 5\n"               // a4 = 5   // memop syscall
    "li  a0, 0\n"               // a0 = 0
    "mv  a1, t1\n"              // a1 = app_brk
    "ecall\n"                   // memop
    "skip_second_brk:\n"

    // Call into the rest of startup. This should never return.
    "mv   a0, s0\n"             // first arg is app_start
    "mv   s0, sp\n"             // Set the frame pointer to sp.
    "mv   a1, s2\n"             // second arg is mem_start

#ifdef __CHERI_PURE_CAPABILITY__
    // By convention we are starting in non-cap mode and this startup code was run with integers. Change into cap mode:
    // auipcc is actually auipc because we are not in cap mode
    "1: auipcc      ct0, %%pcrel_hi(cap_mode_tramp) \n"
    "cincoffset     ct0, ct0, %%pcrel_lo(1b)        \n"
    "cspecialr      ct1, pcc                        \n"
    "csetaddr       ct1, ct1, t0                    \n"
    "li             t0,  1                          \n"
    "csetflags      ct1, ct1, t0                    \n"
    "jr.cap         ct1                             \n"
    "cap_mode_tramp:                                \n"
    // Now we are in cap-mode instructions will have the encoding we expect
    // Rederive app_start/mem_start/sp from ddc
    "cspecialr      ct0, ddc     \n"
    "csetaddr       ca0, ct0, a0 \n"   // app_start
    "csetaddr       ca1, ct0, a1 \n"   // mem_start
    "csetaddr       csp, ct0, sp \n"   // sp
    // Also bounds SP:
    "clw            t0, " OFF_STACK_SZ "(ca0)  \n"
    "neg            t1, t0\n"
    "cincoffset     csp, csp, t1 \n"
    "csetbounds     csp, csp, t0 \n"
    "cincoffset     csp, csp, t0 \n"
#endif

    // Call into the rest of startup. This should never return.
    PRFX "jal  _c_start_noflash         \n"

    "panic:\n"
    PRFX "lw        t0, 0(" ZREG ")\n"
    :
    : [align] "n" (sizeof(void*) - 1),
    [ARCH_BYTES] "n" (sizeof(size_t))
    );

#else
#error Missing initial stack setup trampoline for current arch.
#endif
}


#if !CONTIGUOUS

// C startup routine that configures memory for the process. This also handles
// PIC fixups that are required for the application.
//
// Arguments:
// - `app_start`: The address of where the app binary starts in flash. This does
//   not include the TBF header or any padding before the app.
// - `mem_start`: The starting address of the memory region assigned to this
//   app.
__attribute__((noreturn))
void _c_start_pic(uint32_t app_start, uint32_t mem_start) {
  struct hdr* myhdr = (struct hdr*)app_start;

  // Fix up the Global Offset Table (GOT).

  // Get the address in memory of where the table should go.
  uint32_t* got_start = (uint32_t*)(myhdr->got_start + mem_start);
  // Get the address in flash of where the table currently is.
  uint32_t* got_sym_start = (uint32_t*)(myhdr->got_sym_start + app_start);
  // Iterate all entries in the table and correct the addresses.
  for (uint32_t i = 0; i < (myhdr->got_size / (uint32_t)sizeof(uint32_t)); i++) {
    // Use the sentinel here. If the most significant bit is 0, then we know
    // this offset is pointing to an address in memory. If the MSB is 1, then
    // the offset refers to a value in flash.
    if ((got_sym_start[i] & 0x80000000) == 0) {
      // This is an address for something in memory, and we need to correct the
      // address now that we know where this app is actually running in memory.
      // This equation is really:
      //
      //     got_entry = (got_stored_entry - original_RAM_start_address) + actual_RAM_start_address
      //
      // However, we compiled the app where `original_RAM_start_address` is 0x0,
      // so we can omit that.
      got_start[i] = got_sym_start[i] + mem_start;
    } else {
      // Otherwise, this address refers to something in flash. Now that we know
      // where the app has actually been loaded, we can reference from the
      // actual `app_start` address. We also have to remove our fake flash
      // address sentinel (by ORing with 0x80000000).
      got_start[i] = (got_sym_start[i] ^ 0x80000000) + app_start;
    }
  }

  // Load the data section from flash into RAM. We use the offsets from our
  // crt0 header so we know where this starts and where it should go.
  void* data_start     = (void*)(myhdr->data_start + mem_start);
  void* data_sym_start = (void*)(myhdr->data_sym_start + app_start);
  memcpy(data_start, data_sym_start, myhdr->data_size);

  // Zero BSS segment. Again, we know where this should be in the process RAM
  // based on the crt0 header.
  char* bss_start = (char*)(myhdr->bss_start + mem_start);
  memset(bss_start, 0, myhdr->bss_size);

  // Do relative data address fixups. We know these entries are stored at the end
  // of flash and can be located using the crt0 header.
  //
  // The data structure used for these is `struct reldata`, where a 32 bit
  // length field is followed by that many entries. We iterate each entry and
  // correct addresses.
  struct reldata* rd = (struct reldata*)(myhdr->reldata_start + (uint32_t)app_start);
  for (uint32_t i = 0; i < (rd->len / (int)sizeof(uint32_t)); i += 2) {
    // The entries are offsets from the beginning of the app's memory region.
    // First, we get a pointer to the location of the address we need to fix.
    uint32_t* target = (uint32_t*)(rd->data[i] + mem_start);
    if ((*target & 0x80000000) == 0) {
      // Again, we use our sentinel. If the address at that location has a MSB
      // of 0, then we know this is an address in RAM. We need to fix the
      // address by including the offset where the app actual ended up in
      // memory. This is a simple addition since the app was compiled with a
      // memory address of zero.
      *target += mem_start;
    } else {
      // When the MSB is 1, the address is in flash. We clear our sentinel, and
      // then make the address an offset from the start of where the app is
      // located in flash.
      *target = (*target ^ 0x80000000) + app_start;
    }
  }

  main();
  while (1) {
    yield();
  }
}

#endif

// C startup routine for apps compiled with fixed addresses (i.e. no PIC).
//
// Arguments:
// - `app_start`: The address of where the app binary starts in flash. This does
//   not include the TBF header or any padding before the app.
//   on CHERI hybrid, app_start may not be covered by DDC so is an explicit cap.
// - `mem_start`: The starting address of the memory region assigned to this
//   app.
__attribute__((noreturn))
void _c_start_noflash(uintptr_t app_start, uintptr_t mem_start) {
  struct hdr* myhdr = (struct hdr*)app_start;

#if !CONTIGUOUS
  // Copy over the Global Offset Table (GOT). The GOT seems to still get created
  // and used in some cases, even though nothing is being relocated and the
  // addresses are static. So, all we need to do is copy the GOT entries from
  // flash to RAM, without doing any address changes. Of course, if the GOT
  // length is 0 this is a no-op.
  void* got_start     = (void*)(myhdr->got_start + mem_start);
  void* got_sym_start = (void*)(myhdr->got_sym_start + app_start);
  memcpy(got_start, got_sym_start, myhdr->got_size);

  // Load the data section from flash into RAM. We use the offsets from our
  // crt0 header so we know where this starts and where it should go.
  void* data_start     = (void*)(myhdr->data_start + mem_start);
  void* data_sym_start = (void*)(myhdr->data_sym_start + app_start);
  memcpy(data_start, data_sym_start, myhdr->data_size);
#endif

  // We always do the clear because we may have used BSS for init
  char* bss_start = (char*)(myhdr->bss_start + mem_start);
  memset(bss_start, 0, myhdr->bss_size);

#ifdef __CHERI_PURE_CAPABILITY__
  cheri_init_globals();
  // We no longer need the default capability:
  __asm(" cmove          ct0, cnull \n"
        " cspecialw      ddc, ct0   \n" ::: "ct0");
#endif

  main();
  while (1) {
    yield();
  }
}
