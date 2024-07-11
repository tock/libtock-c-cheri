#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "console.h"
#include "tock.h"

// XXX Suppress unused parameter warnings for this file as the implementations
// are currently all just stubs
#pragma GCC diagnostic ignored "-Wunused-parameter"

// XXX Suppress missing prototype warnings for this file as the headers should
// be in newlib internals, but first stab at including things didn't quite work
// and the warnings are just noise
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wstrict-prototypes"

// XXX Also suppress attribute suggestions as these are stubs
#pragma GCC diagnostic ignored "-Wsuggest-attribute=const"

// ------------------------------
// LIBC SUPPORT STUBS
// ------------------------------

void* __dso_handle = 0;

int _unlink(const char *pathname) {
  return -1;
}

int _isatty(int fd)
{
  if (fd == 0) {
    return 1;
  }
  return 0;
}
int _open(const char* path, int flags, ...)
{
  return -1;
}
int _write(int fd, const void *buf, uint32_t count)
{
  putnstr((const char*)buf, count);
  return count;
}
int _close(int fd)
{
  return -1;
}
int _fstat(int fd, struct stat *st)
{
  st->st_mode = S_IFCHR;
  return 0;
}
int _lseek(int fd, uint32_t offset, int whence)
{
  return 0;
}
int _read(int fd, void *buf, uint32_t count)
{
  return 0;   // k_read(fd, (uint8_t*) buf, count);
}

__attribute__ ((noreturn));
void _exit(int __status)
{
  tock_exit(__status);
}
int _getpid(void)
{
  return 0;
}
int _kill(pid_t pid, int sig)
{
  return -1;
}

__attribute__((alias("_read")))
int read(int fd, void *buf, uint32_t count);
__attribute__((alias("_close")))
int close(int fd);
__attribute__((alias("_fstat")))
int fstat(int fd, struct stat *st);
__attribute__((alias("_isatty")))
int isatty(int fd);
__attribute__((alias("_lseek")))
int lseek(int fd, uint32_t offset, int whence);
__attribute__((alias("_write")))
int write(int fd, const void *buf, uint32_t count);
__attribute__((alias("_lseek")))
int lseek64(int fd, const void *buf, uint32_t count);

/*
   mallocr.c from newlib is not careful enough with using the pointer with the
   right provenance to create new allocations. It makes two calls to sbrk one
   to allocate an amount it desires and then a second to align to 0x1000.
   However, it will use the capability from the first to allocate space in the
   region authorised by the second. This hack preempts this behavior by always
   requesting 0x1000 aligned chunks and returning capabilities that authorise
   access to the next boundary.
   This is done in preference to fixing newlib as we will likely use a different
   libc soon. We can remove this once this change has happened.
 */
#ifdef __CHERI_PURE_CAPABILITY__
#define NEWLIB_MALLOC_HACK 1
#define NEWLIB_HACK_MASK ((size_t)0x1000 - (size_t)1)
#endif

caddr_t _sbrk(int incr)
{
#ifdef NEWLIB_MALLOC_HACK
  // Last break is where the effective break is, and will always authorise
  // up to the end of the next 0x1000 boundary. If it falls on such a boundary,
  // it authorises no more bytes.
  static caddr_t last_break = NULL;
  if (last_break == NULL) {
    // First call: find the current break...
    size_t current_break_addr = (size_t)memop(1, 0).data;
    // .. and align it up to a page
    last_break = (caddr_t)__builtin_cheri_address_set(
      memop(1, (-current_break_addr) & NEWLIB_HACK_MASK).data,
      current_break_addr);
  }
  // If the incr fits within the same page as the last break, we can just
  // return it:
  if (incr <= (ssize_t)((-(size_t)last_break) & NEWLIB_HACK_MASK)) {
    caddr_t result = last_break;
    last_break += incr;
    return result;
  }
  // Otherwise, round up incr to ensure 0x1000 alignent
  int original_incr = incr;
  incr = (incr + NEWLIB_HACK_MASK) & ~NEWLIB_HACK_MASK;
#endif

  memop_return_t ret;
  ret = memop(1, incr);
  if (ret.status != TOCK_STATUSCODE_SUCCESS) {
    errno = ENOMEM;
    return (caddr_t) -1;
  }

#if __has_feature(capabilities)
#ifndef __CHERI_PURE_CAPABILITY__
  // In CHERI hybrid, we need to set DDC to authorise any accesses to the new region
  __asm("cspecialw ddc, %[new_ddc] " :: [new_ddc] "C" (ret.data) : "memory");
  // For CHERI purecap, caddr_t will be a capability and authorise the new
  // region. As long as it gets provenance correct, everything should just
  // work.
#endif
#endif

#ifdef NEWLIB_MALLOC_HACK
  // Result is new authorising capability but with the address of the last break
  caddr_t result = (caddr_t)__builtin_cheri_address_set(ret.data, (size_t)last_break);
  // And store last_break
  last_break = result + original_incr;
  return result;
#endif

  return ccast(caddr_t, ret.data);
}

__attribute__((alias("_sbrk")))
caddr_t sbrk(int incr);
