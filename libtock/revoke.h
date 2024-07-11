#ifndef LIBTOCK_REVOKE_H_
#define LIBTOCK_REVOKE_H_

#include "tock.h"

typedef uint32_t epoch_t;

// The type used the bitmap (optimised for fast set/clear). The kernel will
// accept byte aligned, but we insist on greater alignment

typedef volatile size_t bitmap_t;  // We could use uintptr_t if we had a good way to mask them
#define BITMAP_T_BITS (sizeof(bitmap_t) * 8)
#define BITMAP_T_BITS_LOG_2 __builtin_ctz(BITMAP_T_BITS)
#define BITMAP_T_ONES ((bitmap_t)(~0))

// Revocation granule
#define GRANULE_POW_2 4
#define GRANULE_SIZE (1 << GRANULE_POW_2)
#define GRANULE_MASK (GRANULE_SIZE - 1)

#define CHERI_DRIVER_NUM 0x10003
#define COMMAND_NUM_SET_BASE 1
#define COMMAND_NUM_DO_SWEEP 2

/* Register for revocation. Map should a bitmap covering GRANULE_SIZE granules
 * starting at base. Epoch_ctr will be incremented on each sweep. */
int revoke_register(bitmap_t* map, size_t map_elements, size_t base, volatile epoch_t* epoch_ctr);

/* Wait for (any non-zero number) of epochs to elapse */
int revoke_wait_for_next_epoch(void);

/* Paint the revocation bitmap from address [base, top) */
int set_revoke_range(size_t base, size_t top, int should_revoke);

#endif //LIBTOCK_REVOKE_H_