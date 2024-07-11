#include "revoke.h"

// Globally registered map
bitmap_t* global_map;
size_t global_map_elements;
// Shadows a space starting at
size_t global_at_base;

volatile epoch_t* global_epoch_ctr;

/* Register for revocation. Map should be a bitmap covering GRANULE_SIZE granules
 * starting at base. Epoch_ctr will be incremented on each sweep. */
int revoke_register(bitmap_t* map, size_t map_elements, size_t base, volatile epoch_t* epoch_ctr) {
  // Pre-align base so the kernel will accept it
  base = base & ~((1 << (GRANULE_POW_2 + 3)) - 1);

  // Allow the map
  allow_ro_return_t result = allow_readonly(CHERI_DRIVER_NUM,
                                            0,
                                            (void*)map,
                                            map_elements * sizeof(bitmap_t));
  int ret = tock_allow_ro_return_to_returncode(result);
  if (ret < 0)
    return ret;

  // Allow the ctr
  allow_rw_return_t result_rw = allow_readwrite(CHERI_DRIVER_NUM,
                                                0,
                                                (void*)epoch_ctr,
                                                sizeof(epoch_t));
  ret = tock_allow_rw_return_to_returncode(result_rw);
  if (ret < 0)
    return ret;

  // Then register it
  syscall_return_t res = command(CHERI_DRIVER_NUM, COMMAND_NUM_SET_BASE, base, 0);
  ret = tock_command_return_novalue_to_returncode(res);

  if (ret < 0)
    return ret;

  // Set global values (we get the epoch ctr in individual wait calls)
  global_map = map;
  global_at_base      = base;
  global_map_elements = map_elements;
  global_epoch_ctr    = epoch_ctr;
  return ret;
}

static inline void on_epoch(__unused size_t r1, __unused size_t r2, __unused size_t r3,
                            __unused void* data) {
  // r1 is new epoch, but we can also just read that from shared memory,
  // which may be more up to date if several epochs pass.
  // revoke_wait_for_next_epoch is waiting for the epoch to be incremented.
  // This is done for us by the kernel so this function is empty.
  // We still need the callback as otherwise we may never wake up from yield().
}

/* Wait for (any non-zero number) of epochs to elapse */
int revoke_wait_for_next_epoch(void) {
  int ret;

  volatile epoch_t* epoch_ctr = global_epoch_ctr;

  if (!epoch_ctr) {
    return -1;
  }

  uint32_t epoch_now = *epoch_ctr;

  // Register for upcalls for epoch changing
  subscribe_return_t result = subscribe(CHERI_DRIVER_NUM,
                                        0,
                                        (subscribe_upcall*)&on_epoch,
                                        NULL);
  ret = tock_subscribe_return_to_returncode(result);

  if (ret < 0)
    return ret;

  // Issue request that another sweep happens
  syscall_return_t res = command(CHERI_DRIVER_NUM, COMMAND_NUM_DO_SWEEP, 0, 0);
  ret = tock_command_return_novalue_to_returncode(res);

  if (ret < 0)
    return ret;

  // Yield waiting for the epoch to change
  while (*epoch_ctr == epoch_now) {
    yield();
  }

  // Unregister
  result = subscribe(CHERI_DRIVER_NUM,
                     0,
                     NULL,
                     NULL);

  return tock_subscribe_return_to_returncode(result);
}

/* Paint the revocation bitmap from address [base, top) */
int set_revoke_range(size_t base, size_t top, int should_revoke) {

  // First offset, align, and shift range.
  // This will give two numbers that are indices into the _bits_ of the map,
  // not the bytes.

  size_t align_base = (size_t)(base - global_at_base) >> GRANULE_POW_2;
  // Also make top inclusive by subtracting one extra
  size_t align_top = (top - global_at_base + GRANULE_MASK - 1) >> GRANULE_POW_2;

  // Bounds check
  if (align_base >= align_top || align_top >= (global_map_elements * BITMAP_T_BITS)) {
    return -1;
  }

  // Mask for first byte. 1's in higher bits.
  bitmap_t mask_first = BITMAP_T_ONES << (align_base & (BITMAP_T_BITS - 1));
  // Mask for last byte. 1's in lower bits.
  bitmap_t mask_last = BITMAP_T_ONES >> ((BITMAP_T_BITS - 1) - (align_top & (BITMAP_T_BITS - 1)));

  bitmap_t* word_ptr      = global_map + (align_base >> BITMAP_T_BITS_LOG_2);
  bitmap_t* last_word_ptr = global_map + (align_top >> BITMAP_T_BITS_LOG_2);

  bitmap_t set_mask;
  if (should_revoke) {
    set_mask = BITMAP_T_ONES;
  } else {
    set_mask = 0;
  }

  // Mask for the first word (first iteration)
  bitmap_t select_mask = mask_first;

  // loop though bits setting bits to set_mask, masking which to set by
  // select_mask.
  while (word_ptr <= last_word_ptr) {
    if (word_ptr == last_word_ptr) {
      // Mask for the last word (last iteration
      select_mask &= mask_last;
    }

    bitmap_t inv_mask = ~select_mask;

    bitmap_t word = *word_ptr;
    word      = (word & inv_mask) | (set_mask & select_mask);
    *word_ptr = word;

    word_ptr++;
    select_mask = BITMAP_T_ONES; // mask for most iterations all ones
  }

  return 0;
}
