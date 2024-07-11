#include "console.h"
#include "revoke.h"
#include "tock.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#ifndef __CHERI_PURE_CAPABILITY__

int main(void) {
  printf("Error: running revoke test on non-cheri");
}

#else

char some_memory_area[777];

// Each element of the map is BITMAP_T_BITS. Each bit covers GRANULE_SIZE.
// So, each element of the map covers  (BITMAP_T_BITS * GRANULE_SIZE).
// We need to some_memory_area, so we divide and add one for the edge effect.
#define MAP_ELEMENTS \
  (sizeof(some_memory_area) / (BITMAP_T_BITS * GRANULE_SIZE)) + 1

bitmap_t map_memory[MAP_ELEMENTS];

volatile epoch_t current_epoch;

int main(void) {
  printf("Hello from revoke!\n");

  printf("Setting map:\n");

  // Create a map the shadows some_memory_area
  int ret = revoke_register(map_memory, MAP_ELEMENTS, (size_t)some_memory_area, &current_epoch);
  assert(ret == 0);

  // Two caps
  char* volatile cap1 = cheri_bounds_set(&some_memory_area[10], 1);
  char* volatile cap2 = cheri_bounds_set(&some_memory_area[300], 1);

  // Both should be tagged
  assert(cheri_tag_get(cap1) == 1);
  assert(cheri_tag_get(cap2) == 1);

  // Set some range to revoke
  ret = set_revoke_range((size_t)&some_memory_area[300], (size_t)&some_memory_area[301], 1);
  assert(ret == 0);

  for (size_t j = 0; j != MAP_ELEMENTS; j++) {
    printf("map from userspace: %zx\n", map_memory[j]);
  }

  // Make a sweep happen
  revoke_wait_for_next_epoch();

  printf("Checking\n");

  // Now one revoked, but not the other
  assert(cheri_tag_get(cap1) == 1);
  assert(cheri_tag_get(cap2) == 0);

  // Test with allowing
  // Console chosen arbitrarily as it has two allow slots we can try
  // stash caps in.
  char* to_allow1 = cheri_bounds_set(&some_memory_area[400], 100);
  char* to_allow2 = cheri_bounds_set(&some_memory_area[500], 100);

#define STR1 "hello revoke1"
#define STR2 "hello revoke2"
  memcpy(to_allow1, STR1, sizeof(STR1));
  memcpy(to_allow2, STR2, sizeof(STR2));

  allow_ro_return_t result = allow_readonly(DRIVER_NUM_CONSOLE,
                                            0,
                                            to_allow1,
                                            14);

  ret = tock_allow_ro_return_to_returncode(result);
  assert(ret == 0);

  result = allow_readonly(DRIVER_NUM_CONSOLE,
                          1,
                          to_allow2,
                          14);

  ret = tock_allow_ro_return_to_returncode(result);
  assert(ret == 0);

  ret = set_revoke_range((size_t)&some_memory_area[400], (size_t)&some_memory_area[414], 1);
  assert(ret == 0);

  revoke_wait_for_next_epoch();

  // This should read back the allows
  result = allow_readonly(DRIVER_NUM_CONSOLE,
                          0,
                          NULL,
                          0);
  assert(result.ptr == NULL);
  result = allow_readonly(DRIVER_NUM_CONSOLE,
                          1,
                          NULL,
                          0);
  assert(result.ptr != NULL);

  printf("Revocation test success\n");

  return 0;
}

#endif // __CHERI_PURE_CAPABILITY__