/* vim: set sw=2 expandtab tw=80: */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <console.h>

static void nop(
  int a __attribute__((unused)),
  int b __attribute__((unused)),
  int c __attribute__((unused)),
  void* d __attribute__((unused))) {}

int main(void) {

  // Some data it is very important not to leak
  char very_secret_key[] = {"Very secret indeed"};
  // Otherwise the compiler thinks its oh so smart and optimises this away
  __asm("" ::"r" ((size_t)very_secret_key) : "memory");

  // Declare some message
  char msg[]     = "Hello world!";
  size_t msg_len = sizeof(msg) * 8; // Lengths are in bits, right?

  // Print the message
  putnstr_async(msg, msg_len, nop, NULL);
  tock_exit(0);
}
