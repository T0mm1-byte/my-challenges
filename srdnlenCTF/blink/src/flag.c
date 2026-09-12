#include "blink.h"

#ifndef FLAG_STRING
#define FLAG_STRING "srdnlen{placeholder_flag}"
#endif

/* Pinned to 0x0800FC00 by the linker script. This is the one flash page the
 * dump routine skips. */
__attribute__((section(".flag"), used))
const char g_flag[] = FLAG_STRING;

_Static_assert(sizeof(g_flag) <= FLASH_PAGE_SIZE, "flag does not fit its page");
_Static_assert(sizeof(g_flag) <= FLAG_MAX_LEN, "flag longer than FLAG_MAX_LEN");
