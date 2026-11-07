#include "blink.h"

/* ==========================================================================
 *  THE FLAG. This is the only place it is defined; edit the line below.
 *
 *  Lowercase only: Morse has no case, so an uppercase flag is transmitted
 *  identically to its lowercase form and cannot be recovered.
 *  Usable characters, per the table in morse.c:
 *      a-z 0-9 { } _ - . , ? ! / : ; = + & @ $ ' "  and space
 *  Anything else is skipped silently when transmitted.
 * ========================================================================== */
#define FLAG_STRING "srdnlen{m0rse_1s_4w3s0m3_but_n0t_v3ry_s3cur3_44378d}"

/* Pinned to 0x0800FC00 by the linker script. This is the 1K block right
 * after the region the dump routine transmits. */
__attribute__((section(".flag"), used))
const char g_flag[] = FLAG_STRING;

_Static_assert(sizeof(g_flag) <= DUMP_BLOCK_SIZE, "flag does not fit its block");
_Static_assert(sizeof(g_flag) <= FLAG_MAX_LEN, "flag longer than FLAG_MAX_LEN");
