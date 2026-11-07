#ifndef BLINK_H
#define BLINK_H

#include "stm32f4xx.h"

/* ---- Pinout (Nucleo-F446RE) ---------------------------------------------
 * PA8   morse output, plain GPIO push-pull, 1 = mark, 0 = space   (D7)
 * PC13  B1 USER button on the board, external pull-up, active low,
 *       EXTI13 on both edges
 * NRST  B2 RESET button, hardware reset back to the silent initial state
 * PB6   USART1_TX, AF7, firmware dump                               (D10)
 */
#define MORSE_PORT        GPIOA
#define MORSE_PIN         8u

#define BTN_PORT          GPIOC
#define BTN_PIN           13u

/* ---- Morse timing -------------------------------------------------------
 * International Morse ratios: dot 1, dash 3, element gap 1, letter gap 3,
 * word gap 7. 80 ms/unit is 15 WPM.
 */
#define MORSE_UNIT_MS     80u
#define MORSE_DOT_MS      (1u * MORSE_UNIT_MS)
#define MORSE_DASH_MS     (3u * MORSE_UNIT_MS)
#define MORSE_GAP_MS      (1u * MORSE_UNIT_MS)
#define MORSE_LETTER_MS   (3u * MORSE_UNIT_MS)
#define MORSE_WORD_MS     (7u * MORSE_UNIT_MS)
#define MORSE_REPEAT_MS   (20u * MORSE_UNIT_MS)

/* ---- Trigger ------------------------------------------------------------
 * B1 pressed TRIGGER_PRESSES times within TRIGGER_WINDOW_MS dumps the
 * firmware. B1 held longer than MORSE_HOLD_MS and then released starts the
 * morse loop, which runs until reset.
 */
#define TRIGGER_PRESSES   8u
#define TRIGGER_WINDOW_MS 3000u
#define TRIGGER_DEBOUNCE_MS 40u
#define MORSE_HOLD_MS     5000u

/* ---- Flash layout -------------------------------------------------------
 * The F4 has sectors, not pages: the dump walks the first 63K in 1K blocks.
 * The flag sits in the next block, at the top of sector 3.
 */
#define FLASH_ORIGIN      0x08000000UL
#define DUMP_BLOCK_SIZE   1024u
#define DUMP_BLOCKS       63u                       /* blocks 0..62 */
#define FLAG_ADDR         (FLASH_ORIGIN + DUMP_BLOCKS * DUMP_BLOCK_SIZE)
#define FLAG_MAX_LEN      256u

/* ---- Dump framing -------------------------------------------------------
 * Each frame: "BLNK" | u16 block | u16 total | 1024 data bytes | u32 CRC.
 * CRC is the STM32 hardware unit (poly 0x04C11DB7, init 0xFFFFFFFF, MSB
 * first, no reflection, no final xor) over the 258 words of header+data.
 * Blocks go out permuted, so they must be reordered by block number.
 */
#define FRAME_MAGIC       0x4B4E4C42UL              /* 'B','L','N','K' */
#define FRAME_HDR_BYTES   8u
#define DUMP_BAUD         115200u
#define DUMP_ORDER_MUL    29u
#define DUMP_ORDER_ADD    11u

extern volatile uint32_t g_ms;
extern volatile uint32_t g_morse_on;

void delay_ms(uint32_t ms);

void morse_out(int level);
void morse_send(const volatile char *s, uint32_t max_len);

void dump_init(void);

#endif /* BLINK_H */
