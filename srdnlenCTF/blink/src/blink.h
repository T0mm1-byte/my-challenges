#ifndef BLINK_H
#define BLINK_H

#include "stm32f1xx.h"

/* ---- Pinout (Blue Pill) -------------------------------------------------
 * PC13  morse output, onboard LED, active low
 * PB0   trigger button to GND, internal pull-up, EXTI0 on falling edge
 * PA9   USART1_TX, firmware dump
 */
#define MORSE_PORT        GPIOC
#define MORSE_PIN         13u
#define MORSE_ACTIVE_LOW  1

#define BTN_PORT          GPIOB
#define BTN_PIN           0u

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
/* Long enough that the restart of the loop is unmistakable in a capture. */
#define MORSE_REPEAT_MS   (20u * MORSE_UNIT_MS)

/* ---- Trigger ------------------------------------------------------------ */
#define TRIGGER_PRESSES   3u
#define TRIGGER_WINDOW_MS 2000u
#define TRIGGER_DEBOUNCE_MS 40u

/* ---- Flash layout ------------------------------------------------------- */
#define FLASH_ORIGIN      0x08000000UL
#define FLASH_PAGE_SIZE   1024u
#define DUMP_PAGES        63u                       /* pages 0..62 */
#define FLAG_ADDR         (FLASH_ORIGIN + DUMP_PAGES * FLASH_PAGE_SIZE)
#define FLAG_MAX_LEN      256u

/* ---- Dump framing -------------------------------------------------------
 * Each frame: "BLNK" | u16 page | u16 total | 1024 data bytes | u32 CRC.
 * CRC is the STM32 hardware unit (poly 0x04C11DB7, init 0xFFFFFFFF, MSB
 * first, no reflection, no final xor) over the 258 words of header+data.
 * Pages go out permuted, so they must be reordered by page number.
 */
#define FRAME_MAGIC       0x4B4E4C42UL              /* 'B','L','N','K' */
#define FRAME_HDR_BYTES   8u
#define DUMP_BAUD         115200u
#define DUMP_ORDER_MUL    29u
#define DUMP_ORDER_ADD    11u

extern volatile uint32_t g_ms;

void delay_ms(uint32_t ms);

void morse_led(int on);
void morse_send(const volatile char *s, uint32_t max_len);

void dump_init(void);

#endif /* BLINK_H */
