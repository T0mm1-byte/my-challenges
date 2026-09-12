#include "blink.h"

#define FRAME_WORDS ((FRAME_HDR_BYTES + FLASH_PAGE_SIZE) / 4u)

static union {
    uint32_t w[FRAME_WORDS];
    uint8_t  b[FRAME_HDR_BYTES + FLASH_PAGE_SIZE];
} frame;

static volatile uint32_t press_ts[TRIGGER_PRESSES];
static volatile uint32_t press_count;
static volatile uint32_t last_press_ms;

void dump_init(void)
{
    RCC->AHBENR  |= RCC_AHBENR_CRCEN;
    RCC->APB2ENR |= RCC_APB2ENR_IOPAEN | RCC_APB2ENR_IOPBEN
                  | RCC_APB2ENR_AFIOEN | RCC_APB2ENR_USART1EN;

    /* PB0: input with pull-up, the ODR bit picks up over down. */
    BTN_PORT->CRL = (BTN_PORT->CRL & ~(0xFu << (BTN_PIN * 4u)))
                  | (0x8u << (BTN_PIN * 4u));
    BTN_PORT->ODR |= (1u << BTN_PIN);

    /* PA9 = USART1_TX: alternate function push-pull, 50 MHz. */
    GPIOA->CRH = (GPIOA->CRH & ~(0xFu << ((9u - 8u) * 4u)))
               | (0xBu << ((9u - 8u) * 4u));

    /* PCLK2 is undivided, so USARTDIV*16 is just PCLK2/baud. */
    USART1->BRR = (uint16_t)(SystemCoreClock / DUMP_BAUD);
    USART1->CR2 = 0u;                               /* 1 stop bit      */
    USART1->CR3 = 0u;                               /* no flow control */
    USART1->CR1 = USART_CR1_UE | USART_CR1_TE;      /* 8N1             */

    /* EXTI line 0 -> port B, falling edge only. */
    AFIO->EXTICR[0] = (AFIO->EXTICR[0] & ~AFIO_EXTICR1_EXTI0)
                    | AFIO_EXTICR1_EXTI0_PB;

    EXTI->FTSR |= EXTI_FTSR_TR0;
    EXTI->RTSR &= ~EXTI_RTSR_TR0;
    EXTI->PR    = EXTI_PR_PR0;
    EXTI->IMR  |= EXTI_IMR_MR0;

    NVIC_SetPriority(EXTI0_IRQn, 1);
    NVIC_EnableIRQ(EXTI0_IRQn);
}

static void uart_tx(uint8_t byte)
{
    while ((USART1->SR & USART_SR_TXE) == 0u) {
    }
    USART1->DR = byte;
}

static void uart_flush(void)
{
    while ((USART1->SR & USART_SR_TC) == 0u) {
    }
}

static uint32_t frame_crc(void)
{
    CRC->CR = CRC_CR_RESET;
    for (uint32_t i = 0u; i < FRAME_WORDS; i++) {
        CRC->DR = frame.w[i];
    }
    return CRC->DR;
}

static void dump_page(uint16_t page)
{
    const uint32_t *src = (const uint32_t *)(FLASH_ORIGIN + page * FLASH_PAGE_SIZE);

    frame.w[0] = FRAME_MAGIC;
    frame.w[1] = (uint32_t)page | ((uint32_t)DUMP_PAGES << 16);

    for (uint32_t i = 0u; i < FLASH_PAGE_SIZE / 4u; i++) {
        frame.w[2u + i] = src[i];
    }

    uint32_t crc = frame_crc();

    for (uint32_t i = 0u; i < sizeof(frame.b); i++) {
        uart_tx(frame.b[i]);
    }
    for (uint32_t i = 0u; i < 4u; i++) {
        uart_tx((uint8_t)(crc >> (8u * i)));
    }
}

/* Pages 0..62 only. They go out permuted by an affine map over Z/63, so a
 * capture has to be reordered by page number. Runs to completion inside the
 * handler, holding the CPU for the whole transfer. */
static void dump_firmware(void)
{
    for (uint32_t i = 0u; i < DUMP_PAGES; i++) {
        uint16_t page = (uint16_t)((i * DUMP_ORDER_MUL + DUMP_ORDER_ADD) % DUMP_PAGES);
        dump_page(page);
    }

    uart_flush();

    /* Drop presses that arrived while the CPU was busy, so the handler does
     * not re-enter on return. */
    EXTI->PR = EXTI_PR_PR0;
    NVIC_ClearPendingIRQ(EXTI0_IRQn);
}

void EXTI0_IRQHandler(void)
{
    if ((EXTI->PR & EXTI_PR_PR0) == 0u) {
        return;
    }
    EXTI->PR = EXTI_PR_PR0;

    uint32_t now = g_ms;
    if ((uint32_t)(now - last_press_ms) < TRIGGER_DEBOUNCE_MS) {
        return;
    }
    last_press_ms = now;

    press_ts[press_count % TRIGGER_PRESSES] = now;
    press_count++;

    if (press_count >= TRIGGER_PRESSES) {
        uint32_t oldest = press_ts[(press_count - TRIGGER_PRESSES) % TRIGGER_PRESSES];
        if ((uint32_t)(now - oldest) <= TRIGGER_WINDOW_MS) {
            press_count = 0u;
            dump_firmware();
        }
    }
}
