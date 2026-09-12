#include "blink.h"

volatile uint32_t g_ms;

void delay_ms(uint32_t ms)
{
    uint32_t t0 = g_ms;
    while ((uint32_t)(g_ms - t0) < ms) {
        __WFI();
    }
}

void SysTick_Handler(void)
{
    g_ms++;
}

static void clock_init(void)
{
    /* 72 MHz from the 8 MHz crystal: HSE -> PLL x9. Two wait states are
     * mandatory above 48 MHz. */
    FLASH->ACR = FLASH_ACR_PRFTBE | FLASH_ACR_LATENCY_2;

    RCC->CR |= RCC_CR_HSEON;
    while ((RCC->CR & RCC_CR_HSERDY) == 0u) {
    }

    RCC->CFGR = RCC_CFGR_HPRE_DIV1     /* HCLK  = SYSCLK = 72 MHz */
              | RCC_CFGR_PPRE1_DIV2    /* PCLK1 = 36 MHz (max)    */
              | RCC_CFGR_PPRE2_DIV1    /* PCLK2 = 72 MHz          */
              | RCC_CFGR_PLLSRC        /* PLL fed by HSE          */
              | RCC_CFGR_PLLMULL9;

    RCC->CR |= RCC_CR_PLLON;
    while ((RCC->CR & RCC_CR_PLLRDY) == 0u) {
    }

    RCC->CFGR = (RCC->CFGR & ~RCC_CFGR_SW) | RCC_CFGR_SW_PLL;
    while ((RCC->CFGR & RCC_CFGR_SWS) != RCC_CFGR_SWS_PLL) {
    }

    SystemCoreClockUpdate();
}

static void gpio_init(void)
{
    RCC->APB2ENR |= RCC_APB2ENR_IOPCEN;

    /* PC13: general purpose push-pull, 2 MHz. */
    MORSE_PORT->CRH = (MORSE_PORT->CRH & ~(0xFu << ((MORSE_PIN - 8u) * 4u)))
                    | (0x2u << ((MORSE_PIN - 8u) * 4u));
    morse_led(0);
}

int main(void)
{
    clock_init();
    gpio_init();
    dump_init();

    SysTick_Config(SystemCoreClock / 1000u);
    /* Above EXTI0, so the millisecond counter keeps running while the dump
     * handler holds the CPU. Whatever delay was in flight then finds its
     * deadline already expired and the morse picks up in step. */
    NVIC_SetPriority(SysTick_IRQn, 0);

    for (;;) {
        morse_send((const volatile char *)FLAG_ADDR, FLAG_MAX_LEN);
        delay_ms(MORSE_REPEAT_MS);
    }
}
