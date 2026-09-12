typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;

typedef struct {
    volatile uint32_t CRL;
    volatile uint32_t CRH;
    volatile uint32_t IDR;
    volatile uint32_t ODR;
    volatile uint32_t BSRR;
    volatile uint32_t BRR;
    volatile uint32_t LCKR;
} GPIO_TypeDef;

typedef struct {
    volatile uint32_t EVCR;
    volatile uint32_t MAPR;
    volatile uint32_t EXTICR[4];
    uint32_t RESERVED0;
    volatile uint32_t MAPR2;
} AFIO_TypeDef;

typedef struct {
    volatile uint32_t IMR;
    volatile uint32_t EMR;
    volatile uint32_t RTSR;
    volatile uint32_t FTSR;
    volatile uint32_t SWIER;
    volatile uint32_t PR;
} EXTI_TypeDef;

typedef struct {
    volatile uint32_t SR;
    volatile uint32_t DR;
    volatile uint32_t BRR;
    volatile uint32_t CR1;
    volatile uint32_t CR2;
    volatile uint32_t CR3;
    volatile uint32_t GTPR;
} USART_TypeDef;

typedef struct {
    volatile uint32_t DR;
    volatile uint8_t  IDR;
    uint8_t  RESERVED0;
    uint16_t RESERVED1;
    volatile uint32_t CR;
} CRC_TypeDef;

typedef struct {
    volatile uint32_t CR;
    volatile uint32_t CFGR;
    volatile uint32_t CIR;
    volatile uint32_t APB2RSTR;
    volatile uint32_t APB1RSTR;
    volatile uint32_t AHBENR;
    volatile uint32_t APB2ENR;
    volatile uint32_t APB1ENR;
    volatile uint32_t BDCR;
    volatile uint32_t CSR;
} RCC_TypeDef;

typedef struct {
    volatile uint32_t ISER[8];
    uint32_t RESERVED0[24];
    volatile uint32_t ICER[8];
    uint32_t RESERVED1[24];
    volatile uint32_t ISPR[8];
    uint32_t RESERVED2[24];
    volatile uint32_t ICPR[8];
    uint32_t RESERVED3[24];
    volatile uint32_t IABR[8];
    uint32_t RESERVED4[56];
    volatile uint8_t  IP[240];
} NVIC_TypeDef;

#define AFIO   ((AFIO_TypeDef  *)0x40010000UL)
#define EXTI   ((EXTI_TypeDef  *)0x40010400UL)
#define GPIOA  ((GPIO_TypeDef  *)0x40010800UL)
#define GPIOB  ((GPIO_TypeDef  *)0x40010C00UL)
#define USART1 ((USART_TypeDef *)0x40013800UL)
#define RCC    ((RCC_TypeDef   *)0x40021000UL)
#define CRC    ((CRC_TypeDef   *)0x40023000UL)
#define NVIC   ((NVIC_TypeDef  *)0xE000E100UL)

#define EXTI0_IRQn              6u

#define RCC_AHBENR_CRCEN        0x00000040UL
#define RCC_APB2ENR_AFIOEN      0x00000001UL
#define RCC_APB2ENR_IOPAEN      0x00000004UL
#define RCC_APB2ENR_IOPBEN      0x00000008UL
#define RCC_APB2ENR_USART1EN    0x00004000UL

#define AFIO_EXTICR1_EXTI0      0x0000000FUL
#define AFIO_EXTICR1_EXTI0_PB   0x00000001UL

#define EXTI_IMR_MR0            0x00000001UL
#define EXTI_RTSR_TR0           0x00000001UL
#define EXTI_FTSR_TR0           0x00000001UL
#define EXTI_PR_PR0             0x00000001UL

#define USART_CR1_UE            0x00002000UL
#define USART_CR1_TE            0x00000008UL
#define USART_SR_TXE            0x00000080UL
#define USART_SR_TC             0x00000040UL

#define CRC_CR_RESET            0x00000001UL

#define BTN_PORT                GPIOB
#define BTN_PIN                 0u

#define TRIGGER_PRESSES         3u
#define TRIGGER_WINDOW_MS       2000u
#define TRIGGER_DEBOUNCE_MS     40u

#define FLASH_ORIGIN            0x08000000UL
#define FLASH_PAGE_SIZE         1024u
#define DUMP_PAGES              63u

#define FRAME_MAGIC             0x4B4E4C42UL
#define FRAME_HDR_BYTES         8u
#define DUMP_BAUD               115200u
#define DUMP_ORDER_MUL          29u
#define DUMP_ORDER_ADD          11u

#define FRAME_WORDS ((FRAME_HDR_BYTES + FLASH_PAGE_SIZE) / 4u)

extern volatile uint32_t g_ms;
extern uint32_t SystemCoreClock;

static union {
    uint32_t w[FRAME_WORDS];
    uint8_t  b[FRAME_HDR_BYTES + FLASH_PAGE_SIZE];
} frame;

static volatile uint32_t press_ts[TRIGGER_PRESSES];
static volatile uint32_t press_count;
static volatile uint32_t last_press_ms;

static void NVIC_SetPriority(uint32_t irqn, uint32_t priority)
{
    NVIC->IP[irqn] = (uint8_t)(priority << 4);
}

static void NVIC_EnableIRQ(uint32_t irqn)
{
    NVIC->ISER[irqn >> 5u] = 1u << (irqn & 0x1Fu);
}

static void NVIC_ClearPendingIRQ(uint32_t irqn)
{
    NVIC->ICPR[irqn >> 5u] = 1u << (irqn & 0x1Fu);
}

void dump_init(void)
{
    RCC->AHBENR  |= RCC_AHBENR_CRCEN;
    RCC->APB2ENR |= RCC_APB2ENR_IOPAEN | RCC_APB2ENR_IOPBEN
                  | RCC_APB2ENR_AFIOEN | RCC_APB2ENR_USART1EN;

    BTN_PORT->CRL = (BTN_PORT->CRL & ~(0xFu << (BTN_PIN * 4u)))
                  | (0x8u << (BTN_PIN * 4u));
    BTN_PORT->ODR |= (1u << BTN_PIN);

    GPIOA->CRH = (GPIOA->CRH & ~(0xFu << ((9u - 8u) * 4u)))
               | (0xBu << ((9u - 8u) * 4u));

    USART1->BRR = (uint16_t)(SystemCoreClock / DUMP_BAUD);
    USART1->CR2 = 0u;
    USART1->CR3 = 0u;
    USART1->CR1 = USART_CR1_UE | USART_CR1_TE;

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

static void dump_firmware(void)
{
    for (uint32_t i = 0u; i < DUMP_PAGES; i++) {
        uint16_t page = (uint16_t)((i * DUMP_ORDER_MUL + DUMP_ORDER_ADD) % DUMP_PAGES);
        dump_page(page);
    }

    uart_flush();

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
