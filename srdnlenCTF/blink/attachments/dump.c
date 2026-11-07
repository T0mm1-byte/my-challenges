typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;

typedef struct {
    volatile uint32_t MODER;
    volatile uint32_t OTYPER;
    volatile uint32_t OSPEEDR;
    volatile uint32_t PUPDR;
    volatile uint32_t IDR;
    volatile uint32_t ODR;
    volatile uint32_t BSRR;
    volatile uint32_t LCKR;
    volatile uint32_t AFR[2];
} GPIO_TypeDef;

typedef struct {
    volatile uint32_t MEMRMP;
    volatile uint32_t PMC;
    volatile uint32_t EXTICR[4];
    uint32_t RESERVED[2];
    volatile uint32_t CMPCR;
    uint32_t RESERVED1[2];
    volatile uint32_t CFGR;
} SYSCFG_TypeDef;

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
    volatile uint32_t PLLCFGR;
    volatile uint32_t CFGR;
    volatile uint32_t CIR;
    volatile uint32_t AHB1RSTR;
    volatile uint32_t AHB2RSTR;
    volatile uint32_t AHB3RSTR;
    uint32_t RESERVED0;
    volatile uint32_t APB1RSTR;
    volatile uint32_t APB2RSTR;
    uint32_t RESERVED1[2];
    volatile uint32_t AHB1ENR;
    volatile uint32_t AHB2ENR;
    volatile uint32_t AHB3ENR;
    uint32_t RESERVED2;
    volatile uint32_t APB1ENR;
    volatile uint32_t APB2ENR;
    uint32_t RESERVED3[2];
    volatile uint32_t AHB1LPENR;
    volatile uint32_t AHB2LPENR;
    volatile uint32_t AHB3LPENR;
    uint32_t RESERVED4;
    volatile uint32_t APB1LPENR;
    volatile uint32_t APB2LPENR;
    uint32_t RESERVED5[2];
    volatile uint32_t BDCR;
    volatile uint32_t CSR;
    uint32_t RESERVED6[2];
    volatile uint32_t SSCGR;
    volatile uint32_t PLLI2SCFGR;
    volatile uint32_t PLLSAICFGR;
    volatile uint32_t DCKCFGR;
    volatile uint32_t CKGATENR;
    volatile uint32_t DCKCFGR2;
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

#define USART1 ((USART_TypeDef  *)0x40011000UL)
#define SYSCFG ((SYSCFG_TypeDef *)0x40013800UL)
#define EXTI   ((EXTI_TypeDef   *)0x40013C00UL)
#define GPIOB  ((GPIO_TypeDef   *)0x40020400UL)
#define GPIOC  ((GPIO_TypeDef   *)0x40020800UL)
#define CRC    ((CRC_TypeDef    *)0x40023000UL)
#define RCC    ((RCC_TypeDef    *)0x40023800UL)
#define NVIC   ((NVIC_TypeDef   *)0xE000E100UL)

#define EXTI15_10_IRQn          40u

#define RCC_AHB1ENR_GPIOBEN     0x00000002UL
#define RCC_AHB1ENR_GPIOCEN     0x00000004UL
#define RCC_AHB1ENR_CRCEN       0x00001000UL
#define RCC_APB2ENR_USART1EN    0x00000010UL
#define RCC_APB2ENR_SYSCFGEN    0x00004000UL

#define RCC_CFGR_PPRE2_Pos      13u
#define RCC_CFGR_PPRE2          0x0000E000UL

#define GPIO_MODER_MODER6       0x00003000UL
#define GPIO_MODER_MODER6_1     0x00002000UL
#define GPIO_OSPEEDR_OSPEED6    0x00003000UL
#define GPIO_OSPEEDR_OSPEED6_1  0x00002000UL
#define GPIO_AFRL_AFSEL6_Pos    24u
#define GPIO_AFRL_AFSEL6        0x0F000000UL

#define SYSCFG_EXTICR4_EXTI13    0x000000F0UL
#define SYSCFG_EXTICR4_EXTI13_PC 0x00000020UL

#define EXTI_IMR_MR13           0x00002000UL
#define EXTI_RTSR_TR13          0x00002000UL
#define EXTI_FTSR_TR13          0x00002000UL
#define EXTI_PR_PR13            0x00002000UL

#define USART_CR1_UE            0x00002000UL
#define USART_CR1_TE            0x00000008UL
#define USART_SR_TXE            0x00000080UL
#define USART_SR_TC             0x00000040UL

#define CRC_CR_RESET            0x00000001UL

#define BTN_PORT                GPIOC
#define BTN_PIN                 13u

#define TRIGGER_PRESSES         8u
#define TRIGGER_WINDOW_MS       3000u
#define TRIGGER_DEBOUNCE_MS     40u
#define MORSE_HOLD_MS           5000u

#define FLASH_ORIGIN            0x08000000UL
#define DUMP_BLOCK_SIZE         1024u
#define DUMP_BLOCKS             63u

#define FRAME_MAGIC             0x4B4E4C42UL
#define FRAME_HDR_BYTES         8u
#define DUMP_BAUD               115200u
#define DUMP_ORDER_MUL          29u
#define DUMP_ORDER_ADD          11u

#define FRAME_WORDS ((FRAME_HDR_BYTES + DUMP_BLOCK_SIZE) / 4u)

extern volatile uint32_t g_ms;
extern volatile uint32_t g_morse_on;
extern uint32_t SystemCoreClock;
extern const uint8_t APBPrescTable[8];

static union {
    uint32_t w[FRAME_WORDS];
    uint8_t  b[FRAME_HDR_BYTES + DUMP_BLOCK_SIZE];
} frame;

static volatile uint32_t press_ts[TRIGGER_PRESSES];
static volatile uint32_t press_count;
static volatile uint32_t last_edge_ms;
static volatile uint32_t btn_down;
static volatile uint32_t btn_down_ms;

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
    RCC->AHB1ENR |= RCC_AHB1ENR_CRCEN | RCC_AHB1ENR_GPIOBEN | RCC_AHB1ENR_GPIOCEN;
    RCC->APB2ENR |= RCC_APB2ENR_SYSCFGEN | RCC_APB2ENR_USART1EN;

    BTN_PORT->MODER = BTN_PORT->MODER & ~(0x3u << (BTN_PIN * 2u));
    BTN_PORT->PUPDR = BTN_PORT->PUPDR & ~(0x3u << (BTN_PIN * 2u));

    GPIOB->AFR[0] = (GPIOB->AFR[0] & ~GPIO_AFRL_AFSEL6)
                  | (7u << GPIO_AFRL_AFSEL6_Pos);
    GPIOB->OSPEEDR = (GPIOB->OSPEEDR & ~GPIO_OSPEEDR_OSPEED6)
                   | GPIO_OSPEEDR_OSPEED6_1;
    GPIOB->MODER = (GPIOB->MODER & ~GPIO_MODER_MODER6)
                 | GPIO_MODER_MODER6_1;

    uint32_t pclk2 = SystemCoreClock
                   >> APBPrescTable[(RCC->CFGR & RCC_CFGR_PPRE2) >> RCC_CFGR_PPRE2_Pos];
    USART1->BRR = (uint16_t)(pclk2 / DUMP_BAUD);
    USART1->CR2 = 0u;
    USART1->CR3 = 0u;
    USART1->CR1 = USART_CR1_UE | USART_CR1_TE;

    SYSCFG->EXTICR[3] = (SYSCFG->EXTICR[3] & ~SYSCFG_EXTICR4_EXTI13)
                      | SYSCFG_EXTICR4_EXTI13_PC;

    EXTI->FTSR |= EXTI_FTSR_TR13;
    EXTI->RTSR |= EXTI_RTSR_TR13;
    EXTI->PR    = EXTI_PR_PR13;
    EXTI->IMR  |= EXTI_IMR_MR13;

    NVIC_SetPriority(EXTI15_10_IRQn, 1);
    NVIC_EnableIRQ(EXTI15_10_IRQn);
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

static void dump_block(uint16_t block)
{
    const uint32_t *src = (const uint32_t *)(FLASH_ORIGIN + block * DUMP_BLOCK_SIZE);

    frame.w[0] = FRAME_MAGIC;
    frame.w[1] = (uint32_t)block | ((uint32_t)DUMP_BLOCKS << 16);

    for (uint32_t i = 0u; i < DUMP_BLOCK_SIZE / 4u; i++) {
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
    for (uint32_t i = 0u; i < DUMP_BLOCKS; i++) {
        uint16_t block = (uint16_t)((i * DUMP_ORDER_MUL + DUMP_ORDER_ADD) % DUMP_BLOCKS);
        dump_block(block);
    }

    uart_flush();

    EXTI->PR = EXTI_PR_PR13;
    NVIC_ClearPendingIRQ(EXTI15_10_IRQn);
    btn_down = 0u;
}

void EXTI15_10_IRQHandler(void)
{
    if ((EXTI->PR & EXTI_PR_PR13) == 0u) {
        return;
    }
    EXTI->PR = EXTI_PR_PR13;

    uint32_t now = g_ms;
    if ((uint32_t)(now - last_edge_ms) < TRIGGER_DEBOUNCE_MS) {
        return;
    }
    last_edge_ms = now;

    if ((BTN_PORT->IDR & (1u << BTN_PIN)) != 0u) {
        if (btn_down != 0u) {
            btn_down = 0u;
            if ((uint32_t)(now - btn_down_ms) > MORSE_HOLD_MS) {
                g_morse_on = 1u;
            }
        }
        return;
    }

    if (btn_down != 0u) {
        return;
    }
    btn_down = 1u;
    btn_down_ms = now;

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
