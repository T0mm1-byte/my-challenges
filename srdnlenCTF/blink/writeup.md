# Blink

CTF: Srdnlen Finals 2026

Category: rev, hardware

Author: T0mm1

## Description

The police gave us a mysterious microcontroller, a STM32F446RE, retrieved in a big operation. They don't know exactly how it works but a mole got a piece of its source code. Can you help them to solve the case?

## Overview

This challenge is made of a .c file that contains some source code and a physical board.

## Solution

blink.c is the code that manages the dump of the whole firmware. It's pretty clear from the dump_firmware function. How to trigger the function?

```C
void EXTI15_10_IRQHandler(void)
{
    if ((EXTI->PR & EXTI_PR_PR13) == 0u) {
        return;
    }
    EXTI->PR = EXTI_PR_PR13;

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
```

This function calls dump_firmware() if an interrupt is activated 8 times in 3 seconds. The interrupt is on EXTI13, that means the blue button on the board.

```C
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
}
```

These functions describe the dump: there are 63 blocks, each of them has 4 byte of magic number, 2 of block size, 2 of block number, 1024 of data and 4 of crc. The blocks aren't sent in the right order so it's needed to look at their block numbers to reconstruct the firmware. But where to read it?

```C
#define GPIO_MODER_MODER6       0x00003000UL
#define GPIO_MODER_MODER6_1     0x00002000UL
#define GPIO_OSPEEDR_OSPEED6    0x00003000UL
#define GPIO_OSPEEDR_OSPEED6_1  0x00002000UL
#define GPIO_AFRL_AFSEL6_Pos    24u
#define GPIO_AFRL_AFSEL6        0x0F000000UL

    // ...

    GPIOB->AFR[0] = (GPIOB->AFR[0] & ~GPIO_AFRL_AFSEL6)
                  | (7u << GPIO_AFRL_AFSEL6_Pos);
```

These lines configure the pin PB6 that is D10 on the board.

<img width="593" height="337" alt="nucleo_pinout" src="https://github.com/user-attachments/assets/62609f14-0d7b-40ee-a9c9-17ab32476456" />

Once pressed the blue button eight times in three seconds the dump will start on pin D10 so the next thing to do is to connect the logic analyzer to the board to get it. The next steps are, from saleae logic, to use the serial analyzer in 8N1 mode with 115200 ad baudrate, export the data as a .csv and then write a script to build the firmware.

```python
import csv
import struct
import sys

MAGIC = b"BLNK"
BLOCK = 1024
FRAME = 4 + 2 + 2 + BLOCK + 4


def stm32_crc(data):
    crc = 0xFFFFFFFF
    for (word,) in struct.iter_unpack("<I", data):
        crc ^= word
        for _ in range(32):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else (crc << 1)
            crc &= 0xFFFFFFFF
    return crc


def read_bytes(path):
    with open(path, newline="") as f:
        rows = csv.DictReader(f)
        return bytes(int(r["data"], 16) for r in rows if r["type"] == "data")


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "dump.csv"
    dst = sys.argv[2] if len(sys.argv) > 2 else "firmware.bin"

    stream = read_bytes(src)

    blocks, total, bad = {}, None, 0
    pos = stream.find(MAGIC)
    while pos != -1 and pos + FRAME <= len(stream):
        frame = stream[pos:pos + FRAME]
        index, count = struct.unpack_from("<HH", frame, 4)
        (crc,) = struct.unpack_from("<I", frame, FRAME - 4)

        if stm32_crc(frame[:-4]) == crc and index < count:
            blocks[index] = frame[8:-4]
            total = count
            pos = stream.find(MAGIC, pos + FRAME)
        else:
            bad += 1
            pos = stream.find(MAGIC, pos + 1)

    if total is None:
        sys.exit("no valid frame found")

    image = b"".join(blocks.get(i, b"\xff" * BLOCK) for i in range(total))
    with open(dst, "wb") as f:
        f.write(image)

if __name__ == "__main__":
    main()
```

Running the file command on firmware.bin will show that is a Cortex-M firmware as expected. Opening it in IDA shows a normal code of a STM32 firmware. In the main there is a function that I renamed "morse_send". This function dumps on another pin something in morse code. Unfortunately it's address is 0x800FC00, exactly where the firmware dump ends, so it's impossible to directly see it.

<img width="319" height="127" alt="morse_loop" src="https://github.com/user-attachments/assets/39cf26cd-0bfc-44fe-8df9-49dee58e32ee" />

Which pin does it use?

```C
  v13 = GPIOA_MODER;
  GPIOA_MODER = v13 & 0xFFFCFFFF | 0x10000;
```

These two lines in main configure PA8 (D7) as an output pin. Unfortunately there is a loop before the one with morse_send, a loop that just wait for a value. Pressing "x" over it will show that the only function that writes on it is IRQ_40_handler that is the ISR that permits to dump the firmware. In blink.c it's written that only a part of it is given to the player so in the complete version there should be something new.

<img width="562" height="187" alt="irq_long_press" src="https://github.com/user-attachments/assets/8a743e98-c206-449c-a807-3af66546a654" />

This part isn't present in blink.c and says that if the blue button is pressed for 5 seconds it changes the variable to 1 and the morse_send loop will start. Again it's needed to sample the signal with the logic analyzer on saleae logic, export the data and write a python script to build the message.

```python
import csv, sys, statistics

TABLE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "-.--.": "{", "-.--.-": "}", "..--.-": "_",
    "-....-": "-", ".-.-.-": ".", "--..--": ",", "..--..": "?", "-.-.--": "!",
    "-..-.": "/", "---...": ":", "-.-.-.": ";", "-...-": "=", ".-.-.": "+",
    ".-...": "&", ".--.-.": "@", "...-..-": "$", ".----.": "'", ".-..-.": '"',
}

rows = list(csv.reader(open(sys.argv[1])))
col = int(sys.argv[2]) if len(sys.argv) > 2 else 1
edges = [(float(r[0]), int(float(r[col]))) for r in rows[1:] if r]

runs = [(lvl, t1 - t0) for (t0, lvl), (t1, _) in zip(edges, edges[1:])]
marks = [d for lvl, d in runs if lvl == 1]
unit = statistics.median([d for d in marks if d < 2 * min(marks)])

out, sym = [], ""
for lvl, d in runs:
    u = d / unit
    if lvl == 1:
        sym += "." if u < 2 else "-"
    elif u >= 2:
        out.append(TABLE.get(sym, "#") if sym else "")
        sym = ""
        if u >= 10:
            out.append("\n")
        elif u >= 5:
            out.append(" ")
if sym:
    out.append(TABLE.get(sym, "#"))

print("".join(out).strip())
```

The result is the flag *srdnlen{m0rse_1s_4w3s0m3_but_n0t_v3ry_s3cur3_44378d}*
