TARGET  = blink
BUILD   = build

FLAG   ?= srdnlen{placeholder_flag}

PREFIX  = arm-none-eabi-
CC      = $(PREFIX)gcc
OBJCOPY = $(PREFIX)objcopy
SIZE    = $(PREFIX)size

C_SRC = main.c morse.c dump.c flag.c device/system_stm32f1xx.c
S_SRC = startup/startup_stm32f103xb.s
LDSCRIPT = ld/STM32F103C8_FLASH.ld

INCLUDES = -I. -Icmsis -Idevice

DEFS = -DSTM32F103xB -DHSE_VALUE=8000000U -DFLAG_STRING='"$(FLAG)"'

CPU = -mcpu=cortex-m3 -mthumb

CFLAGS  = $(CPU) $(DEFS) $(INCLUDES) -Os -g3 -std=c11 \
          -Wall -Wextra -Wno-unused-parameter \
          -ffunction-sections -fdata-sections -fno-common
ASFLAGS = $(CPU) -g3
LDFLAGS = $(CPU) -T$(LDSCRIPT) -specs=nano.specs -specs=nosys.specs \
          -Wl,--gc-sections -Wl,-Map=$(BUILD)/$(TARGET).map

OBJ = $(addprefix $(BUILD)/,$(notdir $(C_SRC:.c=.o))) \
      $(addprefix $(BUILD)/,$(notdir $(S_SRC:.s=.o)))
vpath %.c $(sort $(dir $(C_SRC)))
vpath %.s $(sort $(dir $(S_SRC)))

all: $(BUILD)/$(TARGET).bin $(BUILD)/$(TARGET).hex

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: %.c | $(BUILD)
	$(CC) -c $(CFLAGS) -MMD -MP -o $@ $<

$(BUILD)/%.o: %.s | $(BUILD)
	$(CC) -c $(ASFLAGS) -o $@ $<

$(BUILD)/$(TARGET).elf: $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o $@
	$(SIZE) $@

# Pad to the full 64K with 0xFF so the image matches erased flash.
$(BUILD)/$(TARGET).bin: $(BUILD)/$(TARGET).elf
	$(OBJCOPY) -O binary --gap-fill 0xFF --pad-to 0x08010000 $< $@

$(BUILD)/$(TARGET).hex: $(BUILD)/$(TARGET).elf
	$(OBJCOPY) -O ihex $< $@

flash: $(BUILD)/$(TARGET).bin
	st-flash --reset write $< 0x08000000

clean:
	rm -rf $(BUILD)

.PHONY: all flash clean

-include $(wildcard $(BUILD)/*.d)
