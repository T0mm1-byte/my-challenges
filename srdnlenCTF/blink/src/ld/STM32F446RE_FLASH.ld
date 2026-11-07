/*
 * STM32F446RE (Nucleo-F446RE) - 512K flash, 128K RAM.
 *
 * The F4 flash is organised in sectors (4 x 16K, 1 x 64K, 3 x 128K), not
 * pages, but the image keeps the 64K layout of the original board: the
 * firmware is confined to the first 63K (1K blocks 0..62, the region the
 * dump routine transmits) and the next 1K block, at the top of sector 3, is
 * reserved for the flag. Linking fails if the firmware ever grows into the
 * flag block. Everything above 0x08010000 is left unused.
 *
 * Derived from the STM32F103C8 script, itself based on the Ac6
 * STM32F103XB_FLASH.ld template shipped with cmsis-device-f1.
 */

ENTRY(Reset_Handler)

_estack = 0x20020000;    /* top of 128K SRAM (SRAM1 + SRAM2) */

_Min_Heap_Size  = 0x0;
_Min_Stack_Size = 0x400;

MEMORY
{
  FLASH  (rx)  : ORIGIN = 0x08000000, LENGTH = 63K
  FLAGBLK (r)  : ORIGIN = 0x0800FC00, LENGTH = 1K
  RAM    (xrw) : ORIGIN = 0x20000000, LENGTH = 128K
}

_flash_start   = ORIGIN(FLASH);
_flag_block    = ORIGIN(FLAGBLK);
_dump_blocks   = LENGTH(FLASH) / 1024;

SECTIONS
{
  .isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector))
    . = ALIGN(4);
  } >FLASH

  .text :
  {
    . = ALIGN(4);
    *(.text)
    *(.text*)
    *(.glue_7)
    *(.glue_7t)
    *(.eh_frame)

    KEEP (*(.init))
    KEEP (*(.fini))

    . = ALIGN(4);
    _etext = .;
  } >FLASH

  .rodata :
  {
    . = ALIGN(4);
    *(.rodata)
    *(.rodata*)
    . = ALIGN(4);
  } >FLASH

  .ARM.extab : { *(.ARM.extab* .gnu.linkonce.armextab.*) } >FLASH
  .ARM :
  {
    __exidx_start = .;
    *(.ARM.exidx*)
    __exidx_end = .;
  } >FLASH

  .preinit_array :
  {
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP (*(.preinit_array*))
    PROVIDE_HIDDEN (__preinit_array_end = .);
  } >FLASH
  .init_array :
  {
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT(.init_array.*)))
    KEEP (*(.init_array*))
    PROVIDE_HIDDEN (__init_array_end = .);
  } >FLASH
  .fini_array :
  {
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(SORT(.fini_array.*)))
    KEEP (*(.fini_array*))
    PROVIDE_HIDDEN (__fini_array_end = .);
  } >FLASH

  /* Flag block. Never transmitted by the dump routine. */
  .flag :
  {
    . = ALIGN(4);
    KEEP(*(.flag))
    . = ALIGN(4);
  } >FLAGBLK

  _sidata = LOADADDR(.data);

  .data :
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data)
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } >RAM AT> FLASH

  . = ALIGN(4);
  .bss :
  {
    _sbss = .;
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
    __bss_end__ = _ebss;
  } >RAM

  ._user_heap_stack :
  {
    . = ALIGN(8);
    PROVIDE ( end = . );
    PROVIDE ( _end = . );
    . = . + _Min_Heap_Size;
    . = . + _Min_Stack_Size;
    . = ALIGN(8);
  } >RAM

  .ARM.attributes 0 : { *(.ARM.attributes) }
}
