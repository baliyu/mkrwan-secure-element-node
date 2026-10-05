# Cross-check se_link.c (MKR) against the STM32 project's secure_link.c (Feather).
STM32_SL ?= /mnt/c/stm32/l072_blinky/secure_link
SE       = ../../firmware/se_lora_node
CFLAGS   = -std=c99 -Wall -Wextra -Werror -O2 -I$(STM32_SL) -I$(SE)

crosscheck: crosscheck.c $(SE)/se_link.c
	gcc $(CFLAGS) -o $@ crosscheck.c $(SE)/se_link.c \
	    $(STM32_SL)/secure_link.c $(STM32_SL)/aes128.c $(STM32_SL)/aes_cmac.c

clean:
	rm -f crosscheck
