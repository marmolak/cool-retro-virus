all:
	gcc -O0 -std=gnu99 -ffreestanding -fomit-frame-pointer -nostdlib -fPIE -fPIC -o cool-retro-virus cool-retro-virus.c
