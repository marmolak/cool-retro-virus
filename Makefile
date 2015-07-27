all:
	gcc -fomit-frame-pointer -nostdlib -fPIE -fPIC -o cool-retro-virus cool-retro-virus.c
