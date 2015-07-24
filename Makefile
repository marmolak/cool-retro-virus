all:
	clang -fomit-frame-pointer -nostdlib -fPIE -fPIC -o cool-retro-virus cool-retro-virus.c
