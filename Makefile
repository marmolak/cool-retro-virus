all:
	gcc -ftree-sra -ftree-ter -ftree-phiprop -ftree-fre -ftree-dse -ftree-copyrename -fipa-profile -fguess-branch-probability -DDEBUG -fipa-reference -fdefer-pop -fipa-pure-const -fbranch-count-reg -fdse -finline-functions-called-once -fmerge-constants -fauto-inc-dec -fcompare-elim -fcombine-stack-adjustments -fif-conversion2 -fif-conversion -std=gnu99 -ffreestanding -fomit-frame-pointer -nostdlib -fPIE -fPIC -o cool-retro-virus cool-retro-virus.c

test:
	./test.sh
