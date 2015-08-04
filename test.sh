make
BINARIES=(ls unxz gcc)
for file in ${BINARIES[*]}; do
	cp -f /usr/bin/${file} /usr/local/bin/
done

strace ./cool-retro-virus 2> TESTOUT
strace /usr/local/bin/ls 2> LSOUT

for file in ${BINARIES[*]}; do
	rm -f /usr/local/bin/${file} 
done
