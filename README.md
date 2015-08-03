```
   _________  ____  / /     ________  / /__________       _   __(_)______  _______
  / ___/ __ \/ __ \/ /_____/ ___/ _ \/ __/ ___/ __ \_____| | / / / ___/ / / / ___/
 / /__/ /_/ / /_/ / /_____/ /  /  __/ /_/ /  / /_/ /_____/ |/ / / /  / /_/ (__  ) 
 \___/\____/\____/_/     /_/   \___/\__/_/   \____/      |___/_/_/   \__,_/____/  
                  	   ==='\ by m4rm0l4k /' ==
                                                                                 

Experimets with ELF infection. EDUCATION PURPOSES ONLY!

Used tools:
	OS: Fedora 21
	Compilers: gcc-4.9.2-6, nasm-2.11.05-3
	Debugger: gdb-7.8.2-39
	Others: binutils-2.24-32

NOTE: I tested this virus on Fedora 20 with gcc 4.8.3 and it generates code which touch
sections behind .text.
Also it looks that it doesn't work on Fedora 20 binaries either (tested on ls).
Infected binaries looks crippled in gdb and segfaults after start.

Why?

When I was young I has been amazed by viruses.
[OneHalf](https://en.wikipedia.org/wiki/OneHalf) were one of my favorite.

I remember how I played with resident AVG virus protection on i386 machine and
I decided which files will be infected... born to be wild :).
