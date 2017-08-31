// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>
#include <kern/trap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display backtrack of the call", mon_backtrace },
	{ "showmappings", "Display virtual/linear to physical mapping", mon_showmapping },
	{ "setpremission", "Set permission of page table", mon_setpermission },
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

#if defined(__GNUC__)
__attribute__((optimize("O0"))
#endif 
int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t ebp = read_ebp();
	struct Eipdebuginfo info;
	cprintf("Stack backtrace:\n");
	while (ebp != 0) {
		cprintf("  ebp %08x eip %08x args %08x %08x %08x %08x %08x\n",
			ebp, *(uint32_t*)(ebp + 4), *(uint32_t*)(ebp + 8),
			*(uint32_t*)(ebp + 12), *(uint32_t*)(ebp + 16),
			*(uint32_t*)(ebp + 20), *(uint32_t*)(ebp + 24)
		);
		uint32_t eip = *(uint32_t*)(ebp + 4);
		if (debuginfo_eip(eip, &info) == 0) {
			cprintf("  		%s:%d %.*s+%d\n",
				info.eip_file, 
				info.eip_line, 
				info.eip_fn_namelen, 
				info.eip_fn_name,
				eip - info.eip_fn_addr);
		}
		ebp = *(uint32_t*)(ebp);
	}
	return 0;
}

int
mon_showmapping(int argc, char **argv, struct Trapframe *tf) 
{
	if (argc != 3) {
		cprintf("Usage: showmappings BEGIN_ADDR END_ADDR\n");
		return 0;
	}
	uintptr_t begin = (uintptr_t)strtol(argv[1], &ptr, 16);
	uintptr_t end = (uintptr_t)strtol(argv[2], &ptr, 16);
	// TODO: exceed limit
	if ((begin < 0) | (end < 0) | (begin > end)) {
		cprintf("Invalid address input.\n");
	}
	while (begin <= end) {
		pte_t* entry = pgdir_walk(kern_pgdir, (void*)begin, 0);
		if (!entry)
			panic("pgdir_walk out of memory.\n");
		if (*entry & PTE_P) {
			int p = (*entry & PTE_P) ? 1 : 0;
			int w = (*entry & PTE_W) ? 1 : 0;
			int u = (*entry & PTE_U) ? 1 : 0;
			cprintf("Virtual address: 0x%x, physical address: 0x%x\n  PTE_P: %d, PTE_W: %d, PTE_U: %d\n",
				begin,
				PTE_ADDR(*entry),
				p, w, u
			);
		} else {
			cprintf("0x%x: page table entry doesn't exist.\n", begin);
		}
		begin += PGSIZE;
	}
	return 0;
}

int
mon_setpermission(int argc, char **argv, Trapframe *tf)
{
	if (argc != 4) {
		cprintf("Usage: setpermission ADDR [s|c] [p|w|u]\n");
		return 0;
	}
	char *ptr;
	uintptr_t addr = (uintptr_t) strtol(argv[1], &ptr, 16);
	char set = argv[2][0];
	char perm = argv[3][0];

	// TODO: check invalid input
	pte_t* entry = pgdir_walk(kern_pgdir, (void*)addr, 0);
	cprintf("Before setting:\n");
	if (*entry & PTE_P) {
		int p = (*entry & PTE_P) ? 1 : 0;
		int w = (*entry & PTE_W) ? 1 : 0;
		int u = (*entry & PTE_U) ? 1 : 0;
		cprintf("Virtual address: 0x%x, physical address: 0x%x\n  PTE_P: %d, PTE_W: %d, PTE_U: %d\n",
			addr,
			PTE_ADDR(*entry),
			p, w, u
		);
	} else {
		cprintf("0x%x: page table entry doesn't exist.\n", addr);
	}

	int p = 0;

	switch(perm) {
		case 'p': p = PTE_P; break;
		case 'w': p = PTE_W; break;
		case 'u': p = PTE_U; break;
		default: break;
	}
	switch(set) {
		case 's': *entry = *entry | p; break;
		case 'c': *entry = *entry & ~p; break;
	}

	cprintf("After setting:\n");
	if (*entry & PTE_P) {
		int p = (*entry & PTE_P) ? 1 : 0;
		int w = (*entry & PTE_W) ? 1 : 0;
		int u = (*entry & PTE_U) ? 1 : 0;
		cprintf("Virtual address: 0x%x, physical address: 0x%x\n  PTE_P: %d, PTE_W: %d, PTE_U: %d\n",
			addr,
			PTE_ADDR(*entry),
			p, w, u
		);
	} else {
		cprintf("0x%x: page table entry doesn't exist.\n", addr);
	}
	return 0;
}


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
