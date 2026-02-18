#ifndef _SYS_SYSINFO_H
#define _SYS_SYSINFO_H

#ifdef __cplusplus
extern "C" {
#endif

#define SI_LOAD_SHIFT 16

struct sysinfo {
	unsigned _arch_long uptime;
	unsigned _arch_long loads[3];
	unsigned _arch_long totalram;
	unsigned _arch_long freeram;
	unsigned _arch_long sharedram;
	unsigned _arch_long bufferram;
	unsigned _arch_long totalswap;
	unsigned _arch_long freeswap;
	unsigned short procs, pad;
	unsigned _arch_long totalhigh;
	unsigned _arch_long freehigh;
	unsigned mem_unit;
	char __reserved[256];
};

int sysinfo (struct sysinfo *);
int get_nprocs_conf (void);
int get_nprocs (void);
_arch_long get_phys_pages (void);
_arch_long get_avphys_pages (void);

#ifdef __cplusplus
}
#endif

#endif
