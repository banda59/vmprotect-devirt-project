#define SHMLBA 4096

struct shmid_ds {
	struct ipc_perm shm_perm;
	size_t shm_segsz;
	time_t shm_atime;
	time_t shm_dtime;
	time_t shm_ctime;
	pid_t shm_cpid;
	pid_t shm_lpid;
	unsigned _arch_long shm_nattch;
	unsigned _arch_long __pad1;
	unsigned _arch_long __pad2;
};

struct shminfo {
	unsigned _arch_long shmmax, shmmin, shmmni, shmseg, shmall, __unused[4];
};

struct shm_info {
	int __used_ids;
	unsigned _arch_long shm_tot, shm_rss, shm_swp;
	unsigned _arch_long __swap_attempts, __swap_successes;
};
