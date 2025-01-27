const SYSCALLS = {
    '0': {
        name: 'io_setup',
        x0: 'unsigned nr_reqs',
        x1: 'aio_context_t *ctx',
    },
    '1': { name: 'io_destroy', x0: 'aio_context_t ctx' },
    '2': {
        name: 'io_submit',
        x0: 'aio_context_t',
        x1: 'long',
        x2: 'struct iocb * *',
    },
    '3': {
        name: 'io_cancel',
        x0: 'aio_context_t ctx_id',
        x1: 'struct iocb *iocb',
        x2: 'struct io_event *result',
    },
    '4': {
        name: 'io_getevents',
        x0: 'aio_context_t ctx_id',
        x1: 'long min_nr',
        x2: 'long nr',
        x3: 'struct io_event *events',
        x4: 'struct __kernel_timespec *timeout',
    },
    '5': {
        name: 'setxattr',
        x0: 'const char *path',
        x1: 'const char *name',
        x2: 'const void *value',
        x3: 'size_t size',
        x4: 'int flags',
    },
    '6': {
        name: 'lsetxattr',
        x0: 'const char *path',
        x1: 'const char *name',
        x2: 'const void *value',
        x3: 'size_t size',
        x4: 'int flags',
    },
    '7': {
        name: 'fsetxattr',
        x0: 'int fd',
        x1: 'const char *name',
        x2: 'const void *value',
        x3: 'size_t size',
        x4: 'int flags',
    },
    '8': {
        name: 'getxattr',
        x0: 'const char *path',
        x1: 'const char *name',
        x2: 'void *value',
        x3: 'size_t size',
    },
    '9': {
        name: 'lgetxattr',
        x0: 'const char *path',
        x1: 'const char *name',
        x2: 'void *value',
        x3: 'size_t size',
    },
    '10': {
        name: 'fgetxattr',
        x0: 'int fd',
        x1: 'const char *name',
        x2: 'void *value',
        x3: 'size_t size',
    },
    '11': {
        name: 'listxattr',
        x0: 'const char *path',
        x1: 'char *list',
        x2: 'size_t size',
    },
    '12': {
        name: 'llistxattr',
        x0: 'const char *path',
        x1: 'char *list',
        x2: 'size_t size',
    },
    '13': {
        name: 'flistxattr',
        x0: 'int fd',
        x1: 'char *list',
        x2: 'size_t size',
    },
    '14': {
        name: 'removexattr',
        x0: 'const char *path',
        x1: 'const char *name',
    },
    '15': {
        name: 'lremovexattr',
        x0: 'const char *path',
        x1: 'const char *name',
    },
    '16': { name: 'fremovexattr', x0: 'int fd', x1: 'const char *name' },
    '17': { name: 'getcwd', x0: 'char *buf', x1: 'unsigned long size' },
    '18': {
        name: 'lookup_dcookie',
        x0: 'u64 cookie64',
        x1: 'char *buf',
        x2: 'size_t len',
    },
    '19': { name: 'eventfd2', x0: 'unsigned int count', x1: 'int flags' },
    '20': { name: 'epoll_create1', x0: 'int flags' },
    '21': {
        name: 'epoll_ctl',
        x0: 'int epfd',
        x1: 'int op',
        x2: 'int fd',
        x3: 'struct epoll_event *event',
    },
    '22': {
        name: 'epoll_pwait',
        x0: 'int epfd',
        x1: 'struct epoll_event *events',
        x2: 'int maxevents',
        x3: 'int timeout',
        x4: 'const sigset_t *sigmask',
        x5: 'size_t sigsetsize',
    },
    '23': { name: 'dup', x0: 'unsigned int fildes' },
    '24': {
        name: 'dup3',
        x0: 'unsigned int oldfd',
        x1: 'unsigned int newfd',
        x2: 'int flags',
    },
    '25': {
        name: 'fcntl',
        x0: 'unsigned int fd',
        x1: 'unsigned int cmd',
        x2: 'unsigned long arg',
    },
    '26': { name: 'inotify_init1', x0: 'int flags' },
    '27': {
        name: 'inotify_add_watch',
        x0: 'int fd',
        x1: 'const char *path',
        x2: 'u32 mask',
    },
    '28': { name: 'inotify_rm_watch', x0: 'int fd', x1: '__s32 wd' },
    '29': {
        name: 'ioctl',
        x0: 'unsigned int fd',
        x1: 'unsigned int cmd',
        x2: 'unsigned long arg',
    },
    '30': {
        name: 'ioprio_set',
        x0: 'int which',
        x1: 'int who',
        x2: 'int ioprio',
    },
    '31': { name: 'ioprio_get', x0: 'int which', x1: 'int who' },
    '32': { name: 'flock', x0: 'unsigned int fd', x1: 'unsigned int cmd' },
    '33': {
        name: 'mknodat',
        x0: 'int dfd',
        x1: 'const char * filename',
        x2: 'umode_t mode',
        x3: 'unsigned dev',
    },
    '34': {
        name: 'mkdirat',
        x0: 'int dfd',
        x1: 'const char * pathname',
        x2: 'umode_t mode',
    },
    '35': {
        name: 'unlinkat',
        x0: 'int dfd',
        x1: 'const char * pathname',
        x2: 'int flag',
    },
    '36': {
        name: 'symlinkat',
        x0: 'const char * oldname',
        x1: 'int newdfd',
        x2: 'const char * newname',
    },
    '37': {
        name: 'linkat',
        x0: 'int olddfd',
        x1: 'const char *oldname',
        x2: 'int newdfd',
        x3: 'const char *newname',
        x4: 'int flag',
    },
    '38': {
        name: 'renameat',
        x0: 'int olddfd',
        x1: 'const char * oldname',
        x2: 'int newdfd',
        x3: 'const char * newname',
    },
    '39': { name: 'umount2' },
    '40': {
        name: 'mount',
        x0: 'char *dev_name',
        x1: 'char *dir_name',
        x2: 'char *type',
        x3: 'unsigned long flags',
        x4: 'void *dat',
    },
    '41': {
        name: 'pivot_root',
        x0: 'const char *new_root',
        x1: 'const char *put_old',
    },
    '42': { name: 'nfsservctl' },
    '43': { name: 'statfs', x0: 'const char * path', x1: 'struct statfs *buf' },
    '44': { name: 'fstatfs', x0: 'unsigned int fd', x1: 'struct statfs *buf' },
    '45': { name: 'truncate', x0: 'const char *path', x1: 'long length' },
    '46': {
        name: 'ftruncate',
        x0: 'unsigned int fd',
        x1: 'unsigned long length',
    },
    '47': {
        name: 'fallocate',
        x0: 'int fd',
        x1: 'int mode',
        x2: 'loff_t offset',
        x3: 'loff_t len',
    },
    '48': {
        name: 'faccessat',
        x0: 'int dfd',
        x1: 'const char *filename',
        x2: 'int mode',
    },
    '49': { name: 'chdir', x0: 'const char *filename' },
    '50': { name: 'fchdir', x0: 'unsigned int fd' },
    '51': { name: 'chroot', x0: 'const char *filename' },
    '52': { name: 'fchmod', x0: 'unsigned int fd', x1: 'umode_t mode' },
    '53': {
        name: 'fchmodat',
        x0: 'int dfd',
        x1: 'const char * filename',
        x2: 'umode_t mode',
    },
    '54': {
        name: 'fchownat',
        x0: 'int dfd',
        x1: 'const char *filename',
        x2: 'uid_t user',
        x3: 'gid_t group',
        x4: 'int fla',
    },
    '55': {
        name: 'fchown',
        x0: 'unsigned int fd',
        x1: 'uid_t user',
        x2: 'gid_t group',
    },
    '56': {
        name: 'openat',
        x0: 'int dfd',
        x1: 'const char *filename',
        x2: 'int flags',
        x3: 'umode_t mode',
    },
    '57': { name: 'close', x0: 'unsigned int fd' },
    '58': { name: 'vhangup' },
    '59': { name: 'pipe2', x0: 'int *fildes', x1: 'int flags' },
    '60': {
        name: 'quotactl',
        x0: 'unsigned int cmd',
        x1: 'const char *special',
        x2: 'qid_t id',
        x3: 'void *addr',
    },
    '61': {
        name: 'getdents64',
        x0: 'unsigned int fd',
        x1: 'struct linux_dirent64 *dirent',
        x2: 'unsigned int count',
    },
    '62': {
        name: 'lseek',
        x0: 'unsigned int fd',
        x1: 'off_t offset',
        x2: 'unsigned int whence',
    },
    '63': {
        name: 'read',
        x0: 'unsigned int fd',
        x1: 'char *buf',
        x2: 'size_t count',
    },
    '64': {
        name: 'write',
        x0: 'unsigned int fd',
        x1: 'const char *buf',
        x2: 'size_t count',
    },
    '65': {
        name: 'readv',
        x0: 'unsigned long fd',
        x1: 'const struct iovec *vec',
        x2: 'unsigned long vlen',
    },
    '66': {
        name: 'writev',
        x0: 'unsigned long fd',
        x1: 'const struct iovec *vec',
        x2: 'unsigned long vlen',
    },
    '67': {
        name: 'pread64',
        x0: 'unsigned int fd',
        x1: 'char *buf',
        x2: 'size_t count',
        x3: 'loff_t pos',
    },
    '68': {
        name: 'pwrite64',
        x0: 'unsigned int fd',
        x1: 'const char *buf',
        x2: 'size_t count',
        x3: 'loff_t pos',
    },
    '69': {
        name: 'preadv',
        x0: 'unsigned long fd',
        x1: 'const struct iovec *vec',
        x2: 'unsigned long vlen',
        x3: 'unsigned long pos_l',
        x4: 'unsigned long pos_',
    },
    '70': {
        name: 'pwritev',
        x0: 'unsigned long fd',
        x1: 'const struct iovec *vec',
        x2: 'unsigned long vlen',
        x3: 'unsigned long pos_l',
        x4: 'unsigned long pos_',
    },
    '71': {
        name: 'sendfile',
        x0: 'int out_fd',
        x1: 'int in_fd',
        x2: 'off_t *offset',
        x3: 'size_t count',
    },
    '72': {
        name: 'pselect6',
        x0: 'int',
        x1: 'fd_set *',
        x2: 'fd_set *',
        x3: 'fd_set *',
        x4: 'struct __kernel_timespec *',
        x5: 'void *[',
    },
    '73': {
        name: 'ppoll',
        x0: 'struct pollfd *',
        x1: 'unsigned int',
        x2: 'struct __kernel_timespec *',
        x3: 'const sigset_t *',
        x4: 'size_',
    },
    '74': {
        name: 'signalfd4',
        x0: 'int ufd',
        x1: 'sigset_t *user_mask',
        x2: 'size_t sizemask',
        x3: 'int flags',
    },
    '75': {
        name: 'vmsplice',
        x0: 'int fd',
        x1: 'const struct iovec *iov',
        x2: 'unsigned long nr_segs',
        x3: 'unsigned int flags',
    },
    '76': {
        name: 'splice',
        x0: 'int fd_in',
        x1: 'loff_t *off_in',
        x2: 'int fd_out',
        x3: 'loff_t *off_out',
        x4: 'size_t len',
        x5: 'unsigned int flags[',
    },
    '77': {
        name: 'tee',
        x0: 'int fdin',
        x1: 'int fdout',
        x2: 'size_t len',
        x3: 'unsigned int flags',
    },
    '78': {
        name: 'readlinkat',
        x0: 'int dfd',
        x1: 'const char *path',
        x2: 'char *buf',
        x3: 'int bufsiz',
    },
    '79': {
        name: 'newfstatat',
        x0: 'int dfd',
        x1: 'const char *filename',
        x2: 'struct stat *statbuf',
        x3: 'int flag',
    },
    '80': {
        name: 'fstat',
        x0: 'unsigned int fd',
        x1: 'struct __old_kernel_stat *statbuf',
    },
    '81': { name: 'sync' },
    '82': { name: 'fsync', x0: 'unsigned int fd' },
    '83': { name: 'fdatasync', x0: 'unsigned int fd' },
    '84': {
        name: 'sync_file_range',
        x0: 'int fd',
        x1: 'loff_t offset',
        x2: 'loff_t nbytes',
        x3: 'unsigned int flags',
    },
    '85': { name: 'timerfd_create', x0: 'int clockid', x1: 'int flags' },
    '86': {
        name: 'timerfd_settime',
        x0: 'int ufd',
        x1: 'int flags',
        x2: 'const struct __kernel_itimerspec *utmr',
        x3: 'struct __kernel_itimerspec *otmr',
    },
    '87': {
        name: 'timerfd_gettime',
        x0: 'int ufd',
        x1: 'struct __kernel_itimerspec *otmr',
    },
    '88': {
        name: 'utimensat',
        x0: 'int dfd',
        x1: 'const char *filename',
        x2: 'struct __kernel_timespec *utimes',
        x3: 'int flags',
    },
    '89': { name: 'acct', x0: 'const char *name' },
    '90': {
        name: 'capget',
        x0: 'cap_user_header_t header',
        x1: 'cap_user_data_t dataptr',
    },
    '91': {
        name: 'capset',
        x0: 'cap_user_header_t header',
        x1: 'const cap_user_data_t data',
    },
    '92': { name: 'personality', x0: 'unsigned int personality' },
    '93': { name: 'exit', x0: 'int error_code' },
    '94': { name: 'exit_group', x0: 'int error_code' },
    '95': {
        name: 'waitid',
        x0: 'int which',
        x1: 'pid_t pid',
        x2: 'struct siginfo *infop',
        x3: 'int options',
        x4: 'struct rusage *r',
    },
    '96': { name: 'set_tid_address', x0: 'int *tidptr' },
    '97': { name: 'unshare', x0: 'unsigned long unshare_flags' },
    '98': {
        name: 'futex',
        x0: 'u32 *uaddr',
        x1: 'int op',
        x2: 'u32 val',
        x3: 'struct __kernel_timespec *utime',
        x4: 'u32 *uaddr2',
        x5: 'u32 val3[',
    },
    '99': {
        name: 'set_robust_list',
        x0: 'struct robust_list_head *head',
        x1: 'size_t len',
    },
    '100': {
        name: 'get_robust_list',
        x0: 'int pid',
        x1: 'struct robust_list_head * *head_ptr',
        x2: 'size_t *len_ptr',
    },
    '101': {
        name: 'nanosleep',
        x0: 'struct __kernel_timespec *rqtp',
        x1: 'struct __kernel_timespec *rmtp',
    },
    '102': { name: 'getitimer', x0: 'int which', x1: 'struct itimerval *value' },
    '103': {
        name: 'setitimer',
        x0: 'int which',
        x1: 'struct itimerval *value',
        x2: 'struct itimerval *ovalue',
    },
    '104': {
        name: 'kexec_load',
        x0: 'unsigned long entry',
        x1: 'unsigned long nr_segments',
        x2: 'struct kexec_segment *segments',
        x3: 'unsigned long flags',
    },
    '105': {
        name: 'init_module',
        x0: 'void *umod',
        x1: 'unsigned long len',
        x2: 'const char *uargs',
    },
    '106': {
        name: 'delete_module',
        x0: 'const char *name_user',
        x1: 'unsigned int flags',
    },
    '107': {
        name: 'timer_create',
        x0: 'clockid_t which_clock',
        x1: 'struct sigevent *timer_event_spec',
        x2: 'timer_t * created_timer_id',
    },
    '108': {
        name: 'timer_gettime',
        x0: 'timer_t timer_id',
        x1: 'struct __kernel_itimerspec *setting',
    },
    '109': { name: 'timer_getoverrun', x0: 'timer_t timer_id' },
    '110': {
        name: 'timer_settime',
        x0: 'timer_t timer_id',
        x1: 'int flags',
        x2: 'const struct __kernel_itimerspec *new_setting',
        x3: 'struct __kernel_itimerspec *old_setting',
    },
    '111': { name: 'timer_delete', x0: 'timer_t timer_id' },
    '112': {
        name: 'clock_settime',
        x0: 'clockid_t which_clock',
        x1: 'const struct __kernel_timespec *tp',
    },
    '113': {
        name: 'clock_gettime',
        x0: 'clockid_t which_clock',
        x1: 'struct __kernel_timespec *tp',
    },
    '114': {
        name: 'clock_getres',
        x0: 'clockid_t which_clock',
        x1: 'struct __kernel_timespec *tp',
    },
    '115': {
        name: 'clock_nanosleep',
        x0: 'clockid_t which_clock',
        x1: 'int flags',
        x2: 'const struct __kernel_timespec *rqtp',
        x3: 'struct __kernel_timespec *rmtp',
    },
    '116': { name: 'syslog', x0: 'int type', x1: 'char *buf', x2: 'int len' },
    '117': {
        name: 'ptrace',
        x0: 'long request',
        x1: 'long pid',
        x2: 'unsigned long addr',
        x3: 'unsigned long data',
    },
    '118': {
        name: 'sched_setparam',
        x0: 'pid_t pid',
        x1: 'struct sched_param *param',
    },
    '119': {
        name: 'sched_setscheduler',
        x0: 'pid_t pid',
        x1: 'int policy',
        x2: 'struct sched_param *param',
    },
    '120': { name: 'sched_getscheduler', x0: 'pid_t pid' },
    '121': {
        name: 'sched_getparam',
        x0: 'pid_t pid',
        x1: 'struct sched_param *param',
    },
    '122': {
        name: 'sched_setaffinity',
        x0: 'pid_t pid',
        x1: 'unsigned int len',
        x2: 'unsigned long *user_mask_ptr',
    },
    '123': {
        name: 'sched_getaffinity',
        x0: 'pid_t pid',
        x1: 'unsigned int len',
        x2: 'unsigned long *user_mask_ptr',
    },
    '124': { name: 'sched_yield' },
    '125': { name: 'sched_get_priority_max', x0: 'int policy' },
    '126': { name: 'sched_get_priority_min', x0: 'int policy' },
    '127': {
        name: 'sched_rr_get_interval',
        x0: 'pid_t pid',
        x1: 'struct __kernel_timespec *interval',
    },
    '128': { name: 'restart_syscall' },
    '129': { name: 'kill', x0: 'pid_t pid', x1: 'int sig' },
    '130': { name: 'tkill', x0: 'pid_t pid', x1: 'int sig' },
    '131': { name: 'tgkill', x0: 'pid_t tgid', x1: 'pid_t pid', x2: 'int sig' },
    '132': {
        name: 'sigaltstack',
        x0: 'const struct sigaltstack *uss',
        x1: 'struct sigaltstack *uoss',
    },
    '133': {
        name: 'rt_sigsuspend',
        x0: 'sigset_t *unewset',
        x1: 'size_t sigsetsize',
    },
    '134': {
        name: 'rt_sigaction',
        x0: 'int',
        x1: 'const struct sigaction *',
        x2: 'struct sigaction *',
        x3: 'size_t',
    },
    '135': {
        name: 'rt_sigprocmask',
        x0: 'int how',
        x1: 'sigset_t *set',
        x2: 'sigset_t *oset',
        x3: 'size_t sigsetsize',
    },
    '136': {
        name: 'rt_sigpending',
        x0: 'sigset_t *set',
        x1: 'size_t sigsetsize',
    },
    '137': {
        name: 'rt_sigtimedwait',
        x0: 'const sigset_t *uthese',
        x1: 'siginfo_t *uinfo',
        x2: 'const struct __kernel_timespec *uts',
        x3: 'size_t sigsetsize',
    },
    '138': {
        name: 'rt_sigqueueinfo',
        x0: 'pid_t pid',
        x1: 'int sig',
        x2: 'siginfo_t *uinfo',
    },
    '139': { name: 'rt_sigreturn' },
    '140': {
        name: 'setpriority',
        x0: 'int which',
        x1: 'int who',
        x2: 'int niceval',
    },
    '141': { name: 'getpriority', x0: 'int which', x1: 'int who' },
    '142': {
        name: 'reboot',
        x0: 'int magic1',
        x1: 'int magic2',
        x2: 'unsigned int cmd',
        x3: 'void *arg',
    },
    '143': { name: 'setregid', x0: 'gid_t rgid', x1: 'gid_t egid' },
    '144': { name: 'setgid', x0: 'gid_t gid' },
    '145': { name: 'setreuid', x0: 'uid_t ruid', x1: 'uid_t euid' },
    '146': { name: 'setuid', x0: 'uid_t uid' },
    '147': {
        name: 'setresuid',
        x0: 'uid_t ruid',
        x1: 'uid_t euid',
        x2: 'uid_t suid',
    },
    '148': {
        name: 'getresuid',
        x0: 'uid_t *ruid',
        x1: 'uid_t *euid',
        x2: 'uid_t *suid',
    },
    '149': {
        name: 'setresgid',
        x0: 'gid_t rgid',
        x1: 'gid_t egid',
        x2: 'gid_t sgid',
    },
    '150': {
        name: 'getresgid',
        x0: 'gid_t *rgid',
        x1: 'gid_t *egid',
        x2: 'gid_t *sgid',
    },
    '151': { name: 'setfsuid', x0: 'uid_t uid' },
    '152': { name: 'setfsgid', x0: 'gid_t gid' },
    '153': { name: 'times', x0: 'struct tms *tbuf' },
    '154': { name: 'setpgid', x0: 'pid_t pid', x1: 'pid_t pgid' },
    '155': { name: 'getpgid', x0: 'pid_t pid' },
    '156': { name: 'getsid', x0: 'pid_t pid' },
    '157': { name: 'setsid' },
    '158': { name: 'getgroups', x0: 'int gidsetsize', x1: 'gid_t *grouplist' },
    '159': { name: 'setgroups', x0: 'int gidsetsize', x1: 'gid_t *grouplist' },
    '160': { name: 'uname', x0: 'struct old_utsname *' },
    '161': { name: 'sethostname', x0: 'char *name', x1: 'int len' },
    '162': { name: 'setdomainname', x0: 'char *name', x1: 'int len' },
    '163': {
        name: 'getrlimit',
        x0: 'unsigned int resource',
        x1: 'struct rlimit *rlim',
    },
    '164': {
        name: 'setrlimit',
        x0: 'unsigned int resource',
        x1: 'struct rlimit *rlim',
    },
    '165': { name: 'getrusage', x0: 'int who', x1: 'struct rusage *ru' },
    '166': { name: 'umask', x0: 'int mask' },
    '167': {
        name: 'prctl',
        x0: 'int option',
        x1: 'unsigned long arg2',
        x2: 'unsigned long arg3',
        x3: 'unsigned long arg4',
        x4: 'unsigned long arg5',
    },
    '168': {
        name: 'getcpu',
        x0: 'unsigned *cpu',
        x1: 'unsigned *node',
        x2: 'struct getcpu_cache *cache',
    },
    '169': {
        name: 'gettimeofday',
        x0: 'struct timeval *tv',
        x1: 'struct timezone *tz',
    },
    '170': {
        name: 'settimeofday',
        x0: 'struct timeval *tv',
        x1: 'struct timezone *tz',
    },
    '171': { name: 'adjtimex', x0: 'struct __kernel_timex *txc_p' },
    '172': { name: 'getpid' },
    '173': { name: 'getppid' },
    '174': { name: 'getuid' },
    '175': { name: 'geteuid' },
    '176': { name: 'getgid' },
    '177': { name: 'getegid' },
    '178': { name: 'gettid' },
    '179': { name: 'sysinfo', x0: 'struct sysinfo *info' },
    '180': {
        name: 'mq_open',
        x0: 'const char *name',
        x1: 'int oflag',
        x2: 'umode_t mode',
        x3: 'struct mq_attr *attr',
    },
    '181': { name: 'mq_unlink', x0: 'const char *name' },
    '182': {
        name: 'mq_timedsend',
        x0: 'mqd_t mqdes',
        x1: 'const char *msg_ptr',
        x2: 'size_t msg_len',
        x3: 'unsigned int msg_prio',
        x4: 'const struct __kernel_timespec *abs_timeout',
    },
    '183': {
        name: 'mq_timedreceive',
        x0: 'mqd_t mqdes',
        x1: 'char *msg_ptr',
        x2: 'size_t msg_len',
        x3: 'unsigned int *msg_prio',
        x4: 'const struct __kernel_timespec *abs_timeout',
    },
    '184': {
        name: 'mq_notify',
        x0: 'mqd_t mqdes',
        x1: 'const struct sigevent *notification',
    },
    '185': {
        name: 'mq_getsetattr',
        x0: 'mqd_t mqdes',
        x1: 'const struct mq_attr *mqstat',
        x2: 'struct mq_attr *omqstat',
    },
    '186': { name: 'msgget', x0: 'key_t key', x1: 'int msgflg' },
    '187': {
        name: 'msgctl',
        x0: 'int msqid',
        x1: 'int cmd',
        x2: 'struct msqid_ds *buf',
    },
    '188': {
        name: 'msgrcv',
        x0: 'int msqid',
        x1: 'struct msgbuf *msgp',
        x2: 'size_t msgsz',
        x3: 'long msgtyp',
        x4: 'int msgflg',
    },
    '189': {
        name: 'msgsnd',
        x0: 'int msqid',
        x1: 'struct msgbuf *msgp',
        x2: 'size_t msgsz',
        x3: 'int msgflg',
    },
    '190': {
        name: 'semget',
        x0: 'key_t key',
        x1: 'int nsems',
        x2: 'int semflg',
    },
    '191': {
        name: 'semctl',
        x0: 'int semid',
        x1: 'int semnum',
        x2: 'int cmd',
        x3: 'unsigned long arg',
    },
    '192': {
        name: 'semtimedop',
        x0: 'int semid',
        x1: 'struct sembuf *sops',
        x2: 'unsigned nsops',
        x3: 'const struct __kernel_timespec *timeout',
    },
    '193': {
        name: 'semop',
        x0: 'int semid',
        x1: 'struct sembuf *sops',
        x2: 'unsigned nsops',
    },
    '194': {
        name: 'shmget',
        x0: 'key_t key',
        x1: 'size_t size',
        x2: 'int flag',
    },
    '195': {
        name: 'shmctl',
        x0: 'int shmid',
        x1: 'int cmd',
        x2: 'struct shmid_ds *buf',
    },
    '196': {
        name: 'shmat',
        x0: 'int shmid',
        x1: 'char *shmaddr',
        x2: 'int shmflg',
    },
    '197': { name: 'shmdt', x0: 'char *shmaddr' },
    '198': { name: 'socket', x0: 'int', x1: 'int', x2: 'int' },
    '199': { name: 'socketpair', x0: 'int', x1: 'int', x2: 'int', x3: 'int *' },
    '200': { name: 'bind', x0: 'int', x1: 'struct sockaddr *', x2: 'int' },
    '201': { name: 'listen', x0: 'int', x1: 'int' },
    '202': { name: 'accept', x0: 'int', x1: 'struct sockaddr *', x2: 'int *' },
    '203': { name: 'connect', x0: 'int', x1: 'struct sockaddr *', x2: 'int' },
    '204': {
        name: 'getsockname',
        x0: 'int',
        x1: 'struct sockaddr *',
        x2: 'int *',
    },
    '205': {
        name: 'getpeername',
        x0: 'int',
        x1: 'struct sockaddr *',
        x2: 'int *',
    },
    '206': {
        name: 'sendto',
        x0: 'int',
        x1: 'void *',
        x2: 'size_t',
        x3: 'unsigned',
        x4: 'struct sockaddr *',
        x5: 'int',
    },
    '207': {
        name: 'recvfrom',
        x0: 'int',
        x1: 'void *',
        x2: 'size_t',
        x3: 'unsigned',
        x4: 'struct sockaddr *',
        x5: 'int *',
    },
    '208': {
        name: 'setsockopt',
        x0: 'int fd',
        x1: 'int level',
        x2: 'int optname',
        x3: 'char *optval',
        x4: 'int optlen',
    },
    '209': {
        name: 'getsockopt',
        x0: 'int fd',
        x1: 'int level',
        x2: 'int optname',
        x3: 'char *optval',
        x4: 'int *optlen',
    },
    '210': { name: 'shutdown', x0: 'int', x1: 'int' },
    '211': {
        name: 'sendmsg',
        x0: 'int fd',
        x1: 'struct user_msghdr *msg',
        x2: 'unsigned flags',
    },
    '212': {
        name: 'recvmsg',
        x0: 'int fd',
        x1: 'struct user_msghdr *msg',
        x2: 'unsigned flags',
    },
    '213': {
        name: 'readahead',
        x0: 'int fd',
        x1: 'loff_t offset',
        x2: 'size_t count',
    },
    '214': { name: 'brk', x0: 'unsigned long brk' },
    '215': { name: 'munmap', x0: 'unsigned long addr', x1: 'size_t len' },
    '216': {
        name: 'mremap',
        x0: 'unsigned long addr',
        x1: 'unsigned long old_len',
        x2: 'unsigned long new_len',
        x3: 'unsigned long flags',
        x4: 'unsigned long new_addr',
    },
    '217': {
        name: 'add_key',
        x0: 'const char *_type',
        x1: 'const char *_description',
        x2: 'const void *_payload',
        x3: 'size_t plen',
        x4: 'key_serial_t destringid',
    },
    '218': {
        name: 'request_key',
        x0: 'const char *_type',
        x1: 'const char *_description',
        x2: 'const char *_callout_info',
        x3: 'key_serial_t destringid',
    },
    '219': {
        name: 'keyctl',
        x0: 'int cmd',
        x1: 'unsigned long arg2',
        x2: 'unsigned long arg3',
        x3: 'unsigned long arg4',
        x4: 'unsigned long arg5',
    },
    '220': {
        name: 'clone',
        x0: 'unsigned long',
        x1: 'unsigned long',
        x2: 'int *',
        x3: 'int *',
        x4: 'unsigned long',
    },
    '221': {
        name: 'execve',
        x0: 'const char *filename',
        x1: 'const char *const *argv',
        x2: 'const char *const *envp',
    },
    '222': { name: 'mmap' },
    '223': {
        name: 'fadvise64',
        x0: 'int fd',
        x1: 'loff_t offset',
        x2: 'size_t len',
        x3: 'int advice',
    },
    '224': {
        name: 'swapon',
        x0: 'const char *specialfile',
        x1: 'int swap_flags',
    },
    '225': { name: 'swapoff', x0: 'const char *specialfile' },
    '226': {
        name: 'mprotect',
        x0: 'unsigned long start',
        x1: 'size_t len',
        x2: 'unsigned long prot',
    },
    '227': {
        name: 'msync',
        x0: 'unsigned long start',
        x1: 'size_t len',
        x2: 'int flags',
    },
    '228': { name: 'mlock', x0: 'unsigned long start', x1: 'size_t len' },
    '229': { name: 'munlock', x0: 'unsigned long start', x1: 'size_t len' },
    '230': { name: 'mlockall', x0: 'int flags' },
    '231': { name: 'munlockall' },
    '232': {
        name: 'mincore',
        x0: 'unsigned long start',
        x1: 'size_t len',
        x2: 'unsigned char * vec',
    },
    '233': {
        name: 'madvise',
        x0: 'unsigned long start',
        x1: 'size_t len',
        x2: 'int behavior',
    },
    '234': {
        name: 'remap_file_pages',
        x0: 'unsigned long start',
        x1: 'unsigned long size',
        x2: 'unsigned long prot',
        x3: 'unsigned long pgoff',
        x4: 'unsigned long flags',
    },
    '235': {
        name: 'mbind',
        x0: 'unsigned long start',
        x1: 'unsigned long len',
        x2: 'unsigned long mode',
        x3: 'const unsigned long *nmask',
        x4: 'unsigned long maxnode',
        x5: 'unsigned flags',
    },
    '236': {
        name: 'get_mempolicy',
        x0: 'int *policy',
        x1: 'unsigned long *nmask',
        x2: 'unsigned long maxnode',
        x3: 'unsigned long addr',
        x4: 'unsigned long flags',
    },
    '237': {
        name: 'set_mempolicy',
        x0: 'int mode',
        x1: 'const unsigned long *nmask',
        x2: 'unsigned long maxnode',
    },
    '238': {
        name: 'migrate_pages',
        x0: 'pid_t pid',
        x1: 'unsigned long maxnode',
        x2: 'const unsigned long *from',
        x3: 'const unsigned long *to',
    },
    '239': {
        name: 'move_pages',
        x0: 'pid_t pid',
        x1: 'unsigned long nr_pages',
        x2: 'const void * *pages',
        x3: 'const int *nodes',
        x4: 'int *status',
        x5: 'int flags',
    },
    '240': {
        name: 'rt_tgsigqueueinfo',
        x0: 'pid_t tgid',
        x1: 'pid_t pid',
        x2: 'int sig',
        x3: 'siginfo_t *uinfo',
    },
    '241': {
        name: 'perf_event_open',
        x0: 'struct perf_event_attr *attr_uptr',
        x1: 'pid_t pid',
        x2: 'int cpu',
        x3: 'int group_fd',
        x4: 'unsigned long flags',
    },
    '242': {
        name: 'accept4',
        x0: 'int',
        x1: 'struct sockaddr *',
        x2: 'int *',
        x3: 'int',
    },
    '243': {
        name: 'recvmmsg',
        x0: 'int fd',
        x1: 'struct mmsghdr *msg',
        x2: 'unsigned int vlen',
        x3: 'unsigned flags',
        x4: 'struct __kernel_timespec *timeout',
    },
    '244': { name: 'not implemented' },
    '245': { name: 'not implemented' },
    '246': { name: 'not implemented' },
    '247': { name: 'not implemented' },
    '248': { name: 'not implemented' },
    '249': { name: 'not implemented' },
    '250': { name: 'not implemented' },
    '251': { name: 'not implemented' },
    '252': { name: 'not implemented' },
    '253': { name: 'not implemented' },
    '254': { name: 'not implemented' },
    '255': { name: 'not implemented' },
    '256': { name: 'not implemented' },
    '257': { name: 'not implemented' },
    '258': { name: 'not implemented' },
    '259': { name: 'not implemented' },
    '260': {
        name: 'wait4',
        x0: 'pid_t pid',
        x1: 'int *stat_addr',
        x2: 'int options',
        x3: 'struct rusage *ru',
    },
    '261': {
        name: 'prlimit64',
        x0: 'pid_t pid',
        x1: 'unsigned int resource',
        x2: 'const struct rlimit64 *new_rlim',
        x3: 'struct rlimit64 *old_rlim',
    },
    '262': {
        name: 'fanotify_init',
        x0: 'unsigned int flags',
        x1: 'unsigned int event_f_flags',
    },
    '263': {
        name: 'fanotify_mark',
        x0: 'int fanotify_fd',
        x1: 'unsigned int flags',
        x2: 'u64 mask',
        x3: 'int fd',
        x4: 'const char *pathname',
    },
    '264': {
        name: 'name_to_handle_at',
        x0: 'int dfd',
        x1: 'const char *name',
        x2: 'struct file_handle *handle',
        x3: 'int *mnt_id',
        x4: 'int flag',
    },
    '265': {
        name: 'open_by_handle_at',
        x0: 'int mountdirfd',
        x1: 'struct file_handle *handle',
        x2: 'int flags',
    },
    '266': {
        name: 'clock_adjtime',
        x0: 'clockid_t which_clock',
        x1: 'struct __kernel_timex *tx',
    },
    '267': { name: 'syncfs', x0: 'int fd' },
    '268': { name: 'setns', x0: 'int fd', x1: 'int nstype' },
    '269': {
        name: 'sendmmsg',
        x0: 'int fd',
        x1: 'struct mmsghdr *msg',
        x2: 'unsigned int vlen',
        x3: 'unsigned flags',
    },
    '270': {
        name: 'process_vm_readv',
        x0: 'pid_t pid',
        x1: 'const struct iovec *lvec',
        x2: 'unsigned long liovcnt',
        x3: 'const struct iovec *rvec',
        x4: 'unsigned long riovcnt',
        x5: 'unsigned long flags',
    },
    '271': {
        name: 'process_vm_writev',
        x0: 'pid_t pid',
        x1: 'const struct iovec *lvec',
        x2: 'unsigned long liovcnt',
        x3: 'const struct iovec *rvec',
        x4: 'unsigned long riovcnt',
        x5: 'unsigned long flags',
    },
    '272': {
        name: 'kcmp',
        x0: 'pid_t pid1',
        x1: 'pid_t pid2',
        x2: 'int type',
        x3: 'unsigned long idx1',
        x4: 'unsigned long idx2',
    },
    '273': {
        name: 'finit_module',
        x0: 'int fd',
        x1: 'const char *uargs',
        x2: 'int flags',
    },
    '274': {
        name: 'sched_setattr',
        x0: 'pid_t pid',
        x1: 'struct sched_attr *attr',
        x2: 'unsigned int flags',
    },
    '275': {
        name: 'sched_getattr',
        x0: 'pid_t pid',
        x1: 'struct sched_attr *attr',
        x2: 'unsigned int size',
        x3: 'unsigned int flags',
    },
    '276': {
        name: 'renameat2',
        x0: 'int olddfd',
        x1: 'const char *oldname',
        x2: 'int newdfd',
        x3: 'const char *newname',
        x4: 'unsigned int flags',
    },
    '277': {
        name: 'seccomp',
        x0: 'unsigned int op',
        x1: 'unsigned int flags',
        x2: 'void *uargs',
    },
    '278': {
        name: 'getrandom',
        x0: 'char *buf',
        x1: 'size_t count',
        x2: 'unsigned int flags',
    },
    '279': {
        name: 'memfd_create',
        x0: 'const char *uname_ptr',
        x1: 'unsigned int flags',
    },
    '280': {
        name: 'bpf',
        x0: 'int cmd',
        x1: 'union bpf_attr *attr',
        x2: 'unsigned int size',
    },
    '281': {
        name: 'execveat',
        x0: 'int dfd',
        x1: 'const char *filename',
        x2: 'const char *const *argv',
        x3: 'const char *const *envp',
        x4: 'int flags',
    },
    '282': { name: 'userfaultfd', x0: 'int flags' },
    '283': { name: 'membarrier', x0: 'int cmd', x1: 'int flags' },
    '284': {
        name: 'mlock2',
        x0: 'unsigned long start',
        x1: 'size_t len',
        x2: 'int flags',
    },
    '285': {
        name: 'copy_file_range',
        x0: 'int fd_in',
        x1: 'loff_t *off_in',
        x2: 'int fd_out',
        x3: 'loff_t *off_out',
        x4: 'size_t len',
        x5: 'unsigned int flags',
    },
    '286': {
        name: 'preadv2',
        x0: 'unsigned long fd',
        x1: 'const struct iovec *vec',
        x2: 'unsigned long vlen',
        x3: 'unsigned long pos_l',
        x4: 'unsigned long pos_h',
        x5: 'rwf_t flags',
    },
    '287': {
        name: 'pwritev2',
        x0: 'unsigned long fd',
        x1: 'const struct iovec *vec',
        x2: 'unsigned long vlen',
        x3: 'unsigned long pos_l',
        x4: 'unsigned long pos_h',
        x5: 'rwf_t flags',
    },
    '288': {
        name: 'pkey_mprotect',
        x0: 'unsigned long start',
        x1: 'size_t len',
        x2: 'unsigned long prot',
        x3: 'int pkey',
    },
    '289': {
        name: 'pkey_alloc',
        x0: 'unsigned long flags',
        x1: 'unsigned long init_val',
    },
    '290': { name: 'pkey_free', x0: 'int pkey' },
    '291': {
        name: 'statx',
        x0: 'int dfd',
        x1: 'const char *path',
        x2: 'unsigned flags',
        x3: 'unsigned mask',
        x4: 'struct statx *buffer',
    },
};

export { SYSCALLS };
