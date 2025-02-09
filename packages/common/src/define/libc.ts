import { type PropertyCallbackMapper, proxyCallback } from '../internal/proxy.js';

const LibcFinder = {
    // int open(const char *pathname, int flags);
    open: () => {
        const ptr = Module.getExportByName('libc.so', 'open');
        return new SystemFunction(ptr, 'int', ['pointer', 'int']);
    },
    // int fileno(FILE *stream);
    fileno: () => {
        const ptr = Module.getExportByName('libc.so', 'fileno');
        return new SystemFunction(ptr, 'int', ['pointer']);
    },
    // ssize_t write(int fd, const void *buf, size_t count);
    write: () => {
        const ptr = Module.getExportByName('libc.so', 'write');
        return new SystemFunction(ptr, 'int', ['int', 'pointer', 'int']);
    },
    // int creat(const char *pathname, mode_t mode);
    creat: () => {
        const ptr = Module.getExportByName('libc.so', 'creat');
        return new NativeFunction(ptr, 'int', ['pointer', 'int']);
    },
    // int openat(int dirfd, const char *pathname, int flags);
    openat: () => {
        const ptr = Module.getExportByName('libc.so', 'openat');
        return new NativeFunction(ptr, 'int', ['int', 'pointer', 'int', '...']);
    },
    // int close(int fd);
    close: () => {
        const ptr = Module.getExportByName('libc.so', 'close');
        return new NativeFunction(ptr, 'int', ['int']);
    },
    // int close(int fd);
    fclose: () => {
        const ptr = Module.getExportByName('libc.so', 'fclose');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int shutdown(int sockfd, int how);
    shutdown: () => {
        const ptr = Module.getExportByName('libc.so', 'shutdown');
        return new NativeFunction(ptr, 'int', ['int', 'int']);
    },
    mkdir: () => {
        const ptr = Module.getExportByName('libc.so', 'mkdir');
        return new NativeFunction(ptr, 'int', ['pointer', 'int']);
    },
    // DIR *opendir(const char *name);
    opendir: () => {
        const ptr = Module.getExportByName('libc.so', 'opendir');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    // DIR *fdopendir(int fd);
    fdopendir: () => {
        const ptr = Module.getExportByName('libc.so', 'fdopendir');
        return new NativeFunction(ptr, 'pointer', ['int']);
    },
    // struct dirent *readdir(DIR *dirp);
    readdir: () => {
        const ptr = Module.getExportByName('libc.so', 'readdir');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    closedir: () => {
        const ptr = Module.getExportByName('libc.so', 'closedir');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    telldir: () => {
        const ptr = Module.getExportByName('libc.so', 'telldir');
        return new NativeFunction(ptr, 'void', ['pointer']);
    },
    seekdir: () => {
        const ptr = Module.getExportByName('libc.so', 'seekdir');
        return new NativeFunction(ptr, 'void', ['pointer', 'long']);
    },
    scandir: () => {
        const ptr = Module.getExportByName('libc.so', 'scandir');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
    },
    // ssize_t readlink(const char *path, char *buf, size_t bufsiz);
    readlink: () => {
        const ptr = Module.getExportByName('libc.so', 'readlink');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'int']);
    },
    // int readlinkat(int dirfd, char *pathname, char *buf, size_t bufsiz);
    readlinkat: () => {
        const ptr = Module.getExportByName('libc.so', 'readlinkat');
        return new NativeFunction(ptr, 'int', ['int', 'pointer', 'pointer', 'size_t']);
    },
    // ssize_t pread(int fd, void buf[.count], size_t count);
    read: () => {
        const ptr = Module.getExportByName('libc.so', 'read');
        return new NativeFunction(ptr, 'uint', ['int', 'pointer', 'size_t']);
    },
    // ssize_t pread(int fd, void *buf, size_t count, off_t offset);
    pread: () => {
        const ptr = Module.getExportByName('libc.so', 'pread');
        return new NativeFunction(ptr, 'uint', ['int', 'pointer', 'size_t', 'int']);
    },
    // off_t lseek(int fd, off_t offset, int whence);
    lseek: () => {
        const ptr = Module.getExportByName('libc.so', 'lseek');
        return new NativeFunction(ptr, 'pointer', ['int', 'pointer', 'int']);
    },
    // FILE *fopen(const char *restrict pathname, const char *restrict mode);
    fopen: () => {
        const ptr = Module.getExportByName('libc.so', 'fopen');
        return new SystemFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // FILE *fopen(const char *restrict pathname, const char *restrict mode);
    open64: () => {
        const ptr = Module.getExportByName(null, 'open64');
        return new SystemFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // FILE *fopen(const char *restrict pathname, const char *restrict mode);
    fopen64: () => {
        const ptr = Module.getExportByName(null, 'fopen64');
        return new SystemFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // FILE *fdopen(int fd, const char *mode);
    fdopen: () => {
        const ptr = Module.getExportByName('libc.so', 'fdopen');
        return new SystemFunction(ptr, 'pointer', ['int', 'pointer']);
    },
    // FILE *freopen(const char *restrict pathname, const char *restrict mode, FILE *restrict stream);
    freopen: () => {
        const ptr = Module.getExportByName('libc.so', 'freopen');
        return new SystemFunction(ptr, 'pointer', ['pointer', 'pointer', 'pointer']);
    },
    chmod: () => {
        const ptr = Module.getExportByName('libc.so', 'chmod');
        return new NativeFunction(ptr, 'int', ['pointer', 'int']);
    },
    // int access(const char *pathname, int mode);
    access: () => {
        const ptr = Module.getExportByName('libc.so', 'access');
        return new NativeFunction(ptr, 'int', ['pointer', 'int']);
    },
    // int faccessat(int fd, const char *path, int amode, int flag);
    faccessat: () => {
        const ptr = Module.getExportByName('libc.so', 'faccessat');
        return new NativeFunction(ptr, 'int', ['int', 'pointer', 'int', 'int']);
    },
    // int fcntl(int fd, int op, ... /* arg */ );
    fcntl: () => {
        const ptr = Module.getExportByName('libc.so', 'fcntl');
        return new NativeFunction(ptr, 'int', ['int', 'int', '...']);
    },
    // int pthread_create(pthread_t *restrict thread, const pthread_attr_t *restrict attr, void *(*start_routine)(void *), void *restrict arg);
    pthread_create: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_create');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
    },
    // pthread_t pthread_self(void);
    pthread_self: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_self');
        return new NativeFunction(ptr, 'pointer', []);
    },
    // int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr);
    pthread_getattr_np: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_getattr_np');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int pthread_join(pthread_t thread, void **retval);
    pthread_join: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_join');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int pthread_gettid_np(pthread_t *thread);
    pthread_gettid_np: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_gettid_np');
        return new NativeFunction(ptr, 'uint', ['pointer']);
    },
    // int pthread_getname_np(pthread_t *thread, const char * name, size_t len);
    pthread_getname_np: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_getname_np');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'size_t']);
    },
    // void *malloc(size_t size);
    malloc: () => {
        const ptr = Module.getExportByName('libc.so', 'malloc');
        return new NativeFunction(ptr, 'pointer', ['size_t']);
    },
    // int prctl(int __option, ...)
    prctl: () => {
        const ptr = Module.getExportByName('libc.so', 'prctl');
        return new NativeFunction(ptr, 'int', ['int', '...']);
    },
    // void free(void *ptr);
    free: () => {
        const ptr = Module.getExportByName('libc.so', 'free');
        return new NativeFunction(ptr, 'int', []);
    },
    // int rand();
    rand: () => {
        const ptr = Module.getExportByName('libc.so', 'rand');
        return new NativeFunction(ptr, 'int', []);
    },
    // double difftime(time_t __time1, time_t __time0)
    difftime: () => {
        const ptr = Module.getExportByName('libc.so', 'difftime');
        return new NativeFunction(ptr, 'double', ['pointer', 'pointer']);
    },
    // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    connect: () => {
        const ptr = Module.getExportByName('libc.so', 'connect');
        return new NativeFunction(ptr, 'int', ['int', 'pointer', 'pointer']);
    },
    // int __system_property_get(const char *name, char *value);
    __system_property_get: () => {
        const ptr = Module.getExportByName('libc.so', '__system_property_get');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int __system_property_read( const prop_info *pi, char *name, char * value);
    __system_property_read: () => {
        const ptr = Module.getExportByName('libc.so', '__system_property_read');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'pointer']);
    },
    // propinfo * __system_property_find(char * name);
    __system_property_find: (name: string) => {
        const ptr = Module.getExportByName('libc.so', '__system_property_find');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    // propinfo * __system_property_find_nth(i: number);
    __system_property_find_nth: (i: number) => {
        const ptr = Module.getExportByName('libc.so', '__system_property_find_nth');
        return new NativeFunction(ptr, 'pointer', ['int']);
    },
    // struct hostent *gethostbyname(const char *name);
    gethostbyname: () => {
        const ptr = Module.getExportByName('libc.so', 'gethostbyname');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    // int getaddrinfo(const char *restrict node,
    //                const char *restrict service,
    //                const struct addrinfo *restrict hints,
    //                struct addrinfo **restrict res);
    getaddrinfo: () => {
        const ptr = Module.getExportByName('libc.so', 'getaddrinfo');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
    },
    // int inet_aton(const char *cp, struct in_addr *addr);
    inet_aton: () => {
        const ptr = Module.getExportByName('libc.so', 'inet_aton');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int inet_addr(const char *cp, struct in_addr *addr);
    inet_addr: () => {
        const ptr = Module.getExportByName('libc.so', 'inet_addr');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },

    // pid_t fork(void);
    fork: () => {
        const ptr = Module.getExportByName('libc.so', 'fork');
        return new NativeFunction(ptr, 'int', []);
    },
    // int execv(const char *path, char *const argv[]);
    execv: () => {
        const ptr = Module.getExportByName('libc.so', 'execv');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    //int dladdr(const void *addr, Dl_info *info);
    dladdr: () => {
        const ptr = Module.getExportByName('libc.so', 'dladdr');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // void *dlopen(const char *filename, int flags);
    dlopen: () => {
        const ptr = Module.getExportByName('libc.so', 'dlopen');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'int']);
    },
    // void *dlsym(void *restrict handle, const char *restrict symbol);
    dlsym: () => {
        const ptr = Module.getExportByName('libc.so', 'dlsym');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // int dlclose(void *handle);
    dlclose: () => {
        const ptr = Module.getExportByName('libc.so', 'dlclose');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    //void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset);
    mmap: () => {
        const ptr = Module.getExportByName('libc.so', 'mmap');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'size_t', 'int', 'int', 'uint', 'long']);
    },
    // int munmap(void *addr, size_t length);
    munmap: () => {
        const ptr = Module.getExportByName('libc.so', 'munmap');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'size_t']);
    },
    // void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
    mremap: () => {
        const ptr = Module.getExportByName('libc.so', 'mremap');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'size_t', 'size_t', 'int', 'pointer']);
    },
    // int mprotect(void *addr, size_t len, int prot);
    mprotect: () => {
        const ptr = Module.getExportByName('libc.so', 'mprotect');
        return new SystemFunction(ptr, 'int', ['pointer', 'size_t', 'int']);
    },
    // int gettimeofday(struct timeval *restrict tv, struct timezone *_Nullable restrict tz);
    gettimeofday: () => {
        const ptr = Module.getExportByName('libc.so', 'gettimeofday');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
    pthread_mutex_init: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_mutex_init');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int pthread_mutex_lock(pthread_mutex_t *mutex);
    pthread_mutex_lock: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_mutex_lock');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int pthread_mutex_unlock(pthread_mutex_t *mutex);
    pthread_mutex_unlock: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_mutex_unlock');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int pthread_detach(pthread_t thread);
    pthread_detach: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_detach');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // char *strstr(const char *haystack, const char *needle);
    strstr: () => {
        const ptr = Module.getExportByName('libc.so', 'strstr');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // char *strcasestr(const char *haystack, const char *needle);
    strcasestr: () => {
        const ptr = Module.getExportByName('libc.so', 'strcasestr');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // size_t *strlen(const char *str);
    strlen: () => {
        const ptr = Module.getExportByName('libc.so', 'strlen');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int strcmp(const char *s1, const char *s2);
    strcmp: () => {
        const ptr = Module.getExportByName('libc.so', 'strcmp');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int strncmp(const char *s1, const char *s2);
    strncmp: () => {
        const ptr = Module.getExportByName('libc.so', 'strncmp');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int strcasecmp(const char *s1, const char *s2);
    strcasecmp: () => {
        const ptr = Module.getExportByName('libc.so', 'strcasecmp');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // char *stpcpy(char *restrict dst, const char *restrict src);
    stpcpy: () => {
        const ptr = Module.getExportByName('libc.so', 'stpcpy');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // char *strcpy(char *restrict dst, const char *restrict src);
    strcpy: () => {
        const ptr = Module.getExportByName('libc.so', 'strcpy');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // char *strcpy(char *restrict dst, const char *restrict src);
    strncpy: () => {
        const ptr = Module.getExportByName('libc.so', 'strncpy');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'size_t']);
    },
    // char *strchr(char * str, int character);
    strchr: () => {
        const ptr = Module.getExportByName('libc.so', 'strchr');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'int']);
    },
    // char *strchr(char * str, int character);
    strrchr: () => {
        const ptr = Module.getExportByName('libc.so', 'strrchr');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'int']);
    },
    // char *strcat(char *restrict dst, char *restrict src);
    strcat: () => {
        const ptr = Module.getExportByName('libc.so', 'strcat');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    //  char *fgets(char *restrict s, int n, FILE *restrict stream);
    fgets: () => {
        const ptr = Module.getExportByName('libc.so', 'fgets');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'int', 'pointer']);
    },
    //  char *fgets_unlocked(char *restrict s, int n, FILE *restrict stream);
    fgets_unlocked: () => {
        const ptr = Module.getExportByName('libc.so', 'fgets_unlocked');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'int', 'pointer']);
    },
    //  int fstat(int fd, struct stat *statbuf);
    stat: () => {
        const ptr = Module.getExportByName('libc.so', 'stat');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    //  int fstat(int fd, struct stat *statbuf);
    fstat: () => {
        const ptr = Module.getExportByName('libc.so', 'fstat');
        return new NativeFunction(ptr, 'int', ['int', 'pointer']);
    },
    //  int fstat(int fd, struct stat *statbuf);
    lstat: () => {
        const ptr = Module.getExportByName('libc.so', 'lstat');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int __statfs64(const char *, size_t, struct statfs *);
    __statfs64: () => {
        const ptr = Module.getExportByName('libc.so', '__statfs64');
        return new NativeFunction(ptr, 'int', ['pointer', 'int', 'pointer']);
    },
    // time_t time(time_t *t);
    time: () => {
        const ptr = Module.getExportByName('libc.so', 'time');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    // struct tm *localtime(const time_t *timep);
    localtime: () => {
        const ptr = Module.getExportByName('libc.so', 'localtime');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    // ssize_t getline(char **restrict lineptr, size_t *restrict n, FILE *restrict stream);
    getline: () => {
        const ptr = Module.getExportByName('libc.so', 'getline');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'int']);
    },
    // int sscanf(const char *restrict str, const char *restrict format, ...);
    sscanf: () => {
        const ptr = Module.getExportByName('libc.so', 'sscanf');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', '...']);
    },
    // FILE *popen(const char *command, const char *type);
    popen: () => {
        const ptr = Module.getExportByName('libc.so', 'popen');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // FILE *pclose(FD);
    pclose: () => {
        const ptr = Module.getExportByName('libc.so', 'pclose');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // pid_t getpid(void);
    getpid: () => {
        const ptr = Module.getExportByName('libc.so', 'getpid');
        return new NativeFunction(ptr, 'pointer', []);
    },
    // int remove(const char *pathname);
    remove: () => {
        const ptr = Module.getExportByName('libc.so', 'remove');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int unlink(const char *pathname);
    unlink: () => {
        const ptr = Module.getExportByName('libc.so', 'unlink');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // [[noretunr]] void exit(int status);
    exit: () => {
        const ptr = Module.getExportByName('libc.so', 'exit');
        return new NativeFunction(ptr, 'void', ['int']);
    },
    // [[noretunr]] void exit(int status);
    _exit: () => {
        const ptr = Module.getExportByName('libc.so', '_exit');
        return new NativeFunction(ptr, 'void', ['int']);
    },
    // [[noretunr]] void abort(int status);
    abort: () => {
        const ptr = Module.getExportByName('libc.so', 'abort');
        return new NativeFunction(ptr, 'void', ['int']);
    },
    // [[noretunr]] void abort(int status);
    raise: () => {
        const ptr = Module.getExportByName('libc.so', 'raise');
        return new NativeFunction(ptr, 'int', ['int']);
    },
    // int rcx(pid_t pid, int sig);
    kill: () => {
        const ptr = Module.getExportByName('libc.so', 'kill');
        return new NativeFunction(ptr, 'int', ['pointer', 'int']);
    },
    // long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
    ptrace: () => {
        const ptr = Module.getExportByName('libc.so', 'ptrace');
        return new NativeFunction(ptr, 'long', ['int', 'int', 'pointer', 'pointer']);
    },
    // int system(const char *command);
    system: () => {
        const ptr = Module.getExportByName('libc.so', 'system');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int system(const char *command);
    strerror: () => {
        const ptr = Module.getExportByName('libc.so', 'strerror');
        return new NativeFunction(ptr, 'pointer', ['int']);
    },
    // int sprintf ( char * str, const char * format, ... );
    sprintf: () => {
        const ptr = Module.getExportByName('libc.so', 'sprintf');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', '...']);
    },
    // int vsnprintf (char * s, size_t n, const char * format, va_list arg );
    vsnprintf: () => {
        const ptr = Module.getExportByName('libc.so', 'vsnprintf');
        return new NativeFunction(ptr, 'int', ['pointer', 'int', 'pointer']);
    },
    // long int atol ( const char * str );
    atoi: () => {
        const ptr = Module.getExportByName('libc.so', 'atol');
        return new NativeFunction(ptr, 'long', ['pointer']);
    },
    // int atoi (const char * str);
    atol: () => {
        const ptr = Module.getExportByName('libc.so', 'atoi');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int isprint (int ch);
    isprint: () => {
        const ptr = Module.getExportByName('libc.so', 'isprint');
        return new NativeFunction(ptr, 'int', ['int']);
    },
    // long int strtol (const char* str, char** endptr, int base);
    strtol: () => {
        const ptr = Module.getExportByName('libc.so', 'strtol');
        return new NativeFunction(ptr, 'int32', ['pointer', 'pointer', 'int']);
    },
    // unsigned long int strtoul (const char* str, char** endptr, int base);
    strtoul: () => {
        const ptr = Module.getExportByName('libc.so', 'strtoul');
        return new NativeFunction(ptr, 'uint32', ['pointer', 'pointer', 'int']);
    },
    // long long int strtoll (const char* str, char** endptr, int base);
    strtoll: () => {
        const ptr = Module.getExportByName('libc.so', 'strtoll');
        return new NativeFunction(ptr, 'int64', ['pointer', 'pointer', 'int']);
    },
    // unsigned long long int strtoull (const char* str, char** endptr, int base);
    strtoull: () => {
        const ptr = Module.getExportByName('libc.so', 'strtoull');
        return new NativeFunction(ptr, 'uint64', ['pointer', 'pointer', 'int']);
    },
    // char *strtok(char *str, const char *delim);
    strtok: () => {
        const ptr = Module.getExportByName('libc.so', 'strtok');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // char *strtok_r(char *str, const char *delim, char **saveptr)));
    strtok_r: () => {
        const ptr = Module.getExportByName('libc.so', 'strtok_r');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'pointer']);
    },
    // char * strdup(const char *str1);
    strdup: () => {
        const ptr = Module.getExportByName('libc.so', 'strdup');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    // void* memcpy( void* dest, const void* src, std::size_t count );
    memcpy: () => {
        const ptr = Module.getExportByName('libc.so', 'memcpy');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'int']);
    },
    // int memcmp (const void * ptr1, const void * ptr2, size_t num);
    memcmp: () => {
        const ptr = Module.getExportByName('libc.so', 'memcmp');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'int']);
    },
    // void *memmove(void * destination, const void * source, size_t num);
    memmove: () => {
        const ptr = Module.getExportByName('libc.so', 'memmove');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'int']);
    },
    // void * memset (void * __s, int __c, size_t __n);
    memset: () => {
        const ptr = Module.getExportByName('libc.so', 'memset');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'int', 'size_t']);
    },
    // unsigned long getauxval(unsigned long type);
    getauxval: () => {
        const ptr = Module.getExportByName('libc.so', 'getauxval');
        return new NativeFunction(ptr, 'uint32', ['uint32']);
    },
    // int posix_spawn(pid_t *restrict pid, const char *restrict path,
    //                 const posix_spawn_file_actions_t *restrict file_actions,
    //                 const po six_spawnattr_t *restrict attrp,
    //                 char *const argv[restrict],
    //                 char *const envp[restrict]);
    posix_spawn: () => {
        const ptr = Module.getExportByName('libc.so', 'posix_spawn');
        return new NativeFunction(ptr, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']);
    },
    // long syscall(long number, ...);
    syscall: () => {
        const ptr = Module.getExportByName('libc.so', 'syscall');
        return new NativeFunction(ptr, 'int32', ['int32', '...']);
    },
    // may be stupid
    syscall_openat: () => {
        const ptr = Module.getExportByName('libc.so', 'syscall');
        return new NativeFunction(ptr, 'int', ['int', 'int', 'pointer', 'char']);
    },
    syscall_read: () => {
        const ptr = Module.getExportByName('libc.so', 'syscall');
        return new NativeFunction(ptr, 'int', ['int', 'int', 'pointer', 'size_t']);
    },
    // __sighandler_t signal(int __sig,__sighandler_t __handler);
    perror: () => {
        const ptr = Module.getExportByName('libc.so', 'perror');
        return new NativeFunction(ptr, 'void', ['pointer']);
    },
    // __sighandler_t signal(int __sig,__sighandler_t __handler);
    signal: () => {
        const ptr = Module.getExportByName('libc.so', 'signal');
        return new NativeFunction(ptr, 'pointer', ['int', 'pointer']);
    },
    // int nanosleep(const struct timespec *duration, timespec *_Nullable rem);
    nanosleep: () => {
        const ptr = Module.getExportByName('libc.so', 'nanosleep');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // char *getenv(const char *name);
    getenv: () => {
        const ptr = Module.getExportByName('libc.so', 'getenv');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    // char *setenv(const char *name, char *value);
    setenv: () => {
        const ptr = Module.getExportByName('libc.so', 'setenv');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // int dl_iterate_phdr(typeof(int (struct dl_phdr_info *info, size_t size, void *data)) *callback, void *data);
    dl_iterate_phdr: () => {
        const ptr = Module.getExportByName('libc.so', 'dl_iterate_phdr');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // char * __cxa_demangle (const char *mangled_name, char *output_buffer, size_t *length, int *status)
    __cxa_demangle: () => {
        // const pt  = Module.getExportByName('libunwindstack.so', '__cxa_demangle');
        const ptr = DebugSymbol.fromName('__cxa_demangle').address;
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
    },
};

type LibcType = PropertyCallbackMapper<typeof LibcFinder>;
const LibcFinderProxy: LibcType = proxyCallback(LibcFinder);
export { LibcFinderProxy, type LibcType };
