import { type PropertyCallbackMapper, proxyCallback } from '../internal/proxy.js';

const LibcFinder = {
  // int open(const char *pathname, int flags);
  open: () => {
    const ptr = Module.getGlobalExportByName('open');
    return new SystemFunction(ptr, 'int', ['pointer', 'int']);
  },
  // int fileno(FILE *stream);
  fileno: () => {
    const ptr = Module.getGlobalExportByName('fileno');
    return new SystemFunction(ptr, 'int', ['pointer']);
  },
  // ssize_t write(int fd, const void *buf, size_t count);
  write: () => {
    const ptr = Module.getGlobalExportByName('write');
    return new SystemFunction(ptr, 'int', ['int', 'pointer', 'int']);
  },
  // int creat(const char *pathname, mode_t mode);
  creat: () => {
    const ptr = Module.getGlobalExportByName('creat');
    return new NativeFunction(ptr, 'int', ['pointer', 'int']);
  },
  // int openat(int dirfd, const char *pathname, int flags);
  openat: () => {
    const ptr = Module.getGlobalExportByName('openat');
    return new NativeFunction(ptr, 'int', ['int', 'pointer', 'int']);
  },
  // int close(int fd);
  close: () => {
    const ptr = Module.getGlobalExportByName('close');
    return new NativeFunction(ptr, 'int', ['int']);
  },
  // int fclose(FILE *file);
  fclose: () => {
    const ptr = Module.getGlobalExportByName('fclose');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  // int shutdown(int sockfd, int how);
  shutdown: () => {
    const ptr = Module.getGlobalExportByName('shutdown');
    return new NativeFunction(ptr, 'int', ['int', 'int']);
  },
  mkdir: () => {
    const ptr = Module.getGlobalExportByName('mkdir');
    return new NativeFunction(ptr, 'int', ['pointer', 'int']);
  },
  // DIR *opendir(const char *name);
  opendir: () => {
    const ptr = Module.getGlobalExportByName('opendir');
    return new NativeFunction(ptr, 'pointer', ['pointer']);
  },
  // DIR *fdopendir(int fd);
  fdopendir: () => {
    const ptr = Module.getGlobalExportByName('fdopendir');
    return new NativeFunction(ptr, 'pointer', ['int']);
  },
  // struct dirent *readdir(DIR *dirp);
  readdir: () => {
    const ptr = Module.getGlobalExportByName('readdir');
    return new NativeFunction(ptr, 'pointer', ['pointer']);
  },
  closedir: () => {
    const ptr = Module.getGlobalExportByName('closedir');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  telldir: () => {
    const ptr = Module.getGlobalExportByName('telldir');
    return new NativeFunction(ptr, 'void', ['pointer']);
  },
  seekdir: () => {
    const ptr = Module.getGlobalExportByName('seekdir');
    return new NativeFunction(ptr, 'void', ['pointer', 'long']);
  },
  scandir: () => {
    const ptr = Module.getGlobalExportByName('scandir');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
  },
  // ssize_t readlink(const char *path, char *buf, size_t bufsiz);
  readlink: () => {
    const ptr = Module.getGlobalExportByName('readlink');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'int']);
  },
  // int readlinkat(int dirfd, char *pathname, char *buf, size_t bufsiz);
  readlinkat: () => {
    const ptr = Module.getGlobalExportByName('readlinkat');
    return new NativeFunction(ptr, 'int', ['int', 'pointer', 'pointer', 'size_t']);
  },
  // ssize_t pread(int fd, void buf[.count], size_t count);
  read: () => {
    const ptr = Module.getGlobalExportByName('read');
    return new NativeFunction(ptr, 'uint', ['int', 'pointer', 'uint']);
  },
  // ssize_t pread(int fd, void *buf, size_t count, off_t offset);
  pread: () => {
    const ptr = Module.getGlobalExportByName('pread');
    return new NativeFunction(ptr, 'uint', ['int', 'pointer', 'size_t', 'int']);
  },
  // size_t fread(void * buffer, size_t size, size_t count, FILE * stream );
  fread: () => {
    const ptr = Module.getGlobalExportByName('fread');
    return new NativeFunction(ptr, 'uint', ['pointer', 'int', 'int', 'pointer']);
  },
  // off_t lseek(int fd, off_t offset, int whence);
  lseek: () => {
    const ptr = Module.getGlobalExportByName('lseek');
    return new NativeFunction(ptr, 'pointer', ['int', 'pointer', 'int']);
  },
  // FILE *fopen(const char *restrict pathname, const char *restrict mode);
  fopen: () => {
    const ptr = Module.getGlobalExportByName('fopen');
    return new SystemFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // FILE *fopen(const char *restrict pathname, const char *restrict mode);
  open64: () => {
    const ptr = Module.getGlobalExportByName('open64');
    return new SystemFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // FILE *fopen(const char *restrict pathname, const char *restrict mode);
  fopen64: () => {
    const ptr = Module.getGlobalExportByName('fopen64');
    return new SystemFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // FILE *fdopen(int fd, const char *mode);
  fdopen: () => {
    const ptr = Module.getGlobalExportByName('fdopen');
    return new SystemFunction(ptr, 'pointer', ['int', 'pointer']);
  },
  // FILE *freopen(const char *restrict pathname, const char *restrict mode, FILE *restrict stream);
  freopen: () => {
    const ptr = Module.getGlobalExportByName('freopen');
    return new SystemFunction(ptr, 'pointer', ['pointer', 'pointer', 'pointer']);
  },
  chmod: () => {
    const ptr = Module.getGlobalExportByName('chmod');
    return new NativeFunction(ptr, 'int', ['pointer', 'int']);
  },
  // int access(const char *pathname, int mode);
  access: () => {
    const ptr = Module.getGlobalExportByName('access');
    return new NativeFunction(ptr, 'int', ['pointer', 'int']);
  },
  // int faccessat(int fd, const char *path, int amode, int flag);
  faccessat: () => {
    const ptr = Module.getGlobalExportByName('faccessat');
    return new NativeFunction(ptr, 'int', ['int', 'pointer', 'int', 'int']);
  },
  // int fcntl(int fd, int op, ... /* arg */ );
  fcntl: () => {
    const ptr = Module.getGlobalExportByName('fcntl');
    return new NativeFunction(ptr, 'int', ['int', 'int', '...']);
  },
  // int pthread_create(pthread_t *restrict thread, const pthread_attr_t *restrict attr, void *(*start_routine)(void *), void *restrict arg);
  pthread_create: () => {
    const ptr = Module.getGlobalExportByName('pthread_create');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
  },
  // pthread_t pthread_self(void);
  pthread_self: () => {
    const ptr = Module.getGlobalExportByName('pthread_self');
    return new NativeFunction(ptr, 'pointer', []);
  },
  // int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr);
  pthread_getattr_np: () => {
    const ptr = Module.getGlobalExportByName('pthread_getattr_np');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // int pthread_join(pthread_t thread, void **retval);
  pthread_join: () => {
    const ptr = Module.getGlobalExportByName('pthread_join');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // int pthread_gettid_np(pthread_t *thread);
  pthread_gettid_np: () => {
    const ptr = Module.getGlobalExportByName('pthread_gettid_np');
    return new NativeFunction(ptr, 'uint', ['pointer']);
  },
  // int pthread_getname_np(pthread_t *thread, const char * name, size_t len);
  pthread_getname_np: () => {
    const ptr = Module.getGlobalExportByName('pthread_getname_np');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'size_t']);
  },
  // int pthread_key_create(...);
  pthread_key_create: () => {
    const ptr = Module.getGlobalExportByName('pthread_key_create');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // void *calloc(size_t nmemb, size_t size);
  calloc: () => {
    const ptr = Module.getGlobalExportByName('calloc');
    return new NativeFunction(ptr, 'pointer', ['size_t', 'size_t']);
  },
  // void *malloc(size_t size);
  malloc: () => {
    const ptr = Module.getGlobalExportByName('malloc');
    return new NativeFunction(ptr, 'pointer', ['size_t']);
  },
  // void *realloc(void *ptr, size_t new_size);
  realloc: () => {
    const ptr = Module.getGlobalExportByName('realloc');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'size_t']);
  },
  // int prctl(int __option, ...)
  prctl: () => {
    const ptr = Module.getGlobalExportByName('prctl');
    return new NativeFunction(ptr, 'int', ['int', '...']);
  },
  // void free(void *ptr);
  free: () => {
    const ptr = Module.getGlobalExportByName('free');
    return new NativeFunction(ptr, 'int', []);
  },
  // int rand();
  rand: () => {
    const ptr = Module.getGlobalExportByName('rand');
    return new NativeFunction(ptr, 'int', []);
  },
  // double difftime(time_t __time1, time_t __time0)
  difftime: () => {
    const ptr = Module.getGlobalExportByName('difftime');
    return new NativeFunction(ptr, 'double', ['pointer', 'pointer']);
  },
  // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
  connect: () => {
    const ptr = Module.getGlobalExportByName('connect');
    return new NativeFunction(ptr, 'int', ['int', 'pointer', 'pointer']);
  },
  // int __system_property_get(const char *name, char *value);
  __system_property_get: () => {
    const ptr = Module.getGlobalExportByName('__system_property_get');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // int __system_property_read( const prop_info *pi, char *name, char * value);
  __system_property_read: () => {
    const ptr = Module.getGlobalExportByName('__system_property_read');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'pointer']);
  },
  // propinfo * __system_property_find(char * name);
  __system_property_find: (name: string) => {
    const ptr = Module.getGlobalExportByName('__system_property_find');
    return new NativeFunction(ptr, 'pointer', ['pointer']);
  },
  // propinfo * __system_property_find_nth(i: number);
  __system_property_find_nth: (i: number) => {
    const ptr = Module.getGlobalExportByName('__system_property_find_nth');
    return new NativeFunction(ptr, 'pointer', ['int']);
  },
  // struct hostent *gethostbyname(const char *name);
  gethostbyname: () => {
    const ptr = Module.getGlobalExportByName('gethostbyname');
    return new NativeFunction(ptr, 'pointer', ['pointer']);
  },
  // int getaddrinfo(const char *restrict node,
  //                const char *restrict service,
  //                const struct addrinfo *restrict hints,
  //                struct addrinfo **restrict res);
  getaddrinfo: () => {
    const ptr = Module.getGlobalExportByName('getaddrinfo');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
  },
  // int inet_aton(const char *cp, struct in_addr *addr);
  inet_aton: () => {
    const ptr = Module.getGlobalExportByName('inet_aton');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // int inet_addr(const char *cp, struct in_addr *addr);
  inet_addr: () => {
    const ptr = Module.getGlobalExportByName('inet_addr');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },

  // pid_t fork(void);
  fork: () => {
    const ptr = Module.getGlobalExportByName('fork');
    return new NativeFunction(ptr, 'int', []);
  },
  // int execv(const char *path, char *const argv[]);
  execv: () => {
    const ptr = Module.getGlobalExportByName('execv');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  //int dladdr(const void *addr, Dl_info *info);
  dladdr: () => {
    const ptr = Module.getGlobalExportByName('dladdr');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // void *dlopen(const char *filename, int flags);
  dlopen: () => {
    const ptr = Module.getGlobalExportByName('dlopen');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'int']);
  },
  // void *dlsym(void *restrict handle, const char *restrict symbol);
  dlsym: () => {
    const ptr = Module.getGlobalExportByName('dlsym');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // int dlclose(void *handle);
  dlclose: () => {
    const ptr = Module.getGlobalExportByName('dlclose');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  //void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset);
  mmap: () => {
    const ptr = Module.getGlobalExportByName('mmap');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'size_t', 'int', 'int', 'uint', 'long']);
  },
  // int munmap(void *addr, size_t length);
  munmap: () => {
    const ptr = Module.getGlobalExportByName('munmap');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'size_t']);
  },
  // void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
  mremap: () => {
    const ptr = Module.getGlobalExportByName('mremap');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'size_t', 'size_t', 'int', 'pointer']);
  },
  // int mprotect(void *addr, size_t len, int prot);
  mprotect: () => {
    const ptr = Module.getGlobalExportByName('mprotect');
    return new SystemFunction(ptr, 'int', ['pointer', 'size_t', 'int']);
  },
  // int gettimeofday(struct timeval *restrict tv, struct timezone *_Nullable restrict tz);
  gettimeofday: () => {
    const ptr = Module.getGlobalExportByName('gettimeofday');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
  pthread_mutex_init: () => {
    const ptr = Module.getGlobalExportByName('pthread_mutex_init');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // int pthread_mutex_lock(pthread_mutex_t *mutex);
  pthread_mutex_lock: () => {
    const ptr = Module.getGlobalExportByName('pthread_mutex_lock');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  // int pthread_mutex_unlock(pthread_mutex_t *mutex);
  pthread_mutex_unlock: () => {
    const ptr = Module.getGlobalExportByName('pthread_mutex_unlock');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  // int pthread_detach(pthread_t thread);
  pthread_detach: () => {
    const ptr = Module.getGlobalExportByName('pthread_detach');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  // char *strstr(const char *haystack, const char *needle);
  strstr: () => {
    const ptr = Module.getGlobalExportByName('strstr');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // char *strcasestr(const char *haystack, const char *needle);
  strcasestr: () => {
    const ptr = Module.getGlobalExportByName('strcasestr');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // size_t *strlen(const char *str);
  strlen: () => {
    const ptr = Module.getGlobalExportByName('strlen');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  // int strcmp(const char *s1, const char *s2);
  strcmp: () => {
    const ptr = Module.getGlobalExportByName('strcmp');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // int strncmp(const char *s1, const char *s2);
  strncmp: () => {
    const ptr = Module.getGlobalExportByName('strncmp');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // int strcasecmp(const char *s1, const char *s2);
  strcasecmp: () => {
    const ptr = Module.getGlobalExportByName('strcasecmp');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // char *stpcpy(char *restrict dst, const char *restrict src);
  stpcpy: () => {
    const ptr = Module.getGlobalExportByName('stpcpy');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // char *strcpy(char *restrict dst, const char *restrict src);
  strcpy: () => {
    const ptr = Module.getGlobalExportByName('strcpy');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // char *strcpy(char *restrict dst, const char *restrict src);
  strncpy: () => {
    const ptr = Module.getGlobalExportByName('strncpy');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'size_t']);
  },
  // char *strchr(char * str, int character);
  strchr: () => {
    const ptr = Module.getGlobalExportByName('strchr');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'int']);
  },
  // char *strchr(char * str, int character);
  strrchr: () => {
    const ptr = Module.getGlobalExportByName('strrchr');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'int']);
  },
  // char *strcat(char *restrict dst, char *restrict src);
  strcat: () => {
    const ptr = Module.getGlobalExportByName('strcat');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // char *strncat(char *restrict dst, char *restrict src, int size);
  strncat: () => {
    const ptr = Module.getGlobalExportByName('strncat');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'int']);
  },
  //  char *fgets(char *restrict s, int n, FILE *restrict stream);
  fgets: () => {
    const ptr = Module.getGlobalExportByName('fgets');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'int', 'pointer']);
  },
  //  char *fgets_unlocked(char *restrict s, int n, FILE *restrict stream);
  fgets_unlocked: () => {
    const ptr = Module.getGlobalExportByName('fgets_unlocked');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'int', 'pointer']);
  },
  //  int fstat(int fd, struct stat *statbuf);
  stat: () => {
    const ptr = Module.getGlobalExportByName('stat');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  //  int fstat(int fd, struct stat *statbuf);
  fstat: () => {
    const ptr = Module.getGlobalExportByName('fstat');
    return new NativeFunction(ptr, 'int', ['int', 'pointer']);
  },
  //  int fstat(int fd, struct stat *statbuf);
  lstat: () => {
    const ptr = Module.getGlobalExportByName('lstat');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // int __statfs64(const char *, size_t, struct statfs *);
  __statfs64: () => {
    const ptr = Module.getGlobalExportByName('__statfs64');
    return new NativeFunction(ptr, 'int', ['pointer', 'int', 'pointer']);
  },
  // time_t time(time_t *t);
  time: () => {
    const ptr = Module.getGlobalExportByName('time');
    return new NativeFunction(ptr, 'pointer', ['pointer']);
  },
  // struct tm *localtime(const time_t *timep);
  localtime: () => {
    const ptr = Module.getGlobalExportByName('localtime');
    return new NativeFunction(ptr, 'pointer', ['pointer']);
  },
  // ssize_t getline(char **restrict lineptr, size_t *restrict n, FILE *restrict stream);
  getline: () => {
    const ptr = Module.getGlobalExportByName('getline');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'int']);
  },
  // int sscanf(const char *restrict str, const char *restrict format, ...);
  sscanf: () => {
    const ptr = Module.getGlobalExportByName('sscanf');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer', '...']);
  },
  // FILE *popen(const char *command, const char *type);
  popen: () => {
    const ptr = Module.getGlobalExportByName('popen');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // FILE *pclose(FD);
  pclose: () => {
    const ptr = Module.getGlobalExportByName('pclose');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  // pid_t getpid(void);
  getpid: () => {
    const ptr = Module.getGlobalExportByName('getpid');
    return new NativeFunction(ptr, 'pointer', []);
  },
  // int remove(const char *pathname);
  remove: () => {
    const ptr = Module.getGlobalExportByName('remove');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  // int unlink(const char *pathname);
  unlink: () => {
    const ptr = Module.getGlobalExportByName('unlink');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  // [[noretunr]] void exit(int status);
  exit: () => {
    const ptr = Module.getGlobalExportByName('exit');
    return new NativeFunction(ptr, 'void', ['int']);
  },
  // [[noretunr]] void exit(int status);
  _exit: () => {
    const ptr = Module.getGlobalExportByName('_exit');
    return new NativeFunction(ptr, 'void', ['int']);
  },
  // [[noretunr]] void abort(int status);
  abort: () => {
    const ptr = Module.getGlobalExportByName('abort');
    return new NativeFunction(ptr, 'void', ['int']);
  },
  // [[noretunr]] void abort(int status);
  raise: () => {
    const ptr = Module.getGlobalExportByName('raise');
    return new NativeFunction(ptr, 'int', ['int']);
  },
  // int rcx(pid_t pid, int sig);
  kill: () => {
    const ptr = Module.getGlobalExportByName('kill');
    return new NativeFunction(ptr, 'int', ['pointer', 'int']);
  },
  // long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
  ptrace: () => {
    const ptr = Module.getGlobalExportByName('ptrace');
    return new NativeFunction(ptr, 'long', ['int', 'int', 'pointer', 'pointer']);
  },
  // int system(const char *command);
  system: () => {
    const ptr = Module.getGlobalExportByName('system');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  // int system(const char *command);
  strerror: () => {
    const ptr = Module.getGlobalExportByName('strerror');
    return new NativeFunction(ptr, 'pointer', ['int']);
  },
  // int printf ( const char * format, ... );
  printf: () => {
    const ptr = Module.getGlobalExportByName('printf');
    return new NativeFunction(ptr, 'int', ['pointer', '...']);
  },
  // int sprintf ( char * str, const char * format, ... );
  sprintf: () => {
    const ptr = Module.getGlobalExportByName('sprintf');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer', '...']);
  },
  // int sprintf ( char * str, size_t size, const char * format, ... );
  snprintf: () => {
    const ptr = Module.getGlobalExportByName('snprintf');
    return new NativeFunction(ptr, 'int', ['pointer', 'size_t', 'pointer', '...']);
  },
  // int vsnprintf (char * s, size_t n, const char * format, va_list arg );
  vsnprintf: () => {
    const ptr = Module.getGlobalExportByName('vsnprintf');
    return new NativeFunction(ptr, 'int', ['pointer', 'int', 'pointer']);
  },
  // long int atol ( const char * str );
  atoi: () => {
    const ptr = Module.getGlobalExportByName('atol');
    return new NativeFunction(ptr, 'long', ['pointer']);
  },
  // int atoi (const char * str);
  atol: () => {
    const ptr = Module.getGlobalExportByName('atoi');
    return new NativeFunction(ptr, 'int', ['pointer']);
  },
  // int isprint (int ch);
  isprint: () => {
    const ptr = Module.getGlobalExportByName('isprint');
    return new NativeFunction(ptr, 'int', ['int']);
  },
  // long int strtol (const char* str, char** endptr, int base);
  strtol: () => {
    const ptr = Module.getGlobalExportByName('strtol');
    return new NativeFunction(ptr, 'int32', ['pointer', 'pointer', 'int']);
  },
  // unsigned long int strtoul (const char* str, char** endptr, int base);
  strtoul: () => {
    const ptr = Module.getGlobalExportByName('strtoul');
    return new NativeFunction(ptr, 'uint32', ['pointer', 'pointer', 'int']);
  },
  // long long int strtoll (const char* str, char** endptr, int base);
  strtoll: () => {
    const ptr = Module.getGlobalExportByName('strtoll');
    return new NativeFunction(ptr, 'int64', ['pointer', 'pointer', 'int']);
  },
  // unsigned long long int strtoull (const char* str, char** endptr, int base);
  strtoull: () => {
    const ptr = Module.getGlobalExportByName('strtoull');
    return new NativeFunction(ptr, 'uint64', ['pointer', 'pointer', 'int']);
  },
  // char *strtok(char *str, const char *delim);
  strtok: () => {
    const ptr = Module.getGlobalExportByName('strtok');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // char *strtok_r(char *str, const char *delim, char **saveptr)));
  strtok_r: () => {
    const ptr = Module.getGlobalExportByName('strtok_r');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'pointer']);
  },
  // char * strdup(const char *str1);
  strdup: () => {
    const ptr = Module.getGlobalExportByName('strdup');
    return new NativeFunction(ptr, 'pointer', ['pointer']);
  },
  // void* memcpy( void* dest, const void* src, std::size_t count );
  memcpy: () => {
    const ptr = Module.getGlobalExportByName('memcpy');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'int']);
  },
  // int memcmp (const void * ptr1, const void * ptr2, size_t num);
  memcmp: () => {
    const ptr = Module.getGlobalExportByName('memcmp');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'int']);
  },
  // void *memmove(void * destination, const void * source, size_t num);
  memmove: () => {
    const ptr = Module.getGlobalExportByName('memmove');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'int']);
  },
  // void * memset (void * __s, int __c, size_t __n);
  memset: () => {
    const ptr = Module.getGlobalExportByName('memset');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'int', 'size_t']);
  },
  //void * memchr(void * __s, int __ch, size_t __n);
  memchr: () => {
    const ptr = Module.getGlobalExportByName('memchr');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'int', 'size_t']);
  },
  // unsigned long getauxval(unsigned long type);
  getauxval: () => {
    const ptr = Module.getGlobalExportByName('getauxval');
    return new NativeFunction(ptr, 'uint32', ['uint32']);
  },
  // int posix_spawn(pid_t *restrict pid, const char *restrict path,
  //                 const posix_spawn_file_actions_t *restrict file_actions,
  //                 const po six_spawnattr_t *restrict attrp,
  //                 char *const argv[restrict],
  //                 char *const envp[restrict]);
  posix_spawn: () => {
    const ptr = Module.getGlobalExportByName('posix_spawn');
    return new NativeFunction(ptr, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']);
  },
  // long syscall(long number, ...);
  syscall: () => {
    const ptr = Module.getGlobalExportByName('syscall');
    return new NativeFunction(ptr, 'int32', ['int32', '...']);
  },
  // may be stupid
  syscall_openat: () => {
    const ptr = Module.getGlobalExportByName('syscall');
    return new NativeFunction(ptr, 'int', ['int', 'int', 'pointer', 'char']);
  },
  syscall_read: () => {
    const ptr = Module.getGlobalExportByName('syscall');
    return new NativeFunction(ptr, 'int', ['int', 'int', 'pointer', 'size_t']);
  },
  syscall_readlinkat: () => {
    const ptr = Module.getGlobalExportByName('syscall');
    return new NativeFunction(ptr, 'int', ['int', 'int', 'pointer', 'pointer', 'int']);
  },
  // __sighandler_t signal(int __sig,__sighandler_t __handler);
  perror: () => {
    const ptr = Module.getGlobalExportByName('perror');
    return new NativeFunction(ptr, 'void', ['pointer']);
  },
  // __sighandler_t signal(int __sig,__sighandler_t __handler);
  signal: () => {
    const ptr = Module.getGlobalExportByName('signal');
    return new NativeFunction(ptr, 'pointer', ['int', 'pointer']);
  },
  // int nanosleep(const struct timespec *duration, timespec *_Nullable rem);
  nanosleep: () => {
    const ptr = Module.getGlobalExportByName('nanosleep');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  //int usleep(useconds_t usec);
  usleep: () => {
    const ptr = Module.getGlobalExportByName('usleep');
    return new NativeFunction(ptr, 'int', ['ulong']);
  },
  // char *getenv(const char *name);
  getenv: () => {
    const ptr = Module.getGlobalExportByName('getenv');
    return new NativeFunction(ptr, 'pointer', ['pointer']);
  },
  // char *setenv(const char *name, char *value);
  setenv: () => {
    const ptr = Module.getGlobalExportByName('setenv');
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
  },
  // int dl_iterate_phdr(typeof(int (struct dl_phdr_info *info, size_t size, void *data)) *callback, void *data);
  dl_iterate_phdr: () => {
    const ptr = Module.getGlobalExportByName('dl_iterate_phdr');
    return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
  },
  // int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
  sigaction: () => {
    const ptr = Module.getGlobalExportByName('sigaction');
    return new NativeFunction(ptr, 'int', ['int', 'pointer', 'pointer']);
  },
  // char * __cxa_demangle (const char *mangled_name, char *output_buffer, size_t *length, int *status)
  __cxa_demangle: () => {
    // const pt  = Module.getGlobalExportByName('__cxa_demangle');
    const ptr = DebugSymbol.fromName('__cxa_demangle').address;
    return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
  },
};

type LibcType = PropertyCallbackMapper<typeof LibcFinder>;
const LibcFinderProxy: LibcType = proxyCallback(LibcFinder);
export { LibcFinderProxy, type LibcType };
