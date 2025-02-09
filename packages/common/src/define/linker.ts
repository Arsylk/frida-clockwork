import { Color, logger, subLogger } from '@clockwork/logging';
import { Libc, tryNull } from '../index.js';
import { isNully } from '../index.js';
import { stringify } from '../text.js';
import { Linker as LinkerStruct } from './struct.js';
import { SYSCALLS } from './syscalls.js';
const { soinfo } = LinkerStruct;
const { red, gray, dim } = Color.use();

let _dl_solist_get_head = NULL;
let soinfo_get_soname = NULL;
let soinfo_get_realpath = NULL;

const linker = Process.getModuleByName('linker64');
const syms = linker.enumerateSymbols();
for (const i in syms) {
    const sym = syms[i];

    switch (sym.name) {
        case '__dl__Z15solist_get_headv':
            _dl_solist_get_head = sym.address;
            break;
        case '__dl__ZNK6soinfo10get_sonameEv':
            soinfo_get_soname = sym.address;
            break;
        case '__dl__ZNK6soinfo12get_realpathEv':
            soinfo_get_realpath = sym.address;
            break;
    }
}

if (`${soinfo_get_soname}` === '0x0') {
    soinfo_get_soname = new NativeCallback((ptr: NativePointer) => ptr.readPointer(), 'pointer', ['pointer']);
}

namespace Linker {
    const _getSoListHead = new NativeFunction(_dl_solist_get_head, 'pointer', []);

    export function getSoListHead() {
        const ptr = _getSoListHead();
        return new SoInfo(ptr);
    }

    /**
     * Patches the so list to bypass frida detection
     *
     * This should be called directly before your module
     * ex. {@see "android_dlopen_ext"}
     */
    export function patchSoList(predicate?: (name: string) => boolean) {
        const _predicate = (name: string) => {
            for (const match of ['frida']) if (name.includes(match)) return true;
            return false;
        };
        const skip: string[] = [];

        let item: SoInfo | null = Linker.getSoListHead();
        let prev: SoInfo | null = null;
        while (item) {
            const name = item.getName();
            const next = item.getNext();
            logger.info({ tag: name }, `${next}`);
            if (_predicate(name) || predicate?.(name) === true) {
                prev?.setNext(next);
                skip.push(name);
            }
            prev = item;
            item = next;
        }

        let sb = '';
        sb += gray('[ ');
        for (let i = 0; i < skip.length; i += 1) {
            sb += dim(red(`${skip[i]}`));
            sb += i + 1 < skip.length ? ', ' : ' ';
        }
        sb += gray(']');
        const msg = `skipped ${sb}`;
        logger.info({ tag: 'linker' }, msg);
    }

    export function getParsedList() {
        const list: { name: string; base: NativePointer }[] = [];
        for (let item = getSoListHead() as SoInfo | null; item; item = item.getNext()) {
            list.push({ name: item.getName(), base: item.getBase() });
        }
        return list;
    }
}

class SoInfo {
    static #getSoName = new NativeFunction(soinfo_get_soname, 'pointer', ['pointer']);
    static #getRealpath = new NativeFunction(soinfo_get_realpath, 'pointer', ['pointer']);

    get ptr(): NativePointer {
        return this.#struct.ptr;
    }
    #struct: ReturnType<typeof soinfo>;
    constructor(ptr: NativePointer) {
        this.#struct = soinfo(ptr);
    }

    setNext(ptr: SoInfo | null) {
        Memory.protect(this.#struct.next.ptr, Process.pointerSize, 'rwx');
        const value = ptr ? ptr.#struct.ptr : NULL;
        this.#struct.next.ptr.writePointer(value);
    }

    getNext(): SoInfo | null {
        const ptr = this.#struct.next.value;
        if (isNully(ptr)) return null;
        return new SoInfo(ptr);
    }

    getName(): string {
        const ptr = SoInfo.#getRealpath(this.#struct.ptr);
        return `${ptr.readCString()}`;
    }

    getRealpath(): string {
        const ptr = SoInfo.#getRealpath(this.#struct.ptr);
        return `${ptr.readCString()}`;
    }

    getBase(): NativePointer {
        return this.#struct.base.value;
    }

    getSize(): number {
        return this.#struct.size.value.toNumber();
    }
}

const cm = new CModule(
    `
#include <gum/guminterceptor.h>
#include <stdio.h>
#include <string.h>

#define BPF_STMT(code,k) { (unsigned short) (code), 0, 0, k }
#define BPF_JUMP(code,k,jt,jf) { (unsigned short) (code), jt, jf, k }
#define BPF_LD 0x00
#define BPF_W 0x00
#define BPF_ABS 0x20
#define BPF_JEQ 0x10
#define BPF_JMP 0x05
#define BPF_K 0x00
#define BPF_RET 0x06

#define PR_SET_SECCOMP	22
#define PR_SET_NO_NEW_PRIVS	38
#define SECCOMP_MODE_FILTER	2
#define SECCOMP_RET_TRAP 0x00030000U
#define SECCOMP_RET_ALLOW 0x7fff0000U

#define SIGSYS  12
#define SIG_UNBLOCK     2

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned long sigset_t;
typedef long pthread_t;

typedef struct {
    uint32_t flags;
    void* stack_base;
    size_t stack_size;
    size_t guard_size;
    int32_t sched_policy;
    int32_t sched_priority;
  #ifdef __LP64__
    char __reserved[16];
  #endif
} pthread_attr_t;

typedef struct {
#if defined(__LP64__)
  int32_t __private[10];
#else
  int32_t __private[1];
#endif
} pthread_mutex_t;

typedef struct {
    int type;
    int isTask;
    void *args;
    int isReturn;
    void *ret;
    pthread_t thread;
    pthread_mutex_t mutex;
} thread_syscall_t;

typedef struct {
  char *phdr;
  size_t phnum;
  uint64_t base;
  size_t size;
  void *dynamic;
  void *next;
} so_info;

typedef struct {
    uint64_t start;
    uint64_t end;
} mem_region;

typedef struct {
    void *start;
    void *end;
    char prot[5];
    char name[256];
} module_info;

typedef struct {
    const char *dli_fname;  /* Pathname of shared object that contains address */
    void       *dli_fbase;  /* Base address at which shared object is loaded */
    const char *dli_sname;  /* Name of symbol whose definition overlaps addr */
    void       *dli_saddr;  /* Exact address of symbol named dli_sname */
} Dl_info;

extern so_info *solist_get_head();
extern char *soinfo_get_soname(so_info *info);
extern int dladdr(const void *addr, Dl_info *info);
extern int sscanf(const char * s, const char * format, ...);
extern char *strcpy(char * destination, const char * source);
extern char *strncpy(char * destination, const char * source, size_t num);
extern char *strchr(const char * str, int z);
extern int open(const char * path, int flags);
extern FILE *fopen(const char * restrict path, const char * restrict mode);
extern FILE *fdopen(int fildes, const char *options);
extern int fclose(FILE *stream);
extern int sprintf(char *str, const char *format, ...);
extern char *fgets(char *str, int n, FILE *stream);
extern unsigned long strtoul(const char* __s, char** __end_ptr, int __base);
extern unsigned long strlen( const char * str);
extern char *strtok(char *str, const char *delim);
extern char *strtok_r(char *str, const char *delim, char **saveptr);
extern void free(void *ptr);
extern long syscall(long __number, ...);
extern int pthread_mutex_init(pthread_mutex_t* __mutex, const void* __attr);
extern int pthread_mutex_lock(pthread_mutex_t* __mutex);
extern int pthread_mutex_unlock(pthread_mutex_t* __mutex);
extern int pthread_create(pthread_t* __pthread_ptr, pthread_attr_t const* __attr, void* (*__start_routine)(void*), void*);
extern void on_message(char * str);
extern int prctl(int __option, ...);

static void log(const gchar *format, ...){
    gchar *message;
    va_list args;
    va_start(args, format);
    message = g_strdup_vprintf(format, args);
    va_end(args);
    on_message(message);
    g_free(message);
}

module_info modules[1024];
int module_count = 0;
char *find_module(void* addr) {
    for (int i = 0; i < module_count; i++) {
        if (addr >= modules[i].start && addr < modules[i].end) {
            return modules[i].name;
        }
    }
    return "unknown";
}

char *find_so_info(void *addr) {
    so_info *info = solist_get_head();
    while (info) {
        if (__builtin_expect(((uint64_t) addr >= info->base && (uint64_t) addr < info->base + info->size), 0)) {
            return soinfo_get_soname(info);
        }

        info = info->next;
    }
    return find_module(addr);
}


void* call_load_modules(void *args) {
    register uint64_t addr = (uint64_t) args;
    register uint64_t start, end;
    static char prot[4];
    char line[512];

    int fd = syscall(56, 0, "/proc/self/maps", 0, 0);
    FILE *fp = fdopen(fd, "r");
    if (!fp) return (void *) NULL;
    
    module_count = 0;
    char *token, *saveptr;
    while (fgets(line, 512, fp) != NULL) {
        token = strtok_r(line, "-", &saveptr);
        start = (uint64_t) strtoul(token, NULL, 16);

        token = strtok_r(NULL, " ", &saveptr);
        end = (uint64_t) strtoul(token, NULL, 16);

        token = strtok_r(NULL, " ", &saveptr);

        module_info mod;
        mod.start = (void *) start;
        mod.end = (void *) end;
        __builtin_memcpy(mod.prot, token, 4);
        mod.prot[4] = 0;

        token = strtok_r(NULL, " ", &saveptr);
        char *nameptr = strchr(saveptr, '/');
        if (nameptr != NULL) {
            strcpy(mod.name, nameptr);
        }
        modules[module_count++] = mod;
        
        if (__builtin_expect((addr >= start && addr < end), 0)) {
            log("%x <= %x < %x %s %s", mod.start, addr, mod.end, mod.prot, mod.name);
        }

    }
    fclose(fp);
    
    return (void *) 8;
}

void *print_stacktrace(void *addr) {
    // Get current frame pointer
    uint64_t retaddr = (uint64_t )__builtin_extract_return_addr(__builtin_return_address(0));
    uintptr_t *frame_ptr = (uintptr_t*)__builtin_frame_address(0);
    
    
    /*log("Stack trace: %p", retaddr);*/
    int depth = 0;
    // Walk the stack using frame pointers
    while (frame_ptr != NULL && depth < 10) {
        void* return_addr = (void*)*(frame_ptr + 1);
        if (!return_addr) break;
        
        char* module = find_so_info(return_addr);
        log("  %p [%s]", return_addr, module);
        
        frame_ptr = (uintptr_t*)*frame_ptr;
        
        // Basic sanity check for frame pointer
        if ((uintptr_t)frame_ptr & 0x7) break;
        
        depth+=1;
    }

    return (void *) 0x0;
}

void *call_syscall(void *args) {
    void **d_args = (void **)args;
    void *ret = (void *)syscall((long)d_args[0] ,d_args[1] ,d_args[2] ,d_args[3], d_args[4], d_args[5], d_args[6]);
    return ret;
}

void *pthread_syscall(void *args){
    thread_syscall_t *syscall_thread = (thread_syscall_t *)args;
    while(1){
        if(syscall_thread->isTask){
            if(syscall_thread->type == 0){
                syscall_thread->ret = call_syscall(syscall_thread->args);
            }else if(syscall_thread->type == 1){
                syscall_thread->ret = (void*) 1; call_load_modules(syscall_thread->args);
            }else if(syscall_thread->type == 2){
                syscall_thread->ret = (void*) print_stacktrace(syscall_thread->args); // call_read_maps(syscall_thread->args);
            }
            syscall_thread->args = NULL;
            syscall_thread->isReturn = 1;
            syscall_thread->isTask = 0;
        }
    }
    return NULL;
}

thread_syscall_t *pthread_syscall_create(){
    thread_syscall_t *syscall_thread = (thread_syscall_t *)g_malloc(sizeof(thread_syscall_t));
    syscall_thread->type = 0;
    syscall_thread->isTask = 0;
    syscall_thread->args = NULL;
    syscall_thread->ret = NULL;
    syscall_thread->isReturn = 0;
    pthread_mutex_init(&syscall_thread->mutex, NULL);
    pthread_t threadId;
    pthread_create(&threadId, NULL, &pthread_syscall, (void *)syscall_thread);
    syscall_thread->thread = threadId;
    return syscall_thread;
}

int lock(thread_syscall_t *syscall_thread){
    return pthread_mutex_lock(&syscall_thread->mutex);
}

int unlock(thread_syscall_t *syscall_thread){
    return pthread_mutex_unlock(&syscall_thread->mutex);
}

void *enqueue_task(thread_syscall_t *syscall_thread,void *args,int type){
    if(syscall_thread->isTask == 0){
        syscall_thread->args = args;
        syscall_thread->type = type;
        syscall_thread->isTask = 1;
    }
    do{
        if(syscall_thread->isReturn){
            syscall_thread->isReturn = 0;
            return syscall_thread->ret;
        }
    }while(1);
}

struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};

struct sock_filter {
    __u16 code;
    __u8 jt;
    __u8 jf;
    __u32 k;
};

struct sock_fprog {
    unsigned short len;
    struct sock_filter * filter;
};

int install_filter(__u32 nr) {
    log("seccomp_syscall(%lu)", nr);
    struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        log("prctl(NO_NEW_PRIVS)");
        return 1;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        log("prctl(PR_SET_SECCOMP)");
        return 1;
    }
    return 0;
}
`,
    {
        solist_get_head: _dl_solist_get_head,
        soinfo_get_soname: soinfo_get_soname,
        pthread_create: Libc.pthread_create,
        pthread_mutex_init: Libc.pthread_mutex_init,
        pthread_mutex_lock: Libc.pthread_mutex_lock,
        pthread_mutex_unlock: Libc.pthread_mutex_unlock,
        prctl: Libc.prctl,
        free: Libc.free,
        dladdr: Libc.dladdr,
        syscall: Libc.syscall,
        sscanf: Libc.sscanf,
        open: Libc.open,
        fopen: Libc.fopen,
        fdopen: Libc.fdopen,
        fgets: Libc.fgets,
        fclose: Libc.fclose,
        sprintf: Libc.sprintf,
        strlen: Libc.strlen,
        strchr: Libc.strchr,
        strcpy: Libc.strcpy,
        strncpy: Libc.strncpy,
        strtok: Libc.strtok,
        strtok_r: Libc.strtok_r,
        strtoul: Libc.strtoul,
        on_message: new NativeCallback(
            (ptr) => logger.info({ tag: 'cmodule' }, `${ptr.readCString()}`),
            'void',
            ['pointer'],
        ),
    },
);
const CM_pthread_syscall_create = new NativeFunction(cm.pthread_syscall_create, 'pointer', []);
const CM_enqueue_task = new NativeFunction(cm.enqueue_task, 'pointer', ['pointer', 'pointer', 'int']);
const CM_lock = new NativeFunction(cm.lock, 'int', ['pointer']);
const CM_unlock = new NativeFunction(cm.unlock, 'int', ['pointer']);
const CM_print_stacktrace = new NativeFunction(cm.print_stacktrace, 'void', []);
const CM_find_so_info = new NativeFunction(cm.find_so_info, 'pointer', ['pointer']);

let sysThread = NULL;
type SyscallParams = {
    onBefore?: (context: Arm64CpuContext, num: number) => void;
    onAfter?: (context: Arm64CpuContext, num: number) => void;
    logging?: boolean;
};
function hookException(nums: number[], params: SyscallParams) {
    const rawargs = Memory.alloc(7 * Process.pointerSize);
    sysThread = CM_pthread_syscall_create();
    Process.setExceptionHandler((details) => {
        const offset = details.context.pc.sub(0x4);
        if (
            (details as any).message === 'system error' &&
            details.type === 'system' &&
            offset.readUInt() === 0xd4000001
        ) {
            CM_lock(sysThread);
            const num = (details.context as Arm64CpuContext).x8.toInt32();
            // store current registers
            const args: NativePointer[] = new Array(6);
            rawargs.writePointer((details.context as Arm64CpuContext).x8);
            for (let i = 0; i < 6; i += 1) {
                args[i] = Reflect.get(details.context, `x${i}`);
                rawargs.add((i + 1) * Process.pointerSize).writePointer(args[i]);
            }
            if (params.logging === true)
                logger.info({ tag: 'syscall' }, `${num} -> ${stringify(SYSCALLS[`${num}`])}`);

            params.onBefore?.(details.context as Arm64CpuContext, num);
            const retval = CM_enqueue_task(sysThread, rawargs, 0);
            (details.context as Arm64CpuContext).x0 = retval;
            params?.onAfter?.(details.context as Arm64CpuContext, num);

            CM_unlock(sysThread);
            return true;
        }
        return false;
    });

    const install = new NativeFunction(cm.install_filter, 'void', ['int']);
    for (const num of new Set<number>(nums)) install(num);
}

export { Linker, hookException };
