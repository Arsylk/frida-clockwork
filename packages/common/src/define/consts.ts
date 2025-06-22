const PATH_MAX = 4096;

function keynames(obj: object, value: any): string[] {
    return Reflect.ownKeys(obj)
        .filter((key) => obj[key] === value)
        .map(String);
}

function keyname(obj: object, value: any): string | null {
    const names: string[] = keynames(obj, value);
    return names && names.length > 0 ? (names.pop() ?? null) : null;
}

const JavaPrimitive = {
    boolean: 'Z',
    byte: 'B',
    char: 'C',
    double: 'D',
    float: 'F',
    int: 'I',
    long: 'J',
    short: 'S',
    void: 'V',
} as const;

enum mode {
    F_OK = 0,
    X_OK = 1,
    W_OK = 2,
    R_OK = 4,
}

enum a_type {
    AT_NULL = 0,
    AT_IGNORE = 1,
    AT_EXECFD = 2,
    AT_PHDR = 3,
    AT_PHENT = 4,
    AT_PHNUM = 5,
    AT_PAGESZ = 6,
    AT_BASE = 7,
    AT_FLAGS = 8,
    AT_ENTRY = 9,
    AT_NOTELF = 10,
    AT_UID = 11,
    AT_EUID = 12,
    AT_GID = 13,
    AT_EGID = 14,
    AT_PLATFORM = 15,
    AT_HWCAP = 16,
    AT_CLKTCK = 17,
    AT_SECURE = 23,
    AT_BASE_PLATFORM = 24,
    AT_RANDOM = 25,
    AT_HWCAP2 = 26,
    AT_RSEQ_FEATURE_SIZE = 27,
    AT_RSEQ_ALIGN = 28,
    AT_EXECFN = 31,
    AT_MINSIGSTKSZ = 51,
}

const cmd = {
    F_DUPFD: 0,
    F_GETFD: 1,
    F_SETFD: 2,
    F_GETFL: 3,
    F_SETFL: 4,
    F_GETLK: 7,
    F_SETLK: 6,
    F_SETLKW: 8,
    F_GETOWN: 9,
    F_SETOWN: 14,
    F_GETLK64: 22,
    F_SETLK64: 21,
    F_SETLKW64: 23,
    F_GETOWN_EX: 24,
    F_SETOWN_EX: 25,
    F_GETOWNER_UID: 26,
    F_GETOWNER_UIDS: 27,
    F_NOTIFY: 28,
    F_GETPIPE_SZ: 29,
    F_SETPIPE_SZ: 30,
    F_GET_LEASE: 33,
    F_SET_LEASE: 34,
    F_CANCELLK: 35,
    F_GETLK64_BATCH: 36,
    F_SETLK64_BATCH: 37,
    F_GETLKX: 15,
    F_SETLKX: 16,
    F_SETLKWX: 17,
    F_GETSIG: 18,
    F_SETSIG: 19,
    F_IOCTL: 54,
    F_GETFSSTAT: 5,
    F_GETFSSTAT64: 49,
    F_NOTIFY_INT: 41,
    F_GETPATH: 100,
} as const;

const l_type = {
    F_RDLCK: 1,
    F_WRLCK: 2,
    F_UNLCK: 3,
} as const;

const f_access = {
    F_RDACC: 0,
    F_WRACC: 1,
    F_RWACC: 2,
} as const;

const f_deny = {
    F_COMPAT: 0,
    F_RDDNY: 1,
    F_WRDNY: 2,
    F_RWDNY: 3,
    F_NODNY: 4,
} as const;

const oflags = {
    O_CREAT: 0x00000040,
    O_EXCL: 0x00000200,
    O_NOCTTY: 0x00000400,
    O_TRUNC: 0x00000100,
    O_TTY_INIT: 0x00002000,
    O_XATTR: 0x00040000,
} as const;

const whence = {
    0: 'SEEK_SET',
    1: 'SEEK_CUR',
    2: 'SEEK_END',
} as const;

const prot = (flagOrPtr: number | NativePointer) => {
    const flag = flagOrPtr instanceof NativePointer ? flagOrPtr.toInt32() : flagOrPtr
    if (flag === 0) return 'PROT_NONE';
    return (
        [
            [1, 'PROT_READ'],
            [2, 'PROT_WRITE'],
            [4, 'PROT_EXEC'],
        ] as const
    )
        .filter(([f, _]) => f & flag)
        .map(([_, s]) => s)
        .join(' | ');
}

export { PATH_MAX, keynames, keyname, whence, prot, a_type, JavaPrimitive, mode, cmd };
