import { Libc, Struct, isNully, Text } from '@clockwork/common';
import { Color, logger } from '@clockwork/logging';
import { addressOf, readFdPath } from './utils.js';
import { unbox } from './index.js';
// import { constants } from 'frida-fs';
const { bold, dim, green, red, gray, bgRed } = Color.use();
const [R_OK, W_OK, X_OK] = [1, 2, 4];

function ofResultColor(path: NativePointer | string | number, ret: NativePointer | number) {
    if (typeof path === 'number') path = `<fd:${path}>`;
    if (typeof path === 'object') path = path.readCString() ?? '';
    const isOk = ret !== -1 && ret !== ptr(-1);
    const uri = isOk ? dim(green(`${path}`)) : dim(red(`${path}`));
    return uri;
}

function hookAccess(predicate: (ptr: NativePointer) => boolean, fn?: (path) => void) {
    const empty = dim('-');
    function log(
        this: InvocationContext | CallbackContext,
        path: string | null,
        mode: number | null,
        ret: number,
        tag: string,
    ) {
        const isOk = ret !== -1;
        mode ??= 0;
        const mask = `?${mode & R_OK ? 'R' : empty}${mode & W_OK ? 'W' : empty}${mode & X_OK ? 'X' : empty}`;
        const uri = isOk ? dim(green(`${path}`)) : dim(red(`${path}`));

        logger.info({ tag: tag }, `${uri} ${mask} ${addressOf(this.returnAddress)}`);
    }

    Interceptor.replace(
        Libc.access,
        new NativeCallback(
            function (pathname, mode) {
                let ret: number;
                if (predicate(this.returnAddress)) {
                    const path = pathname.readCString();
                    if (path?.endsWith('/su') || path?.startsWith('/system/bin/ls')) {
                        // Memory.proect(pathname, Process.pageSize, 'rw-');
                        pathname = Memory.allocUtf8String('/nya');
                    }
                    const reppath = fn?.(path);
                    if (reppath) {
                        pathname = Memory.allocUtf8String(reppath);
                    }
                    ret = Libc.access(pathname, mode);
                    log.call(this, pathname.readCString(), mode, ret, 'access');
                }
                return (ret ??= Libc.access(pathname, mode));
            },
            'int',
            ['pointer', 'int'],
        ),
    );
    Interceptor.replace(
        Libc.faccessat,
        new NativeCallback(
            function (fd, path, mode, flag) {
                if (predicate(this.returnAddress)) {
                    const strPath = path.readCString();
                    const iPath = `${strPath}`.toLowerCase();
                    if (
                        iPath.endsWith('bin/su') ||
                        iPath.includes('termux') ||
                        iPath.includes('magisk') ||
                        iPath.includes('supersu')
                    ) {
                        return -1;
                    }

                    // const regExp = /^\/apex\/com.android.conscrypt\/cacerts\/[a-f0-9]{8}\.0/;
                    // if (regExp.test(strPath ?? '')) {
                    //     Memory.protect(path, Process.pageSize, 'rw-');
                    //     path.writeUtf8String('/data/local/tmp/9a5ba575.0');
                    // }

                    const ret = Libc.faccessat(fd, path, mode, flag);
                    log.call(this, strPath, mode, ret, 'faccessat');
                    return ret;
                }
                const ret = Libc.faccessat(fd, path, mode, flag);
                return ret;
            },
            'int',
            ['int', 'pointer', 'int', 'int'],
        ),
    );
}

function hookOpen(
    predicate: (ptr: NativePointer) => boolean,
    fn?: (this: InvocationContext | CallbackContext, path: string | null) => any,
) {
    function log(
        this: InvocationContext | CallbackContext,
        uri: string | null,
        flags: number | null,
        mode: number | null,
        errno: number,
        key: string,
    ) {
        const isOk = errno === 0;
        const errstr = !isOk ? ` ${gray(dim(`{${errno}: "${Libc.strerror(errno).readCString()}}"`))}` : '';
        const struri = !isOk ? red(gray(`${uri}`)) : gray(`${uri}`);
        const flagsEnum = flags ? `0b${flags?.toString(2).padStart(16, '0')}` : null;
        const m = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map((x) => addressOf(x))
            .join('\t\n');

        logger.info(
            { tag: key },
            `${struri} flags: ${flagsEnum}, ${mode ? `mode: ${mode} ${errstr}` : ''} ${m}`,
        );
    }
    // Interceptor.replace(
    //     Libc.open,
    //     new NativeCallback(
    //         function (pathname, flags) {
    //             if (predicate(this.returnAddress)) {
    //                 const pathnameStr = pathname.readCString();
    //                 const replaceStr = fn?.call(this, pathnameStr);
    //                 const pathArg = replaceStr ? Memory.allocUtf8String(replaceStr) : pathname;
    //                 const ret = Libc.open(pathArg, flags);
    //                 log.call(
    //                     this,
    //                     replaceStr ? `${pathnameStr} -> ${replaceStr}` : pathnameStr,
    //                     flags,
    //                     null,
    //                     //@ts-ignore
    //                     ret.errno,
    //                     'open',
    //                 );
    //                 return ret.value;
    //             }
    //             const ret = Libc.open(pathname, flags);
    //             return ret.value;
    //         },
    //         'int',
    //         ['pointer', 'int'],
    //     ),
    // );
    // Interceptor.attach(Libc.open, {
    //     onEnter(args) {
    //         this.pathname = args[0];
    //         this.flags = args[1].toInt32();
    //     },
    //     onLeave(retval) {
    //         if (predicate(this.returnAddress)) {
    //             log.call(this, this.pathname.readCString(), this.flags, retval.toInt32(), 0, 'open');
    //         }
    //     },
    // });
    Interceptor.replace(
        Libc.creat,
        new NativeCallback(
            function (pathname, mode) {
                const ret = Libc.creat(pathname, mode);
                if (predicate(this.returnAddress)) {
                    log.call(this, pathname.readCString(), null, mode, ret, 'creat');
                }
                return ret;
            },
            'int',
            ['pointer', 'int'],
        ),
    );
    Interceptor.replace(
        Libc.openat,
        new NativeCallback(
            function (dirfd, pathname, flags, ...any) {
                const ret = Libc.openat(dirfd, pathname, flags, ...any);
                if (predicate(this.returnAddress)) {
                    log.call(this, pathname.readCString(), flags, null, ret, 'openat');
                }
                return ret;
            },
            'int',
            ['int', 'pointer', 'int'],
        ),
    );
}

function hookFopen(
    predicate: (ptr: NativePointer) => boolean,
    statfd = false,
    fn?: (this: InvocationContext | CallbackContext, path: string | null) => string | undefined,
) {
    function log(
        this: InvocationContext | CallbackContext,
        uri: string | number | null,
        mode: string | null,
        stream: NativePointer | null,
        errno: number,
        key: string,
    ) {
        const isFd = typeof uri === 'number';
        let strpath = isFd ? `<fd:${uri}>` : `${uri}`;
        const isOk = `${errno}` === '0';

        if (isFd && statfd) {
            const infs = readFdPath(uri);
            strpath += ` -> "${infs}"`;
        }

        const struri = isOk ? dim(`${strpath}`) : dim(red(`${strpath}`));
        const strmod = `${mode}`.padEnd(2);
        const errstr = !isOk ? ` ${gray(dim(`{${errno}: "${Libc.strerror(errno).readCString()}}"`))}` : '';

        logger.info(
            { tag: key },
            `${struri} ${strmod} ${!stream ? '' : `->${stream}`}${errstr} ${addressOf(this.returnAddress)}`,
        );
    }

    Interceptor.replace(
        Libc.fopen,
        new NativeCallback(
            function (pathname, mode) {
                if (predicate(this.returnAddress)) {
                    const pathnameStr = pathname.readCString();
                    const replaceStr = fn?.call(this, pathnameStr);
                    const pathArg = replaceStr ? Memory.allocUtf8String(replaceStr) : pathname;

                    const ret = Libc.fopen(pathArg, mode);
                    log.call(
                        this,
                        replaceStr ? `${pathnameStr} -> ${replaceStr}` : pathnameStr,
                        mode.readCString(),
                        null,
                        //@ts-ignore
                        ret.errno,
                        'fopen',
                    );
                    return ret.value;
                }
                const ret = Libc.fopen(pathname, mode);
                return ret.value;
            },
            'pointer',
            ['pointer', 'pointer'],
        ),
    );
    Interceptor.replace(
        Libc.fdopen,
        new NativeCallback(
            function (fd, mode) {
                let ret: any;
                if (predicate(this.returnAddress)) {
                    let replaceStr = fn?.call(this, `${fd}`);
                    if (statfd) replaceStr ??= fn?.call(this, readFdPath(fd));

                    let errno: any;
                    if (replaceStr) {
                        const replacePtr = Memory.allocUtf8String(replaceStr);
                        [ret, errno] = unbox(Libc.fopen(replacePtr, mode));
                    } else {
                        [ret, errno] = unbox(Libc.fdopen(fd, mode));
                    }
                    log.call(this, fd, mode.readCString(), null, errno, 'fdopen');
                }
                return ret ?? Libc.fdopen(fd, mode).value;
            },
            'pointer',
            ['int', 'pointer'],
        ),
    );
    Interceptor.replace(
        Libc.freopen,
        new NativeCallback(
            function (pathname, mode, stream) {
                const [ret, errno] = unbox(Libc.freopen(pathname, mode, stream));
                if (predicate(this.returnAddress)) {
                    log.call(this, pathname.readCString(), mode.readCString(), stream, errno, 'freopen');
                }
                return ret;
            },
            'pointer',
            ['pointer', 'pointer', 'pointer'],
        ),
    );
}

function hookOpendir(predicate: (ptr: NativePointer) => boolean, fn?: (path: string | null) => any) {
    Interceptor.replace(
        Libc.opendir,
        new NativeCallback(
            function (pathname) {
                let ret: NativePointer | null = null;
                if (predicate(this.returnAddress)) {
                    const pathnameStr = pathname.readCString();
                    const replaceStr = fn?.call(this, pathnameStr);
                    const pathArg = replaceStr ? Memory.allocUtf8String(replaceStr) : pathname;
                    ret = Libc.opendir(pathArg);

                    const msg = ofResultColor(
                        replaceStr ? `${pathnameStr} -> ${replaceStr}` : `${pathnameStr}`,
                        ret,
                    );
                    logger.info({ tag: 'opendir' }, `${msg} ${addressOf(this.returnAddress)}`);
                }
                return ret ?? Libc.opendir(pathname);
            },
            'pointer',
            ['pointer'],
        ),
    );
    Interceptor.replace(
        Libc.fdopendir,
        new NativeCallback(
            function (fd) {
                const ret = Libc.fdopendir(fd);
                if (predicate(this.returnAddress)) {
                    logger.info({ tag: 'fdopendir' }, ofResultColor(fd, ret));
                }
                return ret;
            },
            'pointer',
            ['int'],
        ),
    );
}

function hookDirent(predicate: (ptr: NativePointer) => boolean) {
    Interceptor.attach(Libc.readdir, {
        onLeave(retval) {
            if (predicate(this.returnAddress)) {
                const dirent = !isNully(retval)
                    ? Text.stringify(Struct.toObject(Struct.Dir.dirent(retval)))
                    : ptr(0x0);
                logger.info({ tag: 'readdir' }, `${dirent} ${addressOf(this.returnAddress)}`);
            }
        },
    });
    Interceptor.attach(Libc.seekdir, {
        onEnter(args) {
            if (predicate(this.returnAddress)) {
                const dirent = !isNully(args[0])
                    ? Text.stringify(Struct.toObject(Struct.Dir.dirent(args[0])))
                    : ptr(0x0);
                logger.info({ tag: 'seekdir' }, `${dirent} at 0x${args[1]}`);
            }
        },
    });
    Interceptor.attach(Libc.telldir, {
        onEnter(args) {
            if (predicate(this.returnAddress)) {
                const dirent = !isNully(args[0])
                    ? Text.stringify(Struct.toObject(Struct.Dir.dirent(args[0])))
                    : ptr(0x0);
                logger.info({ tag: 'telldir' }, `${dirent} at 0x${args[1]}`);
            }
        },
    });
    Interceptor.attach(Libc.scandir, {
        onEnter({ 0: drip, 1: namelist, 2: filter, 3: compar }) {
            this.drip = drip.readCString();
            this.namelist = namelist;
        },
        onLeave(retval) {
            const intRet = retval.toInt32();
            logger.info({ tag: 'scandir' }, `${this.drip}: ${intRet}`);
        },
    });
    Interceptor.attach(Libc.closedir, {
        onEnter(args) {
            if (predicate(this.returnAddress)) {
                const dirent = !isNully(args[0])
                    ? Text.stringify(Struct.toObject(Struct.Dir.dirent(args[0])))
                    : ptr(0x0);
                logger.info({ tag: 'closedir' }, `${dirent}`);
            }
        },
    });
}

function hookStat(predicate: (ptr: NativePointer) => boolean) {
    function log(uri: string | number | null, statbuf: NativePointer, ret: number, tag: string) {
        const isFd = typeof uri === 'number';
        const strpath = isFd ? `<fd:${uri}>` : `${uri}`;
        const isOk = ret === 0;

        let strmsg = isOk ? dim(`${strpath}`) : dim(red(`${strpath}`));
        if (isFd) {
            const target = readFdPath(uri);
            strmsg += ` -> "${gray(`${target}`)}"`;
        }

        strmsg += ` @${statbuf}`;
        // const stat = Struct.Stat.stat(statbuf);
        // strmsg += ` ${JSON.stringify(Struct.toObject(stat))}`

        logger.info({ tag: tag }, strmsg);
    }

    const array: ('stat' | 'lstat')[] = ['stat', 'lstat'];
    for (const key of array) {
        const func = Libc[key];
        Interceptor.replace(
            func,
            new NativeCallback(
                function (pathname, statbuf) {
                    const ret = func(pathname, statbuf);
                    if (predicate(this.returnAddress)) {
                        log.call(this, pathname.readCString(), statbuf, ret, key);
                    }
                    return ret;
                },
                'int',
                ['pointer', 'pointer'],
            ),
        );
    }
    Interceptor.replace(
        Libc.fstat,
        new NativeCallback(
            function (fd, statbuf) {
                const ret = Libc.fstat(fd, statbuf);
                if (predicate(this.returnAddress)) {
                    log.call(this, fd, statbuf, ret, 'fstat');
                }
                return ret;
            },
            'int',
            ['int', 'pointer'],
        ),
    );
}

function hookRemove(predicate: (ptr: NativePointer) => boolean, ignore?: (path: string) => boolean) {
    const array: ('remove' | 'unlink')[] = ['remove', 'unlink'];
    for (const key of array) {
        const func = Libc[key];
        Interceptor.replace(
            func,

            new NativeCallback(
                function (pathname) {
                    let ret: number;
                    if (predicate(this.returnAddress)) {
                        const strpath = pathname.readCString();
                        const replace = ignore?.(`${pathname}`) === true;
                        const fmt = replace ? bgRed : String;
                        logger.info(
                            { tag: key },
                            `${fmt(bold(gray(`${strpath}`)))}` + ` ${addressOf(this.returnAddress)}`,
                        );
                        if (replace) return 0;
                    }
                    return (ret ??= func(pathname));
                },
                'int',
                ['pointer'],
            ),
        );
    }
}

function hookReadlink(predicate: (ptr: NativePointer) => boolean) {
    Interceptor.replace(
        Libc.readlink,
        new NativeCallback(
            function (pathname, buf, bufsize) {
                const ret = Libc.readlink(pathname, buf, bufsize);
                if (predicate(this.returnAddress)) {
                    const lnstring = pathname.readCString();
                    const rlstring = buf.readCString(ret);
                    const frlstring = rlstring; // .replace(/�.*$/g, '')
                    logger.info({ tag: 'readlink' }, `"${lnstring}" -> "${frlstring}"`);
                }
                return ret;
            },
            'int',
            ['pointer', 'pointer', 'int'],
        ),
    );
    Interceptor.replace(
        Libc.readlinkat,
        new NativeCallback(
            function (fd, pathname, buf, bufsize) {
                const ret = Libc.readlinkat(fd, pathname, buf, bufsize);
                if (predicate(this.returnAddress)) {
                    const lnstring = pathname.readCString();
                    const rlstring = buf.readCString(ret);
                    const frlstring = rlstring; // .replace(/�.*$/g, '')
                    logger.info({ tag: 'readlinkat' }, `"${lnstring}" -> "${frlstring}"`);
                }
                return ret;
            },
            'int',
            ['int', 'pointer', 'pointer', 'int'],
        ),
    );
}

function hookFgets(predicate: (ptr: NativePointer) => boolean, fn?: (line: string) => string | undefined) {
    const array: ('fgets' | 'fgets_unlocked')[] = ['fgets', 'fgets_unlocked'];
    for (const key of array) {
        const func = Libc[key];
        function callback(buffer: NativePointer, size: number, fp: NativePointer) {
            const retval = func(buffer, size, fp);

            if (predicate(this.returnAddress)) {
                const fd = Libc.fileno(fp).value;
                const fdp = readFdPath(fd, 64);
                if (fdp?.endsWith('/status') || fdp?.endsWith('/maps')) {
                    logger.info({ tag: key }, `${fdp} ${red('SKIP')}`);
                    Libc.lseek(fd, NULL, 2);
                    return NULL;
                }
                const m = buffer.readCString()?.trimEnd();
            }
            return retval;
        }
        Interceptor.replace(func, new NativeCallback(callback, 'pointer', ['pointer', 'int', 'pointer']));
    }
}

export {
    hookAccess,
    hookStat,
    hookFopen,
    hookOpen,
    hookOpendir,
    hookRemove,
    hookReadlink,
    hookDirent,
    hookFgets,
};
