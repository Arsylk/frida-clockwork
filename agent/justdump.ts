import { memmove, memcmp, ProcMaps } from '@clockwork/cmodules';
import { hookException, isIterable, Text, Linker } from '@clockwork/common';
import { attach } from '@clockwork/jnitrace';
import { logger } from '@clockwork/logging';
import {
    addressOf,
    getSelfProcessName,
    log,
    previousReturn,
    Pthread,
    readFdPath,
    stalk,
} from '@clockwork/native';
import Java from 'frida-java-bridge';

let done = false;

const libdl = Process.getModuleByName('libdl.so');
log(libdl.getExportByName('dlsym'), 'ps', {
    predicate: ProcMaps.inRange,
});
log(libdl.getExportByName('dlclose'), 'p', {
    predicate: ProcMaps.inRange,
});
log(libdl.getExportByName('dlopen'), 'si', {
    predicate: ProcMaps.inRange,
    call(args) {
        this.name = args[0].readCString();
        ProcMaps.printStacktrace(this.context, 'dlopen');
    },
    ret(retval) {
        if (this.name === 'libjiagu.so' || this.name === 'libjiagu_64.so' || this.name === 'l0c2e9060.so') {
            if (!done) {
                done = true;
                hookmore(this.name, retval);
            }
        }
    },
});
// log(Module.getGlobalExportByName('__cxa_atexit'), 'ppp', { predicate: ProcMaps.inRange });

const libc = Process.getModuleByName('libc.so');
// log(libc.getExportByName('fopen'), 'si', { predicate: ProcMaps.inRange, });
// log(libc.getExportByName('__snprintf_chk'), 'siiis');
// log(libc.getExportByName('mprotect'), 'pi', { predicate: ProcMaps.inRange });
// log(libc.getExportByName('mmap'), 'ppp', { predicate: ProcMaps.inRange });
// Interceptor.attach(libc.getExportByName('memmove'), memmove);
// Interceptor.attach(libc.getExportByName('memcmp'), memcmp);

// Pthread.hookPthread_create();
// Interceptor.attach(Module.getGlobalExportByName('android_dlopen_ext'), {
//     onEnter(args) {
//         this.path = args[0].readCString();
//     },
//     onLeave(retval) {
//         const name = this.path.split('/').pop();
//         if (name.includes('wCZuFsyR')) {
//             logger.info({ tag: 'dumpinit' }, `${this.returnAddress}`);
//         }
//     },
// });

// Java.performNow(() => {
//     const uniq = getHookUnique();
//     const tryme = () => {
//         uniq('com.igbr.shn.ghi.lib2.FontUtils', 'initAction', {
//             replace(method, activity, flag) {
//                 return method.call(this, activity, true);
//             },
//         });
//     };
//     hook(Classes.DexPathList, 'addDexPath', {
//         after(method, returnValue, ...args) {
//             tryme();
//         },
//     });
//     ClassLoader.perform(() => {
//         tryme();
//     });
// });

log(libc.getExportByName('open'), 's', { predicate: ProcMaps.inRange });
// log(libc.getExportByName('strlen'), 's', { predicate: ProcMaps.inRange });
// log(libc.getExportByName('strstr'), 'ss', { predicate: ProcMaps.inRange });
// log(libc.getExportByName('lstat'), 'sp', { predicate: ProcMaps.inRange });
// log(libc.getExportByName('strcat'), 's', { call: false, ret: false, predicate: ProcMaps.inRange });
Interceptor.replace(
    libc.getExportByName('remove'),
    new NativeCallback(
        (a0) => {
            console.log(a0.readCString());
            return 0;
        },
        'int',
        ['pointer'],
    ),
);
// log(Libc.strcpy, '_s', { predicate: ProcMaps.inRange });
// attach((x) => ProcMaps.inRange(x.returnAddress), false);
Process.attachModuleObserver({
    onAdded(module) {
        const { base, name, size, path } = module;
        if (
            !path.includes(Reflect.get(globalThis, 'packageName')) ||
            name === 'libmonochrome_64.so' ||
            name === 'libhwui.so'
        )
            return;
        if (name === 'base.odex') {
            Linker.patchSoList((name) => name.includes('memfd') || name.includes('libart.so'));
        }
        ProcMaps.addRange(module);
        if (name.includes('libirrlicht.so')) {
            hookException([56, 62, 78], {
                onBefore(context, num) {
                    if (num === 56) {
                        const path = context.x1.readCString();
                        this.path = path;
                        const mode = context.x2.toInt32();
                        this.mode = mode;
                    } else if (num === 62) {
                        const fd = readFdPath(context.x0.toInt32());
                        logger.info(
                            { tag: 'lseek' },
                            `${fd} +${context.x1.toInt32()} ${context.x2.toUInt32()}`,
                        );
                    } else if (num === 63 || num === 67) {
                        const fd = readFdPath(context.x0.toInt32());
                        this.fd = fd;
                        this.buf = context.x1;
                    } else if (num === 78) {
                        this.path = context.x1.readCString();
                        this.buf = context.x2;
                        this.bufsize = context.x3.toInt32();
                    } else if (num === 130) {
                        logger.info({ tag: 'tkill' }, `${context.x0.toInt32()}`);
                    }
                },
                onAfter(context, num) {
                    if (num === 56) {
                        const path = this.path;
                        if (
                            path?.startsWith('/proc/ ') &&
                            (path.endsWith('/maps ') ||
                                path.endsWith('/fd') ||
                                path.endsWith('/task ') ||
                                path.endsWith('/cmdline') ||
                                path.endsWith('/status '))
                        ) {
                            const numFd = context.x0.toInt32();
                            if (numFd > 0) {
                                Libc.close(numFd);
                            }
                            const arg1ptr = this.rawargs.add((1 + 1) * Process.pointerSize);
                            arg1ptr.writePointer(Memory.allocUtf8String('/dev/null'));
                            this.redo_call();
                        }
                        logger.info(
                            { tag: '__openat' },
                            `${this.path} ${this.mode} ? ${context.x0.toInt32()} ${addressOf(context.lr)}`,
                        );
                    } else if (num === 63) {
                        const length = context.x0.toInt32();
                        Memory.protect(this.buf, length, 'rw');
                        const content = this.buf.readCString(length);
                        const patch = content.replace(/frida/gi, 'nyasi');
                        this.buf.writeUtf8String(patch);
                        // const mempatch = Memory.alloc(length);
                        // mempatch.writeUtf8String(patch);
                        // File.writeAllBytes(MEMFD, mempatch.readByteArray(length));
                        // const nfd = Libc.open(Memory.allocUtf8String(MEMFD), 0).value;
                        // const arg1ptr = this.rawargs.add((1 + 1) * Process.pointerSize);
                        // arg1ptr.writePointer(ptr(nfd));
                        // this.redo_call();
                        logger.info({ tag: 'read' }, `${this.fd} -> \n${content}`);
                    } else if (num === 67) {
                        const length = context.x0.toInt32();
                        Memory.protect(this.buf, length, 'rw');
                        const content = this.buf.readCString(length);
                        const patch = content.replace(/frida/gi, 'nyasi');
                        this.buf.writeUtf8String(patch);
                        logger.info({ tag: 'pread64' }, `${this.fd} -> \n${content}`);
                    } else if (num === 78) {
                        const result = this.buf.readCString(this.bufsize)?.replace(/�/gi, '');
                        logger.info({ tag: 'readlinkat' }, `${this.path} -> ${result}`);
                    }
                },
            });
        }
    },
});

function hookmore(name: string, handle: NativePointer) {
    const module = Process.getModuleByName(name);
    const { base, size } = module;
    for (let _base = base; _base < base.add(size); _base = _base.add(Process.pageSize)) {
        try {
            const match = Memory.scanSync(_base, Process.pageSize, '01 00 b4 ?? 01 00 b4 ?0 0? 3f d6');
            if (match.length === 0) continue;
            const address = match[0].address;
            logger.info({ tag: 'memmatch' }, `${address}`);
            const inst = Instruction.parse(address.sub(0x1 + 0x4 * 2)) as Arm64Instruction;
            if (inst.mnemonic === 'bl') {
                const op = inst.operands[0] as Arm64ImmOperand;
                const f = ptr(`${op.value}`);
                log(f, 'ps', {
                    call(args) {
                        this.symbol = args[1].readCString();
                    },
                    ret(retval) {
                        const mapval = (symbol: string) => {
                            switch (symbol) {
                                case 'rtld_db_dlactivity':
                                    return ptr(0x0);
                                case '_ZN3art7Runtime9instance_E':
                                case '_ZN3art7Runtime15DisableVerifierEv': {
                                    const module = Libc.dlopen(
                                        Memory.allocUtf8String('/apex/com.android.art/lib64/libart.so'),
                                        2,
                                    );
                                    return Libc.dlsym(module, Memory.allocUtf8String(symbol));
                                }
                                case '_ZNK3art16ArtDexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE': {
                                    const module = Libc.dlopen(
                                        Memory.allocUtf8String('/apex/com.android.art/lib64/libdexfile.so'),
                                        2,
                                    );
                                    return Libc.dlsym(module, Memory.allocUtf8String(symbol));
                                }
                            }
                            return null;
                        };
                        const newval = mapval(this.symbol);
                        if (newval) retval.replace(newval);
                    },
                });
            }
        } catch {}
    }
}
