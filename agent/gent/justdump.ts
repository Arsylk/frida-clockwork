import { memmove, memcmp, ProcMaps } from '@clockwork/cmodules';
import { hookException, isIterable, Text, Linker, tryNull, Consts, isNully } from '@clockwork/common';
import { dumpLib } from '@clockwork/dump';
import { hook } from '@clockwork/hooks';
import { attach } from '@clockwork/jnitrace';
import { logger } from '@clockwork/logging';
import {
    addressOf,
    asExportedObject,
    getEnumerated,
    getSelfFiles,
    getSelfProcessName,
    isInRange,
    log,
    previousReturn,
    Pthread,
    readFdPath,
    replace,
    TheEnd,
} from '@clockwork/native';
import Java from 'frida-java-bridge';

let done = false;
let found = false;
const mprots = new Array<{base: NativePointer, size: number}>()
const dexes = new Map<string, number>()

const libdl = Process.getModuleByName('libdl.so');
const dladdr = new NativeFunction(libdl.getExportByName('dladdr'), 'int', ['pointer', 'pointer'])
log(libdl.getExportByName('dl_iterate_phdr'), 'ps', {
    predicate: ProcMaps.inRange,
});
// log(libdl.getExportByName('dlsym'), 'ps', {
//     predicate: ProcMaps.inRange,
// });
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
                hookmore(this.name);
            } 
        }
    },
});

// log(Module.getGlobalExportByName('__cxa_atexit'), '000', {
//     transform: {
//         0: (ptr) => DebugSymbol.fromAddress(ptr).toString()
//     }
// });

const libc = Process.getModuleByName('libc.so');
log(libc.getExportByName('mprotect'), 'pii', { 
    predicate: ProcMaps.inRange,
    call(args) {
        this.base = args[0]
        this.size = args[1].toInt32()
    },
    ret(retval) {
        const range = {base: this.base, size: this.size}
        mprots.push(range)
        ProcMaps.addRange(range)
    },
});
// log(libc.getExportByName('mmap'), 'pp2', {
//     predicate: ProcMaps.inRange,
//     transform: { 2: Consts.prot }
// });
// log(libc.getExportByName('__snprintf_chk'), 'siiis');
// log(libc.getExportByName('fopen'), 'si', { predicate: ProcMaps.inRange, });

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
//     hook(Classes.SharedPreferencesImpl, 'getString', {
//         replace(method, ...args) {
//             if (args[0] === 'promo_url') return 'https://google.pl/search?q=hi'
//             if (args[0] === 'referrer' || args[0] === 'extraReferrer') return 'utm_content=Non-organic'
//             return method.call(this, ...args)
//         },
//     });
// });

// log(libc.getExportByName('open'), 's', { predicate: ProcMaps.inRange });
// log(libc.getExportByName('strlen'), 's', { predicate: ProcMaps.inRange });
// log(libc.getExportByName('strstr'), 'ss', { predicate: ProcMaps.inRange });
// log(libc.getExportByName('lstat'), 'sp', { predicate: ProcMaps.inRange });
log(libc.getExportByName('lseek'), '0pp', { predicate: ProcMaps.inRange, transform: {
    0: (ptr) => readFdPath(ptr.toInt32())
} });
// log(libc.getExportByName('strcat'), 's', { call: false, ret: false, predicate: ProcMaps.inRange });
// log(Libc.strcpy, '_s', { predicate: ProcMaps.inRange });
// Interceptor.replace(
//     libc.getExportByName('remove'),
//     new NativeCallback(
//         (a0) => {
//             console.log(a0.readCString());
//             return 0;
//         },
//         'int',
//         ['pointer'],
//     ),
// );
// Interceptor.attach(Libc.memmove, memmove)
// Interceptor.attach(Libc.memcmp, memcmp)

attach((x) => ProcMaps.inRange(x.returnAddress), false);
Process.attachModuleObserver({
    onAdded(module) {
        const { base, name, size, path } = module;
        if (
            !path.includes(Reflect.get(globalThis, 'packageName')) ||
            name === 'libmonochrome_64.so' ||
            name === 'libunity.so' ||
            name === 'libil2cpp.so' ||
            name === 'libmain.so' ||
            name === 'libhwui.so' ||
            name === 'libsigner.so'
        )
            return;
        if (name === 'base.odex ') {
            const libart = Process.getModuleByName('libart.so')
            // log(getEnumerated(libart, '_ZN3art11ClassLinker15RegisterDexFileERKNS_7DexFileENS_6ObjPtrINS_6mirror11ClassLoaderEEE'), 'ppp')
            log(getEnumerated(libart, '_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_3dex8ClassDefE'), 'ppsppp', {
                nolog: true,
                call(args) {
                    const dexfile = args[5]
                    const base = dexfile.add(Process.pointerSize).readPointer()
                    const size = dexfile.add(Process.pointerSize * 2).readUInt()
                    if (dexes.has(`${base}`)) return
                    dexes.set(`${base}`, size)
                    logger.info({tag: 'dex'}, `${Text.toHexString(base.readByteArray(4))} ${base.readCString(4).replace('\n', '\\n')} ${size}`)
                    Memory.protect(base, size, 'r')
                    File.writeAllBytes(`${getSelfFiles()}/classes_${base}.dex`, base.readByteArray(size))
                },
            })
            Linker.patchSoList((name) => name.includes('memfd') || name.includes('libart.so'));
        }

        logger.info({ tag: 'phdr_add' }, `${Text.stringify({ name: name, base: base, size: size })}`);
        ProcMaps.addRange(module);
    },
});

function hookmore(name: string) {
    const module = Process.getModuleByName(name);
    for (const range of [module, ...mprots]) {
        logger.info({tag: 'memscan'}, `${range.base} - ${range.base.add(range.size)}`)
        for (let _base = range.base; _base < range.base.add(range.size); _base = _base.add(Process.pageSize)) {
            try {
                const match = Memory.scanSync(_base, Process.pageSize, '01 00 b4 ?? 01 00 b4 ?0 0? 3f d6');
                if (match.length === 0) continue;
                const address = match[0].address;
                logger.info({ tag: 'memmatch' }, `${address}`);
                const inst = Instruction.parse(address.sub(0x1 + 0x4 * 2)) as Arm64Instruction;
                if (inst.mnemonic === 'bl') {
                    found = true
                    const op = inst.operands[0] as Arm64ImmOperand;
                    const f = ptr(`${op.value}`);
                    logger.info({ tag: 'memfound' }, `${inst.address} ${inst} ${f}`);
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
                    break
                }
            } catch {}
        }
        if (found) break
    }
    if (found) hooksyscall()
}

function hooksyscall() {
    hookException([56,], {
        onBefore(context, num) {
            if (num === 56) {
                const path = context.x1.readCString();
                this.path = path;
                const mode = context.x2.toInt32();
                this.mode = mode;
            } else if (num === 62) {
                this.fd = context.x0.toInt32()
                this.offset = context.x1.toInt32()
                this.whence = context.x2.toUInt32()
            } else if (num === 63 || num === 67) {
                this.fd = context.x0.toInt32();
                this.buf = context.x1;
            } else if (num === 78) {
                this.path = context.x1.readCString();
                this.buf = context.x2;
                this.bufsize = context.x3.toInt32();
            } else if (num === 130) {
                logger.info({ tag: 'tkill' }, `${context.x0.toInt32()}`);

            } else if (num === 226) {
                this.base = context.x0
                this.size = context.x1.toInt32()
                this.prot = context.x2.toUInt32()
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
            } else if (num === 62) {
                const fdpath = readFdPath(this.fd)
                if (fdpath.endsWith('/base.apk')) return
                logger.info(
                    { tag: 'lseek' },
                    `${fdpath} ${this.offset} ${Consts.whence[this.whence]}`,
                );
            } else if (num === 63) {
                const length = context.x0.toInt32();
                // Memory.protect(this.buf, length, 'rw');
                const content = this.buf.readCString(length);
                // const patch = content.replace(/frida/gi, 'nyasi');
                // this.buf.writeUtf8String(patch);
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
                // Memory.protect(this.buf, length, 'rw');
                const content = this.buf.readCString(length);
                // const patch = content.replace(/frida/gi, 'nyasi');
                // this.buf.writeUtf8String(patch);
                logger.info({ tag: 'pread64' }, `${readFdPath(this.fd)} -> \n${content}`);
            } else if (num === 78) {
                const result = this.buf.readCString(this.bufsize)?.replace(/�/gi, '');
                logger.info({ tag: 'readlinkat' }, `${this.path} -> ${result}`);
            } else if (num === 226) {
                logger.info({ tag: 'mprotect' }, `${this.base} ${this.size} ${Consts.prot(this.prot)}`);
            }
        },
    });
}
