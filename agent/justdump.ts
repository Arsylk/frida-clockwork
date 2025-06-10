import { memmove, memcmp, ProcMaps } from '@clockwork/cmodules';
import { hookException, isIterable, Text } from '@clockwork/common';
import { dumpLib, initSoDump } from '@clockwork/dump';
import { attach } from '@clockwork/jnitrace';
import { logger } from '@clockwork/logging';
import { addressOf, getSelfProcessName, log, previousReturn, readFdPath, stalk } from '@clockwork/native';

let done = false;

const libdl = Process.getModuleByName('libdl.so');
// log(libdl.getExportByName('dlsym'), 'ps');
// log(libdl.getExportByName('dlclose'), 'p');
log(libdl.getExportByName('dlopen'), 'si', {
    call(args) {
        this.name = args[0].readCString();
        // ProcMaps.printStacktrace(this.context, 'dlopen');
    },
    ret(retval) {
        if (this.name === 'libjiagu.so' || this.name === 'libjiagu_64.so' || this.name === 'l554456de.so') {
            if (!done) {
                done = true;
                hookmore(this.name, retval);
            }
        }
    },
});
// log(Module.getGlobalExportByName('__cxa_atexit'), 'ppp', { predicate: ProcMaps.inRange });
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
                                case '_ZN3art7Runtime15DisableVerifierEv':
                                    return Process.getModuleByName('libart.so').getExportByName(symbol);
                                case '_ZNK3art16ArtDexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE':
                                    return Process.getModuleByName('libdexfile.so').getExportByName(symbol);
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

const libc = Process.getModuleByName('libc.so');
// log(libc.getExportByName('fopen'), 'si');
// log(libc.getExportByName('mprotect'), 'pi', { predicate: ProcMaps.inRange });
// log(libc.getExportByName('mmap'), 'ppp', { predicate: ProcMaps.inRange });
// Interceptor.attach(libc.getExportByName('memmove'), memmove);
// Interceptor.attach(libc.getExportByName('memcmp'), memcmp);

Interceptor.attach(Module.getGlobalExportByName('android_dlopen_ext'), {
    onEnter(args) {
        this.path = args[0].readCString();
    },
    onLeave(retval) {
        const name = this.path.split('/').pop();
        if (name.includes('risk')) {
            logger.info({ tag: 'dumpinit' }, `${this.returnAddress}`);
            setTimeout(() => {
                dumpLib('libjiagu.so', true);
            }, 0);
        }
    },
});

attach((x) => ProcMaps.inRange(x.returnAddress), true);
Process.attachModuleObserver({
    onAdded(module) {
        const { base, name, size, path } = module;
        if (!name.includes('libjiagu')) return;
        ProcMaps.addRange({ base: base, size: size });

        hookException([56], {
            onBefore(context, num) {
                if (num === 56) {
                    const path = context.x1.readCString();
                    this.path = path;
                    const mode = context.x2.toInt32();
                    this.mode = mode;
                } else if (num === 62) {
                    const fd = readFdPath(context.x0.toInt32());
                    logger.info({ tag: 'lseek' }, `${fd} +${context.x1.toInt32()} ${context.x2.toUInt32()}`);
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
                        path?.startsWith('/proc/   ') &&
                        (path.endsWith('/maps ') ||
                            path.endsWith('/fd') ||
                            path.endsWith('/task ') ||
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
                    const result = this.buf.readCString(this.bufsize);
                    logger.info({ tag: 'readlinkat' }, `${this.path} -> ${result}`);
                }
            },
        });
    },
});

// biome-ignore lint/complexity/useArrowFunction: don't
rpc.exports.init = function (stage, params: object) {
    const ent = Reflect.ownKeys(params).reduce<PropertyDescriptorMap>((prev, crnt) => {
        const value = Reflect.get(params, crnt);
        Reflect.set(prev, crnt, {
            value: value,
            writable: false,
            configurable: false,
            enumerable: isIterable(value),
        } as PropertyDescriptor);
        return prev;
    }, {} as PropertyDescriptorMap);
    Object.defineProperties(globalThis, ent);
    console.log('init', stage, Text.stringify(params));
};
