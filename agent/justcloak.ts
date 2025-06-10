import { Debug, HideMaps as Hide } from '@clockwork/anticloak';
import { memcmp, memmove, ProcMaps } from '@clockwork/cmodules';
import { Linker, Struct, Text, hookException } from '@clockwork/common';
import { dumpLib } from '@clockwork/dump';
import { logger } from '@clockwork/logging';
import * as Native from '@clockwork/native';

Object.defineProperty(globalThis, 'runme', {
    value: Script.nextTick.bind(null, dumpLib.bind(null, 'libjiagu.so')),
});

// JniTrace.attach((x) => Native.Inject.isInOwnRange(x.returnAddress), false);
function ba2hex(b: ArrayBuffer): string {
    const uint8arr = new Uint8Array(b);
    if (!uint8arr) {
        return '';
    }
    let hexStr = '';
    for (let i = 0; i < uint8arr.length; i++) {
        let hex = (uint8arr[i] & 0xff).toString(16);
        hex = hex.length === 1 ? `0${hex}` : hex;
        hexStr += hex;
    }
    return hexStr;
}

Debug.hookPtrace();
Native.Strings.hookStrstr(Native.Inject.isInOwnRange);
Native.Pthread.hookPthread_create();
Process.attachModuleObserver({
    onAdded(module: Module) {
        const { name, base, size, path } = module;
        if (
            (path.startsWith('/data/app/') || path.startsWith('/data/data/')) &&
            !path.includes('/com.google.android.trichromelibrary') &&
            !path.includes('(deleted)')
        ) {
            Native.Inject.ownRanges.push(module);
        }
        logger.info({ tag: 'phdr_init' }, Text.stringify({ name: name, base: base, size: size, path: path }));
        if (name === 'base.odex') {
            Linker.patchSoList((name: string) => name.startsWith('/memfd:') || name.includes(' (deleted)'));
            ProcMaps.addRange(module);
        }
        if (
            [
                'l35cd1c2a.so',
                'libXYLUXam.so',
                'libjiagu.so',
                'l7d15e546.so',
                'libshield.so',
                'libnp.so',
                'libcovault-appsec.so',
                'libmtprotect.so',
            ].includes(name)
        ) {
            ProcMaps.addRange(module);
            Native.log(Module.getGlobalExportByName('uncompress'), 's', {
                call(args) {
                    this.arg0 = args[0];
                },
                ret(retval) {
                    logger.info({ tag: 'uncompress' }, hexdump(this.arg0));
                },
            });
            Native.log(base.add(0x159104), 'hp');
            Native.log(base.add(0x44324), '0ppp4', {
                transform: {
                    '0': (ptr) => ba2hex(ptr.readByteArray(0x18)),
                    '4': (ptr) => DebugSymbol.fromAddress(ptr.readPointer()).toString(),
                },
                call(args) {
                    const ctx = this.context as Arm64CpuContext;
                    logger.info(
                        { tag: '0x44324' },
                        `\n${Text.stringify({ pc: ctx.pc.sub(base), lr: ctx.lr.sub(base), fp: ctx.fp.sub(base) })}`,
                    );
                },
            });
            Interceptor.attach(
                Libc.memmove,
                memmove as InvocationListenerCallbacks | InstructionProbeCallback,
            );

            Interceptor.attach(Libc.memcmp, memcmp as InvocationListenerCallbacks | InstructionProbeCallback);

            hookException([56, 62], {
                onBefore(context, num) {
                    if (num === 56) {
                        const path = context.x1.readCString();
                        this.path = path;
                        const mode = context.x2.toInt32();
                        this.mode = mode;
                        logger.info({ tag: '__openat' }, `${path} ${context.x0}`);
                    } else if (num === 62) {
                        const fd = Native.readFdPath(context.x0.toInt32());
                        logger.info({ tag: 'lseek' }, `${fd}!${context.x1} ${context.x2.toUInt32()}`);
                    } else if (num === 63 || num === 67) {
                        const fd = context.x0.toInt32();
                        const fds = Native.readFdPath(fd);
                        this.fd = fds;
                        this.buf = context.x1;
                        this.size = context.x2.toInt32();
                        this.tell = Libc.lseek(fd, NULL, 1);
                    } else if (num === 78) {
                        this.path = context.x1.readCString();
                        this.buf = context.x2;
                        this.bufsize = context.x3.toInt32();
                    } else if (num === 130) {
                        logger.info({ tag: 'tkill' }, `${context.x0.toInt32()}`);
                    } else if (num === 134) {
                        logger.info({ tag: 'rt_sigaction' }, `${context.x0.toInt32()}`);
                    }
                },
                onAfter(context, num) {
                    if (num === 56) {
                        const path = this.path;
                        if (path?.endsWith('/maps')) {
                            const numFd = context.x0.toInt32();
                            if (numFd > 0) {
                                Libc.close(numFd);
                            }
                            const arg1ptr = this.rawargs.add((1 + 1) * Process.pointerSize);
                            arg1ptr.writePointer(Memory.allocUtf8String('/dev/nya'));
                            this.redo_call();
                        }
                        if (path?.endsWith('classes2.dex')) {
                            const buf = Memory.alloc(0xff);
                            Libc.pread(context.x0.toInt32(), buf, 0xff, 0);
                            logger.info({ tag: 'dex' }, ba2hex(buf.readByteArray(0xff)));
                            dumpLib(name, true);
                        }
                    } else if (num === 63) {
                        const length = context.x0.toInt32();
                        const content = this.buf.readCString(length);
                        const patch = content.replace(/frida/gi, 'nyasi');
                        // this.buf.writeUtf8String(patch);
                        logger.info(
                            { tag: 'read' },
                            `${this.fd}!${this.tell} ${length}:${this.size} -> \n${content}`,
                        );
                    } else if (num === 67) {
                        const length = context.x0.toInt32();
                        const content = hexdump(this.buf, { length: length, ansi: true });
                        const patch = content.replace(/frida/gi, 'nyasi');
                        // this.buf.writeUtf8String(patch);
                        logger.info({ tag: 'pread64' }, `${this.fd} -> \n${content}`);
                    } else if (num === 78) {
                        const result = this.buf.readCString(this.bufsize);
                        logger.info({ tag: 'readlinkat' }, `${this.path} -> ${result}`);
                    }
                },
            });
            // Native.log(Process.getModuleByName('libdl.so').getExportByName('dlopen'), 'si');

            const c: (t: string) => string = (t) => t;
            // const c_strlen = (x: string) =>
            //     new CModule(x, {
            //         frida_log: new NativeCallback(
            //             (str) => {
            //                 const msg = str.readCString();
            //                 logger.info({ tag: 'strlen' }, `${msg}`);
            //             },
            //             'void',
            //             ['pointer'],
            //         ),
            //     }) as any;
            // Interceptor.attach(
            //     Libc.strlen,
            //     c_strlen(
            //         c(`
            //       #include <gum/guminterceptor.h>
            //       #include <stdio.h>
            //       typedef unsigned long long u64;
            //       void* BASE = (void *) ${base};
            //       void* SIZE = (void *) ${size};
            //
            //       typedef struct _IcState IcState;
            //       struct _IcState {
            //         char *arg0;
            //         void *retaddr;
            //         int log;
            //       };
            //
            //       extern void frida_log(void *str);
            //       static void mklog(const char *format, ...) {
            //           gchar *message;
            //           va_list args;
            //           va_start(args, format);
            //           message = g_strdup_vprintf(format, args);
            //           va_end(args);
            //           frida_log(message);
            //           g_free(message);
            //       }
            //
            //       void onEnter(GumInvocationContext * ic) {
            //         IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
            //         is->arg0 = gum_invocation_context_get_nth_argument(ic, 0);
            //         is->retaddr = (void *) gum_invocation_context_get_return_address(ic);
            //         if ((u64) BASE <= (u64)is->retaddr && (u64)BASE + (u64)SIZE > (u64)is->retaddr) {
            //             is->log = 1;
            //         } else {
            //             is->log = 0;
            //         }
            //       };
            //       void onLeave(GumInvocationContext * ic) {
            //         IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
            //         u64 retval = (u64) gum_invocation_context_get_return_value(ic);
            //         if (is->log == 1) {
            //             mklog("%s = %d %p", is->arg0, retval, (u64)is->retaddr-(u64)BASE);
            //         }
            //       };
            //     `),
            //     ),
            // );

            type ntype = NativeFunction<number, [NativePointer, NativePointer, NativePointer]>;
            const argpget = (original: ntype) =>
                new NativeCallback(
                    // biome-ignore lint/complexity/useArrowFunction:
                    function (a0, a1, a2) {
                        const dlinfo = Struct.Linker.dl_phdr_info(a0);
                        logger.info(
                            { tag: 'dl_iterate_phdr', id: 'callback' },
                            `${Text.stringify(Struct.toObject(dlinfo))}`,
                        );
                        return original(a0, a1, a2);
                    },
                    'int',
                    ['pointer', 'pointer', 'pointer'],
                );
            Native.log(Libc.dl_iterate_phdr, 'ph', {
                predicate: Native.bindInRange(module),
                call(args) {
                    args[0] = argpget(new NativeFunction(args[0], 'int', ['pointer', 'pointer', 'pointer']));
                },
            });
            // Native.Files.hookAccess(Native.bindInRange(module));
            // Native.Files.hookOpendir(Native.bindInRange(module));
            // Native.Files.hookDirent(Native.bindInRange(module));
            Native.log(Libc.mmap, 'pi23', {
                predicate: Native.bindInRange(module),
                transform: {
                    2: (ptr) => {
                        if (!ptr) return 'PROT_NONE';
                        return (
                            [
                                [1, 'PROT_READ'],
                                [2, 'PROT_WRITE'],
                                [4, 'PROT_EXEC'],
                            ] as const
                        )
                            .filter(([f, _]) => f & Number(ptr))
                            .map(([_, s]) => s)
                            .join(' | ');
                    },
                    3: (ptr) => {
                        return (
                            [
                                [1, 'MAP_SHARED'],
                                [2, 'MAP_PRIVATE'],
                                [3, 'MAP_SHARED_VALIDATE'],
                                [8, 'MAP_DROPPABLE'],
                            ] as const
                        )
                            .filter(([f, _]) => f & Number(ptr))
                            .map(([_, s]) => s)
                            .join(' | ');
                    },
                },
                call(args) {
                    this.size = args[1].toInt32();
                },
                ret(retval) {
                    const cmd = `adb shell dd if=/proc/${Process.id}/mem of=/data/local/tmp/${retval}_${retval.add(this.size)}.mem bs=1 skip=${retval.toUInt32()} count=${this.size}`;
                    logger.info({ tag: 'adb' }, cmd);
                },
            });
        }
    },
});
