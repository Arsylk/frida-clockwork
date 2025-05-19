import { ProcMaps } from '@clockwork/cmodules';
import { hookException, Text } from '@clockwork/common';
import { dumpLib } from '@clockwork/dump';
import { logger } from '@clockwork/logging';
import * as Native from '@clockwork/native';

Object.defineProperty(globalThis, 'runme', {
    value: Script.nextTick.bind(null, dumpLib.bind(null, 'libjiagu.so')),
});

Process.attachModuleObserver({
    onAdded(module) {
        const { name, base, size, path } = module;
        logger.info({ tag: 'phdr_init' }, Text.stringify({ name: name, base: base, size: size, path: path }));
        if (['libjiagu.so', 'l7d15e546.so', 'libshield.so', 'libnp.so'].includes(name)) {
            // const mem = Memory.allocUtf8String('/data/data/io.liankong.riskdetector/fakemaps');
            // const manic = (ptr: NativePointer) =>
            //     setInterval(() => logger.info({ tag: 'hbrk' }, `${DebugSymbol.fromAddress(ptr)}`), 1);
            // manic(base.add(0x1d1b60));
            logger.info({ tag: 'stack' }, `wbstack_arm64 -w ${base.add(0x1d1b60)}:x[ptr] --stack --regs`);

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
                    if (this.size === 7174384) {
                        Thread.sleep(100);
                    }
                    // logger.info({ tag: 'save' }, `${filep}`);
                    //     if (!Memory.protect(retval, this.size, 'r'))
                    //         for (let i = 0; i < this.size; i += 0x100) Memory.protect(retval.add(i), 0x100, 'r');
                    //     File.writeAllBytes(filep, retval.readByteArray(this.size));
                },
            });
            hookException([56], {
                onBefore(context, num) {
                    if (num === 56) {
                        const path = context.x1.readCString();
                        this.path = path;
                        const mode = context.x2.toInt32();
                        this.mode = mode;
                        logger.info({ tag: '__openat' }, `${path} ${mode}`);
                    } else if (num === 62) {
                        const fd = Native.readFdPath(context.x0.toInt32());
                        logger.info(
                            { tag: 'lseek' },
                            `${fd} +${context.x1.toInt32()} ${context.x2.toUInt32()}`,
                        );
                    } else if (num === 63 || num === 67) {
                        const fd = Native.readFdPath(context.x0.toInt32());
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
                        if (path?.startsWith('/proc/') && path.endsWith('/maps')) {
                            const numFd = context.x0.toInt32();
                            if (numFd > 0) {
                                Libc.close(numFd);
                            }
                            const arg1ptr = this.rawargs.add((1 + 1) * Process.pointerSize);
                            arg1ptr.writePointer(Memory.allocUtf8String('/dev/null'));
                            this.redo_call();
                        }
                        logger.info({ tag: '__openat', id: 'fd' }, `${context.x0}`);
                    } else if (num === 63) {
                        const length = context.x0.toInt32();
                        const content = this.buf.readCString(length);
                        const patch = content.replace(/frida/gi, 'nyasi');
                        this.buf.writeUtf8String(patch);
                        logger.info({ tag: 'read' }, `${this.fd} -> ${content === patch}`);
                    } else if (num === 67) {
                        const length = context.x0.toInt32();
                        const content = hexdump(this.buf, { length: length, ansi: true });
                        // const patch = content.replace(/frida/gi, 'nyasi');
                        // this.buf.writeUtf8String(patch);
                        logger.info({ tag: 'pread64' }, `${this.fd} -> ${content}`);
                    } else if (num === 78) {
                        const result = this.buf.readCString(this.bufsize);
                        logger.info({ tag: 'readlinkat' }, `${this.path} -> ${result}`);
                    }
                },
            });
        }
    },
});
