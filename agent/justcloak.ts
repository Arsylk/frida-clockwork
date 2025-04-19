import { ProcMaps } from '@clockwork/cmodules';
import { hookException, Text } from '@clockwork/common';
import { logger } from '@clockwork/logging';
import * as Native from '@clockwork/native';

Native.Inject.onPrelinkOnce((module) => {
    const { name, base, size, path } = module;
    logger.info({ tag: 'phdr_init' }, Text.stringify({ name: name, base: base, size: size, path: path }));
    if (name === 'libjiagu.so') {
        const mem = Memory.allocUtf8String('/data/data/io.liankong.riskdetector/fakemaps');
        Interceptor.attach(Module.getGlobalExportByName('fopen64'), {
            onEnter(args) {
                const addr = Native.addressOf(this.returnAddress);
                const path = args[0].readCString();
                if (path?.startsWith('/proc/') && path.endsWith('/maps') && addr?.includes('libjiagu')) {
                    args[0] = mem;
                }
                logger.info({ tag: 'fopen64' }, `${path} ${addr}`);
            },
        });
        hookException([56, 63, 67, 130], {
            onBefore(context, num) {
                if (num === 56) {
                    logger.info({ tag: '__openat' }, `${context.x1.readCString()} ${context.x2.toInt32()}`);
                } else if (num === 63 || num === 67) {
                    const fd = Native.readFdPath(context.x0.toInt32());
                    this.fd = fd;
                    this.buf = context.x1;
                } else if (num === 130) {
                    logger.info({ tag: 'tkill' }, `${context.x0.toInt32()}`);
                }
            },
            onAfter(context, num) {
                if (num === 63) {
                    const length = context.x0.toInt32();
                    const content = this.buf.readCString(length);
                    const patch = content.replace(/frida/gi, 'nyasi');
                    this.buf.writeUtf8String(patch);
                    logger.info({ tag: 'read' }, `${this.fd} -> ${content === patch}`);
                } else if (num === 67) {
                    const length = context.x0.toInt32();
                    const content = this.buf.readCString(length);
                    const patch = content.replace(/frida/gi, 'nyasi');
                    this.buf.writeUtf8String(patch);
                    logger.info({ tag: 'pread64' }, `${this.fd} -> ${content === patch}`);
                }
            },
        });
    }
});
