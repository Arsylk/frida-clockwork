import * as JniTrace from '@clockwork/jnitrace';
import { Text } from '@clockwork/common';
import { log, stalk } from '@clockwork/native';
import { logger } from '@clockwork/logging';
import Java from 'frida-java-bridge';
Java.deoptimizeEverything();

const isInRange = (module: { base: NativePointer; size: number }, ptr: NativePointer) =>
    ptr && module && ptr >= module.base && module.base.add(module.size) > ptr;
const ownRanges: { base: NativePointer; size: number }[] = [];
Process.attachModuleObserver({
    onAdded(module: Module) {
        const { name, base, size, path } = module;
        if (
            (path.startsWith('/data/app/') || path.startsWith('/data/data/')) &&
            !path.includes('/com.google.android.trichromelibrary') &&
            !path.includes('libconscrypt_gmscore_jni.so') &&
            !path.includes('(deleted)') &&
            !path.includes('libd7B2A6FE44B27.so')
        ) {
            logger.info(
                {
                    tag: 'phdr_push',
                },
                `${Text.stringify({ name: module.name, base: module.base, size: module.size, path: module.path })}`,
            );
            ownRanges.push(module);
        }

        if (name === 'libcom.common.core.so') {
            log(base.add(0x426bc), 'pp', {
                call(args) {
                    stalk(this.threadId, base);
                },
                ret(retval) {
                    Stalker.unfollow(this.threadId);
                },
            });
        }
    },
});

setTimeout(async () => {
    JniTrace.attach((x) => {
        for (const range of ownRanges) {
            if (isInRange(range, x.returnAddress)) {
                return true;
            }
        }
    }, true);
}, 0);
