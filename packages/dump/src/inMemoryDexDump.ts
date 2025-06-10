import Java from 'frida-java-bridge';
import { ClassesString, Text, tryNull } from '@clockwork/common';
import { hook } from '@clockwork/hooks';
import { JNI, asFunction } from '@clockwork/jnitrace';
import { logger } from '@clockwork/logging';
import { getSelfFiles } from '@clockwork/native';

function hookInMemoryDexDump() {
    hook(Classes.InMemoryDexClassLoader, '$init', {
        predicate: (o, i) => i === 0,
        before(_method, buffer, classLoader) {
            const array = Reflect.has(buffer, 'length') ? buffer : [buffer];
            for (const buf of array) {
                const path = `${getSelfFiles()}/classes_${buf.$h}.dex`;
                buf.position(0);
                const size = buf.remaining();

                try {
                    const N = Java.use('java.nio.ByteBuffer').class.getDeclaredField('hb');
                    N.setAccessible(true);
                    const hb = N.get(buf);
                    const jniEnv = Java.vm.getEnv().handle;
                    const L = asFunction(jniEnv, JNI.NewLocalRef);
                    const ghb = L(jniEnv, hb.$h ?? hb.handle);
                    //@ts-ignore
                    File.writeAllBytes(path, ghb);
                    logger.info({ tag: 'inmemory' }, `saving ${path} size: ${Text.toByteSize(size)}`);
                } catch (e) {
                    logger.info(
                        { tag: 'inmemory', id: 'err' },
                        `not saved ${path} size: ${Text.toByteSize(size)}`,
                    );
                }
            }
        },
    });
}

export { hookInMemoryDexDump };
