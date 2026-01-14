import Java from 'frida-java-bridge';
import { ClassesString, stacktrace, stacktraceList, Text, tryNull } from '@clockwork/common';
import { ClassLoader, hook } from '@clockwork/hooks';
import { JNI, asFunction } from '@clockwork/jnitrace';
import { Color, logger } from '@clockwork/logging';
import { getSelfFiles } from '@clockwork/native';
const { orange } = Color.use();

function hookInMemoryDexDump() {
  ClassLoader.perform(() => {
    const _method = Java.use(ClassesString.InMemoryDexClassLoader);
    const ov = _method.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.String', 'java.lang.ClassLoader');
    ov.implementation = function (...args) {
      const buffer = args[0];
      logger.info({ tag: 'inmemory' }, `called: ${ov}`);
      const array = Reflect.has(buffer, 'length') ? buffer : [buffer];
      for (const buf of array) {
        const path = `${getSelfFiles()}/classes_${buf.$h}.dex`;
        buf.position(0);
        const size = buf.remaining();

        const jarr = Java.use('[B').$new();
        buf.get(jarr);
        logger.info({ tag: 'inmemory' }, `got: ${jarr}`);
        //@ts-ignore
        File.writeAllBytes(path, new Uint8Array(jarr).buffer);
        logger.info({ tag: 'inmemory' }, `wrote: ${path} `);

        buf.position(0);
      }
      return ov.call(this, ...args);
    };
    //
    //     try {
    //       const jniEnv = Java.vm.getEnv().handle;
    //       const NewByteArray = asFunction(jniEnv, JNI.NewByteArray);
    //       const FindClass = asFunction(jniEnv, JNI.FindClass);
    //       const GetMethodID = asFunction(jniEnv, JNI.GetMethodID);
    //       const CallObjectMethod = asFunction(jniEnv, JNI.CallObjectMethod);
    //       const GetByteArrayElements = asFunction(jniEnv, JNI.GetByteArrayElements);
    //
    //       const jcls = FindClass(jniEnv, Memory.allocUtf8String('java/nio/ByteBuffer'));
    //       const jmth = GetMethodID(
    //         jniEnv,
    //         jcls,
    //         Memory.allocUtf8String('get'),
    //         Memory.allocUtf8String('([B)Ljava/nio/ByteBuffer;'),
    //       );
    //       const jarr = NewByteArray(jniEnv, size);
    //       CallObjectMethod(jniEnv, buf.$h, jmth, jarr);
    //       const jbytes = GetByteArrayElements(jniEnv, jarr, ptr(0x0));
    //       const bytes = jbytes.readByteArray(size);
    //
    //       //@ts-ignore
    //       File.writeAllBytes(path, new Uint8Array(bytes).buffer);
    //       logger.info(
    //         { tag: 'inmemory' },
    //         `saving ${path} size: ${Text.toByteSize(size)} ${orange(stacktrace())}`,
    //       );
    //     } catch (e) {
    //       logger.info({ tag: 'inmemory', id: 'err' }, `not saved ${path} size: ${Text.toByteSize(size)}`);
    //       logger.info({ tag: 'inmemory', id: 'err' }, `${e}`);
    //     }
    //   }
    //
    //   const retval = _method.$init.call(this, ...args);
    //   return retval;
    // };
  });
}

export { hookInMemoryDexDump };
