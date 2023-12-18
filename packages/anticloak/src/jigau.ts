import * as Native from '@clockwork/native';
import { logger } from '@clockwork/logging';

const NativeLibName = 'libjiagu_64.so';
const Arm64Pattern = '00 03 3f d6 a0 06 00 a9';

/** can be super finniky about other native functions hooked befor it patches the memory */
function memoryPatch(name: string = NativeLibName) {
    let hookNow = false;
    Native.Inject.afterInitArray((name) => {
        if (name?.includes(NativeLibName)) {
            hookNow = true;
        }
        if (hookNow) {
            let module: Module | null = null;
            if (hookNow && (module = Process.findModuleByName(NativeLibName))) {
                Memory.scan(module.base, module.size, Arm64Pattern, {
                    onMatch: function (found) {
                        Interceptor.attach(found, function (args) {
                            Memory.protect(args[0], Process.pointerSize, 'rwx');
                            try {
                                const arg0 = args[0].readCString();
                                if (arg0?.includes('/proc/') && arg0?.includes('/maps')) {
                                    args[0].writeUtf8String('/proc/self/cmdline');
                                }
                            } catch (e) {}
                        });
                    },
                    onComplete: function () {
                        logger.info({ tag: 'jigau' }, 'frida detection nypassed');
                    },
                });
            }
        }
    });
}

export { memoryPatch };
