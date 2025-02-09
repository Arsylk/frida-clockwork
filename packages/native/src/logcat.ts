import { logger } from '@clockwork/logging';
import { Inject } from './inject.js';
import { addressOf, isInRange, previousReturn } from './index.js';

function hookLogcat(fn?: (this: InvocationContext, msg: string) => void) {
    const liblog = Process.getModuleByName('liblog.so');
    const _isLoggable = Module.getExportByName(null, '__android_log_is_loggable');
    Interceptor.replaceFast(_isLoggable, new NativeCallback(() => 1, 'bool', ['int', 'pointer', 'int']));
    const vsnprintf = Module.getExportByName(null, 'vsnprintf');
    Inject.attachInModule('liblog.so', vsnprintf, {
        onEnter: function (args) {
            this.result = args[0];
        },
        onLeave: function (retval) {
            if (isInRange(liblog, this.returnAddress)) {
                const prevReturn = previousReturn(this.context as Arm64CpuContext);
                if (Inject.isInOwnRange(prevReturn)) {
                    const result = this.result;
                    const msg = `${result.readCString()}`.trimEnd();
                    logger.info({ tag: 'logcat' }, `${msg} ${addressOf(prevReturn)}`);
                    fn?.call(this, msg);
                }
            }
        },
    });
}

export { hookLogcat };
