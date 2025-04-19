import { logger } from '@clockwork/logging';
import { Inject } from './inject.js';

function hookLogcat(fn?: (this: InvocationContext, msg: string) => void) {
    const liblog = Process.getModuleByName('liblog.so');
    //const _isLoggable = Module.getGlobalExportByName('__android_log_is_loggable');
    //Interceptor.replaceFast(_isLoggable, new NativeCallback(() => 1, 'bool', ['int', 'pointer', 'int']));
    const _logPrint = Module.getGlobalExportByName('__android_log_print');
    Interceptor.attach(_logPrint, {
        onEnter: function (args) {
            this.resultPtr = this.context.sp.sub(1112);
            //const tag = (this.tag = args[1].readCString()) ?? '';
            const msg = (this.msg = args[2].readCString()) ?? '';
            //logger.info(`${this.resultPtr} +- ${args[1]} = ${args[1].sub(this.resultPtr)}` )
        },
        onLeave(retval) {
            logger.info({ tag: 'logcat' }, `${this.resultPtr.readCString()}`);
        },
    });
    const vsnprintf = Module.getGlobalExportByName('vsnprintf');
    Inject.attachInModule('liblog.so', vsnprintf, {
        onEnter: function (args) {
            this.result = args[0];
        },
        onLeave: function (retval) {
            if (liblog.base <= this.returnAddress && liblog.base.add(liblog.size) >= this.returnAddress) {
                const result = this.result;
                const msg = `${result.readCString()}`.trimEnd();
                logger.info({ tag: 'logcat' }, msg);
                fn?.call(this, msg);
                // MemoryAccessMonitor.enable(
                //     { base: result, size: 1024 },
                //     {
                //         onAccess(details) {
                //             logger.info({ tag: 'memwatch', id: `${result}` }, JSON.stringify(details));
                //         },
                //     },
                // );
            }
        },
    });
}

export { hookLogcat };
