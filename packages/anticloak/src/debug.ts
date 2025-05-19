import { Libc, tryNull } from '@clockwork/common';
import { always, hook } from '@clockwork/hooks';
import { logger } from '@clockwork/logging';
import { addressOf } from '@clockwork/native';

function hookPtrace() {
    const replace = Interceptor.replaceFast(
        Libc.ptrace,
        new NativeCallback(
            function (
                this: CallbackContext,
                request: number,
                pid: number,
                addr: NativePointer,
                data: NativePointer,
            ) {
                logger.info(
                    { tag: 'ptrace' },
                    `${request} ${pid} ${addr} ${data} ${addressOf(this.returnAddress)}`,
                );
                return -1;
            },
            'long',
            ['int', 'int', 'pointer', 'pointer'],
        ),
    );
}

function hookVMDebug() {
    hook(Classes.VMDebug, 'isDebuggerConnected', { replace: always(false) });
    hook(Classes.VMDebug, 'isDebuggingEnabled', { replace: always(false) });
    hook(Classes.VMDebug, 'lastDebuggerActivity', { replace: always(-1) });
}

function hookDigestEquals() {
    hook(Classes.MessageDigest, 'equals', {
        replace(method, ...args) {
            return (
                tryNull(() => {
                    const thisClazz = Reflect.get(this, '$className');
                    const otherClazz = Reflect.get(args[0], '$className');
                    return thisClazz === otherClazz;
                }) ?? false
            );
        },
    });
}

function hookVerify() {
    hook(Classes.Signature, 'verify', { replace: always(true) });
}

export { hookDigestEquals, hookPtrace, hookVerify, hookVMDebug };
