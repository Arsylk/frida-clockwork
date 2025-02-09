import { Libc } from '@clockwork/common';
import { logger } from '@clockwork/logging';
import _memcmp from '@src/memcmp.c';
import _procmaps from '@src/procmaps.c';
import _inject from '@src/inject.c';

function base64(str: string) {
    const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    str = str.replace(/\s+/g, '').replace(/=/g, ''); // Remove padding as well
    const base64Map = {};
    for (let i = 0; i < base64Chars.length; i++) {
        base64Map[base64Chars[i]] = i;
    }

    let binaryString = '';
    for (let i = 0; i < str.length; i++) {
        const value = base64Map[str[i]]; // Get the 6-bit value
        binaryString += value.toString(2).padStart(6, '0'); // Convert to 6-bit binary string
    }

    let output = '';
    for (let i = 0; i < binaryString.length; i += 8) {
        const byte = binaryString.slice(i, i + 8); // Get an 8-bit chunk
        const charCode = Number.parseInt(byte, 2); // Convert the binary chunk to a decimal value
        output += String.fromCharCode(charCode); // Convert the decimal value to an ASCII character
    }

    return output;
}

function fbase64(input: string) {
    const fixed = input.substring(input.indexOf(',') + 1);
    return base64(fixed);
}

const get_frida_log = (tag: string) =>
    new NativeCallback(
        (str) => {
            const msg = str.readCString();
            logger.info({ tag: tag }, `${msg}`);
        },
        'void',
        ['pointer'],
    );

const LinkerSym = Object.assign(
    {},
    ...Process.getModuleByName('linker64')
        .enumerateSymbols()
        .map(({ name, address }) => {
            return { [name]: address };
        }),
);

const memcmp = new CModule(fbase64(_memcmp), {
    frida_log: get_frida_log('memcmp'),
});

namespace ProcMaps {
    export const cm = new CModule(fbase64(_procmaps), {
        frida_log: get_frida_log('procmaps'),
        perror: Module.getExportByName(null, 'perror'),
        _Unwind_Backtrace: Module.getExportByName(null, '_Unwind_Backtrace'),
        _Unwind_GetIP: Module.getExportByName(null, '_Unwind_GetIP'),
        dl_soinfo_get_soname: LinkerSym.__dl__ZNK6soinfo12get_realpathEv,
        dl_solist_get_head: LinkerSym.__dl__Z15solist_get_headv,
        close: Libc.close,
        fclose: Libc.fclose,
        fdopen: Libc.fdopen,
        fgets: Libc.fgets,
        strchr: Libc.strchr,
        strlen: Libc.strlen,
        strcpy: Libc.strcpy,
        strdup: Libc.strdup,
        strtok_r: Libc.strtok_r,
        strtoul: Libc.strtoul,
        syscall: Libc.syscall,
        dladdr: Libc.dladdr,
        __cxa_demangle: Libc.__cxa_demangle,
    });
    const _get_backtrace = new NativeFunction(cm.get_backtrace, 'pointer', ['pointer']);
    const _addressOf = new NativeFunction(cm.addressOf, 'pointer', ['pointer']);
    const _isFridaAddress = new NativeFunction(cm.isFridaAddress, 'bool', ['pointer']);

    export function backtraceOf(ptr: NativePointer): string {
        return _get_backtrace(ptr).readCString() as string;
    }

    export function addressOf(ptr: NativePointer): string {
        return _addressOf(ptr).readCString() as string;
    }

    export function isFridaAddress(ptr: NativePointer): boolean {
        return _isFridaAddress(ptr) !== 0;
    }

    export function printStacktrace(context?: CpuContext, tag?: string) {
        const stack = Thread.backtrace(context, Backtracer.FUZZY);
        let trace = '';
        for (const ptr of stack) {
            trace += `${this.addressOf(ptr)}\n\t`;
        }
        logger.info({ tag: tag ?? 'stack' }, trace);
    }
}

namespace Inject {
    export const cm = new CModule(
        `
    void register_constructor_callback(void*data) {}
`,
        {
            frida_log: get_frida_log('inject'),
        },
    );
    const _registerCallback = new NativeFunction(cm.register_constructor_callback, 'void', ['pointer']);

    export function registerCallback(
        cb: NativeCallbackImplementation<void, [UInt64, NativePointer, NativePointer, NativePointer]>,
    ) {
        // this._registerCallback(new NativeCallback(cb, 'void', ['size_t', 'pointer', 'pointer', 'pointer']));
    }
}

// namespace SvcHook {
//     const cm = new CModule('');
//     //@ts-ignore
//     const _svc_hook =
//         //@ts-ignore
//         cm === null ? new NativeFunction(cm.svc_hook as any, 'uint', ['uint', 'pointer', 'pointer']) : null;
//
//     export function svc_hook(
//         sysno: number,
//         before?: (...args: NativePointer[]) => void,
//         after?: (...args: NativePointer[]) => void,
//     ) {
//         const before_func =
//             (before &&
//                 new NativeCallback(
//                     (...args: NativePointer[]) => {
//                         before(...args);
//                         return NULL;
//                     },
//                     'pointer',
//                     ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
//                 )) ||
//             NULL;
//         const after_func =
//             (after &&
//                 new NativeCallback(
//                     (...args: NativePointer[]) => {
//                         after(...args);
//                         return NULL;
//                     },
//                     'pointer',
//                     ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
//                 )) ||
//             NULL;
//         // logger.info({ tag: 'svchook' }, `${_svc_hook(sysno, before_func, after_func)}`);
//     }
// }

export { memcmp, ProcMaps, Inject, fbase64, LinkerSym };
