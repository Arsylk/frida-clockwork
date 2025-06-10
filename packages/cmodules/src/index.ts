import { Libc } from '@clockwork/common';
import { logger } from '@clockwork/logging';
import _memcmp from '@src/memcmp.c';
import _memmove from '@src/memmove.c';
import _procmaps from '@src/procmaps.c';
import _inject from '@src/inject.c';

function base64(strs: string) {
    const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    const str = strs.replace(/\s+/g, '').replace(/=/g, ''); // Remove padding as well
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

function callback<T extends CModule>(cmodule: T) {
    return cmodule as T & InvocationListenerCallbacks;
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

namespace ProcMaps {
    const rangesSize = Process.pointerSize * 2 * 8;
    const ranges = Memory.alloc(rangesSize);
    Memory.protect(ranges, rangesSize, 'rwx');
    export const cm = new CModule(fbase64(_procmaps), {
        frida_log: get_frida_log('procmaps'),
        perror: Module.getGlobalExportByName('perror'),
        _Unwind_Backtrace: Module.getGlobalExportByName('_Unwind_Backtrace'),
        _Unwind_GetIP: Module.getGlobalExportByName('_Unwind_GetIP'),
        dl_soinfo_get_soname: LinkerSym.__dl__ZNK6soinfo10get_sonameEv,
        dl_solist_get_head: LinkerSym.__dl__Z15solist_get_headv,
        sprintf: Libc.sprintf,
        isprint: Libc.isprint,
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
        getranges: new NativeCallback(() => ranges, 'pointer', []),
    });
    const _get_backtrace = new NativeFunction(cm.get_backtrace, 'pointer', ['pointer']);
    const _addressOf = new NativeFunction(cm.addressOf, 'pointer', ['pointer']);
    const _isFridaAddress = new NativeFunction(cm.isFridaAddress, 'bool', ['pointer']);
    const _inRange = new NativeFunction(cm.inRange, 'bool', ['pointer']);

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

    export function addRange(range: { base: NativePointer; size: number }) {
        const count = ranges.readU32();
        const addr = ranges.add(4 + Process.pointerSize * 2 * count);
        0x171f88;
        addr.writePointer(range.base);
        addr.add(Process.pointerSize).writeU64(range.size);
        ranges.writeU32(count + 1);
        // console.log(hexdump(ranges));
    }

    export function inRange(ptr: NativePointer): boolean {
        if (!ptr || ptr === NULL || `${ptr}` === '0x0') return false;
        return _inRange(ptr) !== 0;
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

const memcmp = callback(
    new CModule(fbase64(_memcmp), {
        frida_log: get_frida_log('memcmp'),
        sprintf: Libc.sprintf,
        isprint: Libc.isprint,
        inRange: ProcMaps.cm.inRange,
        addressOf: ProcMaps.cm.addressOf,
    }),
);

const memmove = callback(
    new CModule(fbase64(_memmove), {
        frida_log: get_frida_log('memmove'),
        sprintf: Libc.sprintf,
        isprint: Libc.isprint,
        inRange: ProcMaps.cm.inRange,
        addressOf: ProcMaps.cm.addressOf,
    }),
);

export { memcmp, memmove, ProcMaps, fbase64, LinkerSym };
