import { isNully, Libc } from '@clockwork/common';
import { logger } from '@clockwork/logging';
import _strlen from '@src/strlen.c';
import _memcmp from '@src/memcmp.c';
import _memmove from '@src/memmove.c';
import _fgets from '@src/fgets.c';
import _procmaps from '@src/procmaps.c';
import _inject from '@src/inject.c';
import _elfheader from '@src/elfheader.c';
import _sofixer from '@src/sofixer.c';

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

function callback<T extends CModule>(cmodule: T, init?: (cmodule: T) => void) {
  init?.(cmodule);
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
  const rangesSize = Process.pointerSize * 2 * 512;
  const ranges = Memory.alloc(rangesSize);
  Memory.protect(ranges, rangesSize, 'rwx');
  export const cm = new CModule(fbase64(_procmaps), {
    frida_log: get_frida_log('procmaps'),
    dl_soinfo_get_soname: new NativeCallback(
      function (soinfo) {
        return Memory.allocUtf8String('nya');
      },
      'pointer',
      ['pointer'],
    ),
    dl_solist_get_head: LinkerSym['__dl__Z15solist_get_headv'],
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
      trace += `${this.addressOf(ptr)} ${DebugSymbol.fromAddress(ptr)}\n\t`;
    }
    logger.info({ tag: tag ?? 'stack' }, trace);
  }

  export function addRange(range: { base: NativePointer; size: number }) {
    try {
      const count = ranges.readU32();
      const addr = ranges.add(4 + Process.pointerSize * 2 * count);
      addr.writePointer(range.base);
      addr.add(Process.pointerSize).writeU64(range.size);
      ranges.writeU32(count + 1);
      logger.info({ tag: 'range' }, `${range.base}-${range.base.add(range.size)} #${count}`);
    } catch (e) {}
  }

  export function inRange(ptr: NativePointer): boolean {
    if (!ptr || ptr === NULL || `${ptr}` === '0x0') return false;
    return _inRange(ptr) !== 0;
  }
}

// WIP: having memory access issues, but when it can read it resolves more than `addressOf` would
namespace ElfHeader {
  export const cm = new CModule(fbase64(_elfheader), {
    frida_log: get_frida_log('procmaps'),
    stat: Libc.stat,
    fopen: Libc.fopen,
    fseek: Libc.fseek,
    fread: Libc.fread,
    sscanf: Libc.sscanf,
    strstr: Libc.strstr,
    malloc: Libc.malloc,
    realloc: Libc.realloc,
    strncpy: Libc.strncpy,
    strrchr: Libc.strrchr,
    fgets: Libc.fgets,
    fclose: Libc.fclose,
    calloc: Libc.calloc,
    free: Libc.free,
    addressOf: ProcMaps.cm.addressOf,
    ensureReadable: new NativeCallback(
      function (addr: NativePointer) {
        return NULL;
        // const sec = Memory.queryProtection(addr);
        // const pages = Math.floor(Number(addr) / Process.pageSize);
        // const pagee = pages + Process.pageSize;
        // // logger.info({ tag: 'ensurereadable' }, `addr: ${addr} page: ${ptr(pages)}-${ptr(pagee)}`);
        // return sec.includes('r') ? ptr(0x1) : ptr(0x0);
      },
      'pointer',
      ['pointer'],
    ),
  });
  const _resolve_address = new NativeFunction(cm.resolve_address, 'pointer', ['pointer']);

  export function resolve_address(ptr: NativePointer) {
    if (!ptr || ptr === NULL || `${ptr}` === '0x0') return null;
    return _resolve_address(ptr)?.readCString() ?? null;
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

const fgets = callback(
  new CModule(fbase64(_fgets), {
    frida_log: get_frida_log('fgets'),
    syscall: Libc.syscall,
    snprintf: Libc.snprintf,
    strstr: Libc.strstr,
    fileno: Libc.fileno,
    inRange: ProcMaps.cm.inRange,
    addressOf: ProcMaps.cm.addressOf,
  }),
);

const strlen = callback(
  new CModule(fbase64(_strlen), {
    frida_log: get_frida_log('strlen'),
    strstr: Libc.strstr,
    sprintf: Libc.sprintf,
    isprint: Libc.isprint,
    inRange: ProcMaps.cm.inRange,
    addressOf: ProcMaps.cm.addressOf,
    limits: Memory.alloc(4 * 2),
  }),
  (cm) => {
    cm.limits.writeU32(0);
    cm.limits.add(0x4).writeU32(160);
  },
);

const memcmp = callback(
  new CModule(fbase64(_memcmp), {
    frida_log: get_frida_log('memcmp'),
    sprintf: Libc.sprintf,
    isprint: Libc.isprint,
    inRange: ProcMaps.cm.inRange,
    addressOf: ProcMaps.cm.addressOf,
  }),
);

const ptr = Memory.alloc(128);
Memory.protect(ptr, 128, 'rwx');
Libc.memset(ptr, 0, 128);
const memmove = callback(
  new CModule(fbase64(_memmove), {
    frida_log: get_frida_log('memmove'),
    sprintf: Libc.sprintf,
    isprint: Libc.isprint,
    inRange: ProcMaps.cm.inRange,
    addressOf: ProcMaps.cm.addressOf,
    geton: new NativeCallback(() => ptr, 'pointer', []),
    verbose: Memory.alloc(1),
  }),
);

Object.defineProperties(globalThis, {
  ElfHeader: {
    value: ElfHeader,
    writable: false,
  },
  memmove: {
    value: memmove,
    writable: false,
  },
});

export { strlen, fgets, memcmp, memmove, ElfHeader, ProcMaps, fbase64, LinkerSym };
