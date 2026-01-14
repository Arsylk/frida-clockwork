import { EventEmitter } from 'events';
import { ClassesProxy, ClassesString, type ClassesType } from './define/java.js';
import { LibcFinderProxy, type LibcType } from './define/libc.js';
import { Linker, hookException } from './define/linker.js';
import { enumerateMembers, findChoose, findClass, getFindUnique } from './search.js';
import { SYSCALLS } from './define/syscalls.js';
import Java from 'frida-java-bridge';
import { stringify } from './text.js';
import { logger } from '@clockwork/logging';
export { SYSCALLS as Syscalls };
export * as Consts from './define/consts.js';
export * as Std from './define/std.js';
export * as Struct from './define/struct.js';
export * as Text from './text.js';
export * from './types.js';
export * from './visualize.js';

type Success<T> = [T, null];

type Failure<E extends Error> = [null, E];

function tryErr<T, E extends Error>(fn: () => T): Success<T> | Failure<E> {
  try {
    return [fn(), null] as Success<T>;
  } catch (e: any) {
    return [null, e] as Failure<E>;
  }
}

function tryNull<T>(fn: () => T): T | null {
  try {
    return fn();
  } catch (_) {}
  return null;
}

function isJWrapper(clazzOrName: Java.Wrapper | string): clazzOrName is Java.Wrapper {
  return typeof clazzOrName === 'object' ? Reflect.has(clazzOrName, '$className') : false;
}

function isIterable(obj: any, string = false) {
  if (obj === null || obj === undefined) {
    return false;
  }
  return (string || typeof obj !== 'string') && typeof obj[Symbol.iterator] === 'function';
}

function stacktrace(e?: Java.Wrapper): string {
  e ??= Classes.Exception.$new();
  return Classes.Log.getStackTraceString(e).split('\n').slice(1).join('\n');
}

function stacktraceList(e?: Java.Wrapper): string[] {
  e ??= Classes.Exception.$new();
  const stack = Classes.Log.getStackTraceString(e);
  return `${stack}`
    .split('\n')
    .slice(1)
    .map((s: string) => s.substring(s.indexOf('at ') + 3).trim());
}

function getApplication(): Java.Wrapper {
  const app = Classes.ActivityThread.currentApplication();
  const implClass = findClass(app.$className);
  return implClass ? Java.cast(app, implClass) : app;
}

function getApplicationContext(): Java.Wrapper {
  return Classes.ActivityThread.currentApplication()?.getApplicationContext();
}

function javaB64Decode(str: string): Uint8Array {
  return Classes.Base64.getDecoder().decode(str);
}

function jarrayToBuffer(jarray: []): ArrayBuffer {
  const uint8s = new Uint8Array(jarray);
  return uint8s.buffer;
}

const isNully = (ptr: NativePointerValue) => !ptr || ptr === NULL || `${ptr}` === '0x0';

const isNullyVararg = (...ptr: NativePointerValue[]) => {
  for (const p of ptr) if (isNully(p)) return true;
  return false;
};

const filterMulti = (
  filter: [[] | string[] | string, [] | string[] | string][],
  first: string,
  second: string,
) => {
  for (const [tfirst, tsecond] of filter) {
    let firstpass = isIterable(tfirst) && tfirst.length === 0;
    let secondpass = isIterable(tsecond) && tsecond.length === 0;
    for (const arrFirst of isIterable(tfirst) ? tfirst : [tfirst]) {
      if (arrFirst == first) {
        firstpass = true;
        break;
      }
    }
    for (const arrSecond of isIterable(tsecond) ? tsecond : [tsecond]) {
      if (arrSecond == second) {
        secondpass = true;
        break;
      }
    }
    if (firstpass && secondpass) return true;
  }
  return false;
};

function getRandomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

const emitter = new EventEmitter();
declare global {
  const Classes: ClassesType;
  const Libc: LibcType;
  // biome-ignore lint/suspicious/noRedeclare: Makes the function accessible from global frida context
  function findClass(className: string, ...loaders: Java.Wrapper[]): Java.Wrapper | null;
}
Object.defineProperties(globalThis, {
  Linker: {
    value: Linker,
    writable: false,
  },
  Classes: {
    value: ClassesProxy,
    writable: false,
  },
  Libc: {
    value: LibcFinderProxy,
    writable: false,
  },
  findClass: {
    value: findClass,
  },
  findChoose: {
    value: findChoose,
  },
  tryNull: {
    value: tryNull,
  },
  emitter: {
    value: emitter,
  },
  application: {
    get: () => getApplication(),
  },
  applicationContext: {
    get: () => getApplicationContext(),
  },
  jniinit: {
    value: (libname: string) => {
      const module = Module.load(libname);
      if (!module) return -1;
      let jni = module.enumerateExports().filter((e) => e.name === 'JNI_OnLoad')?.[0]?.address;
      jni ??= module.enumerateSymbols().filter((e) => e.name === 'JNI_OnLoad')?.[0]?.address;
      if (!jni) return -1;
      const fn = new NativeFunction(jni, 'int', ['pointer', 'pointer']);
      const env = Java.vm.tryGetEnv()?.handle;
      if (!env) return -1;
      return fn(env, NULL);
    },
  },
});

// biome-ignore lint/complexity/useArrowFunction: don't
rpc.exports.init = function (stage, params: object) {
  const ent = Reflect.ownKeys(params).reduce<PropertyDescriptorMap>((prev, crnt) => {
    const value = Reflect.get(params, crnt);
    Reflect.set(prev, crnt, {
      value: value,
      writable: false,
      configurable: true,
      enumerable: isIterable(value),
    } as PropertyDescriptor);
    return prev;
  }, {} as PropertyDescriptorMap);
  Object.defineProperties(globalThis, ent);
  logger.info({ tag: 'externalargs' }, stringify({ stage: stage, params: params, pid: Process.id }));
  Java.perform(() => {
    (Java.classFactory as any).cacheDir = `/data/data/${globalThis.packageName}/`;
    (Java.classFactory as any).codeCacheDir = `/data/data/${globalThis.packageName}/`;
  });
};

export {
  Linker,
  ClassesProxy as Classes,
  ClassesString,
  emitter,
  enumerateMembers,
  findClass,
  findChoose,
  getApplication,
  getApplicationContext,
  getFindUnique,
  isJWrapper,
  isNully,
  LibcFinderProxy as Libc,
  stacktrace,
  stacktraceList,
  tryNull,
  tryErr,
  isIterable,
  hookException,
  jarrayToBuffer,
  filterMulti,
  isNullyVararg,
  getRandomInt,
};
