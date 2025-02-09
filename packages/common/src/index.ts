import { EventEmitter } from 'events';
import { ClassesProxy, ClassesString, type ClassesType } from './define/java.js';
import { LibcFinderProxy, type LibcType } from './define/libc.js';
import { Linker, hookException } from './define/linker.js';
import { enumerateMembers, findChoose, findClass, getFindUnique } from './search.js';
import { SYSCALLS } from './define/syscalls.js';
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

function isIterable(obj: any) {
    if (obj === null || obj === undefined) {
        return false;
    }
    return typeof obj[Symbol.iterator] === 'function';
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

function getApplicationContext(): Java.Wrapper {
    return Classes.ActivityThread.currentApplication().getApplicationContext();
}

const isNully = (ptr: NativePointerValue) => !ptr || ptr === NULL || `${ptr}` === '0x0';

const emitter = new EventEmitter();
declare global {
    const Classes: ClassesType;
    const Libc: LibcType;
    // biome-ignore lint/suspicious/noRedeclare: Makes the function accessible from global frida context
    function findClass(className: string, ...loaders: Java.Wrapper[]): Java.Wrapper | null;
}
Object.defineProperties(global, {
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
    emitter: {
        value: emitter,
    },
});

export {
    Linker,
    ClassesProxy as Classes,
    ClassesString,
    emitter,
    enumerateMembers,
    findClass,
    findChoose,
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
};
