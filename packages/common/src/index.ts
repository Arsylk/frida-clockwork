import { EventEmitter } from 'events';
import { ClassesProxy, ClassesString, type ClassesType } from './define/java.js';
import { LibcFinderProxy, type LibcType } from './define/libc.js';
export * as Struct from './define/struct.js';
export * as Std from './define/std.js';
export * as Text from './text.js';
export * from './types.js';
import { enumerateMembers, findClass, getFindUnique } from './search.js';

function isJWrapper(clazzOrName: Java.Wrapper | string): clazzOrName is Java.Wrapper {
    return Object.hasOwn(clazzOrName as any, '$className');
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

const emitter = new EventEmitter();
declare global {
    const Classes: ClassesType;
    const Libc: LibcType;
    // biome-ignore lint/suspicious/noRedeclare: Makes the function accessible from global frida context
    function findClass(className: string, ...loaders: Java.Wrapper[]): Java.Wrapper | null;
}
Object.defineProperties(global, {
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
    emitter: {
        value: emitter,
    },
});

export {
    ClassesString,
    ClassesProxy as Classes,
    LibcFinderProxy as Libc,
    isJWrapper,
    stacktrace,
    stacktraceList,
    getApplicationContext,
    findClass,
    enumerateMembers,
    getFindUnique,
    emitter,
};
