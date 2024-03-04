import { ClassesProxy as Classes, ClassesString } from './define/java.js';
import { LibcFinderProxy } from './define/libc.js';
import * as Std from './define/std.js';
import { enumerateMembers, findClass, getFindUnique } from './search.js';
import * as Text from './text.js';

function isJWrapper(clazzOrName: Java.Wrapper | string): clazzOrName is Java.Wrapper {
    return clazzOrName?.hasOwnProperty('$className');
}

function stacktrace(): string {
    const e = Classes.Exception.$new();
    return Classes.Log.getStackTraceString(e).split('\n').slice(1).join('\n');
}

function stacktraceList(): string[] {
    const e = Classes.Exception.$new();
    const stack = Classes.Log.getStackTraceString(e);
    return `${stack}`.split('\n').slice(1).map((s: string) => s.substring(s.indexOf('at ') + 3).trim());
}


declare global {
    function findClass(className: string, ...loaders: Java.Wrapper[]): Java.Wrapper | null
}
Object.defineProperties(global, {
    findClass: {
        value: findClass
    },
})


export { Classes, ClassesString, LibcFinderProxy as Libc, isJWrapper, stacktrace, stacktraceList, findClass, enumerateMembers, getFindUnique, Text, Std };
