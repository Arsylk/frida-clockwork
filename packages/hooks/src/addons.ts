import type Java from 'frida-java-bridge';
import type {
    FridaMethodReplacement,
    FridaMethodReplacementOptional,
    FridaMethodThisCompat,
} from './types.js';

const always: (value: any) => FridaMethodReplacement = (value) => () => value;

const compat = (fn: (this: FridaMethodThisCompat) => any): FridaMethodReplacement => {
    return function (this: Java.Wrapper, method: Java.Method, ...args: any[]): any {
        const addon = {
            get originalMethod(): Java.Method {
                return method;
            },
            get originalArgs(): any[] {
                return args;
            },
            fallback(): any {
                return this.originalMethod.call(this, ...this.originalArgs);
            },
        };
        return fn.call(Object.assign(this, addon));
    };
};

const ifReturn: (fn: FridaMethodReplacementOptional) => FridaMethodReplacement = (
    fn: FridaMethodReplacementOptional,
) => {
    return function (this: Java.Wrapper, method: Java.Method, ...args: any[]) {
        const result = fn.call(this, method, ...args);
        if (result !== undefined) return result;
        return method.call(this, ...args);
    };
};

const ifKey: (fn: (key: string) => any | undefined, index?: number) => FridaMethodReplacement = (
    fn: (key: string) => any | undefined,
    index?: number,
) => {
    return ifReturn(function (this, method, ...args) {
        const key = args[index ?? 0];
        return fn(key);
    });
};

export { always, compat, ifKey, ifReturn };
