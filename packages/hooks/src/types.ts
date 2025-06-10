import type Java from 'frida-java-bridge';
import type { JavaArgument } from '@clockwork/common';
import type { ReturnOptional } from '@clockwork/common/src/types';

type LoggerValueTransform = (
    value: any,
    type: string | null,
    id: number,
) => [value?: any, type?: string | null] | null | undefined;

type LoggerOptions = {
    spacing: string;
    arguments: boolean;
    return: boolean;
    multiline: boolean;
    short: boolean;
    call: boolean;
    hook: boolean;
    enable: boolean;
    transform?: LoggerValueTransform;
};

type HookParameters = {
    predicate?: MethodHookPredicate;
    before?: FridaBeforeMethod;
    replace?: FridaMethodReplacement;
    after?: FridaAfterMethod;
    logging?: Partial<LoggerOptions>;
    loggingPredicate?: LoggingPredicate;
};

type MethodHookPredicate = (overload: Java.Method, index: number) => boolean;
type NativeCallbackPredicate = (thisRef: InvocationContext) => boolean;

type LoggingPredicate = (this: Java.Wrapper, method: Java.Method, ...args: JavaArgument[]) => boolean;

type FridaMethodReplacement = (this: Java.Wrapper, method: Java.Method, ...args: any[]) => any;
type FridaMethodReplacementOptional = ReturnOptional<FridaMethodReplacement>;
type FridaMethodThisCompat = Java.Wrapper & {
    readonly originalMethod: Java.Method;
    readonly originalArgs: any[];
    fallback(): any;
};

type FridaBeforeMethod = (this: Java.Wrapper, method: Java.Method, ...args: any[]) => void;

type FridaAfterMethod = (this: Java.Wrapper, method: Java.Method, returnValue?: any, ...args: any[]) => void;

export type {
    FridaMethodReplacement,
    FridaMethodReplacementOptional,
    FridaMethodThisCompat,
    HookParameters,
    LoggerOptions,
    MethodHookPredicate,
    NativeCallbackPredicate,
};
