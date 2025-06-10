import Java from 'frida-java-bridge';
import { JNI } from './jni.js';
import type { JNIEnvInterceptor } from './jniEnvInterceptor.js';
import { JNIEnvInterceptorARM64 } from './jniEnvInterceptorArm64.js';
import { Fields, Methods } from './model.js';
import { isNully } from '@clockwork/common';

type JniDefinition<T extends NativeFunctionReturnType, R extends [] | NativeFunctionArgumentType[]> = {
    offset: number;
    retType: T;
    argTypes: R;
};

type JniField<T extends NativePointerValue> = {
    set(value: T): void;
    get(): T;
};

class EnvWrapper {
    #env: Java.Env;
    jniEnv: NativePointer;
    jniInterceptor: JNIEnvInterceptor;

    Fields = Fields;
    Methods = Methods;

    #functions: { [key: number]: NativeFunction<any, any> } = {};
    #fields: { [key: number]: JniField<any> } = {};

    constructor(env: Java.Env) {
        this.#env = env;
        this.jniEnv = env.handle;
        this.jniInterceptor = new JNIEnvInterceptorARM64(() => this);
    }

    public getFunction<T extends NativeFunctionReturnType, R extends [] | NativeFunctionArgumentType[]>(
        def: JniDefinition<T, R>,
    ) {
        const cached = this.#functions[def.offset];
        if (cached) return cached;
        return (this.#functions[def.offset] = asFunction(this.jniEnv, def));
    }

    getLocalRef<T>(ptr: NativePointer, fn: (ptr: NativePointer) => T): T {
        let ref: NativePointer | null = null;
        try {
            const NewLocalRef = this.getFunction(JNI.NewLocalRef);
            return fn((ref = NewLocalRef(this.jniEnv, ptr)));
        } finally {
            if (ref) {
                const DeleteLocalRef = this.getFunction(JNI.DeleteLocalRef);
                DeleteLocalRef(this.jniEnv, ref);
                ref = null;
            }
        }
    }
}

function asFunction<T extends NativeFunctionReturnType, R extends [] | NativeFunctionArgumentType[]>(
    jniEnv: NativePointer,
    def: JniDefinition<T, R>,
) {
    const vaTable: NativePointer = jniEnv.readPointer();
    const ptrPos = vaTable.add(def.offset * Process.pointerSize);
    const ptr = ptrPos.readPointer();
    return new NativeFunction(ptr, def.retType, def.argTypes);
}

function asLocalRef<T>(jniEnv: NativePointer, ptr: NativePointer, fn: (ptr: NativePointer) => T): T {
    let ref: NativePointer | null = null;
    try {
        const NewLocalRef = asFunction(jniEnv, JNI.NewLocalRef);
        return fn((ref = NewLocalRef(jniEnv, ptr)));
    } finally {
        if (ref) {
            const DeleteLocalRef = asFunction(jniEnv, JNI.DeleteLocalRef);
            DeleteLocalRef(jniEnv, ref);
            ref = null;
        }
    }
}

function asExceptionSafe<T>(jniEnv: NativePointer, fn: () => T): T {
    let ex: NativePointer | null = null;
    try {
        if (asFunction(jniEnv, JNI.ExceptionCheck)(jniEnv)) {
            ex = asFunction(jniEnv, JNI.ExceptionOccurred)(jniEnv);
            asFunction(jniEnv, JNI.ExceptionClear)(jniEnv);
        }
        return fn();
    } finally {
        if (ex) {
            asFunction(jniEnv, JNI.Throw)(jniEnv, ex);
            ex = null;
        }
    }
}

function getClassName(env: NativePointer, handle: NativePointer) {
    const getName = (ptr: NativePointer) => Java.cast(ptr, Classes.Class).getName();
    return `${handle}`.length === 12 ? asLocalRef(env, handle, getName) : getName(handle);
}

function getObjectClassName(env: NativePointer, handle: NativePointer) {
    const clazz = asFunction(env, JNI.GetObjectClass)(env, handle);
    return getClassName(env, clazz);
}

export {
    asFunction,
    asLocalRef,
    asExceptionSafe,
    EnvWrapper,
    getClassName,
    getObjectClassName,
    type JniDefinition,
};
