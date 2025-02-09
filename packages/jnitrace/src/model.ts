import { Text } from '@clockwork/common';
import type { jFieldID, jMethodID } from './jni.js';

enum JniInvokeMode {
    Normal = 0,
    Nonvirtual = 1,
    Static = 2,
    Constructor = 3,
}

class JavaMethod {
    #jParameterTypes: string[] | null = null;
    #jReturnType: string | null = null;
    public constructor(
        public readonly className: string,
        public readonly name: string,
        public readonly parameters: string[],
        public readonly returnType: string,
        public readonly isStatic: boolean,
    ) {}

    public get jParameterTypes(): string[] {
        return (this.#jParameterTypes ??= this.parameters.map(Text.toPrettyType));
    }

    public get jReturnType(): string {
        return (this.#jReturnType ??= Text.toPrettyType(this.returnType));
    }

    public get isVoid(): boolean {
        return this.returnType === 'void';
    }

    public get isConstructor(): boolean {
        return this.name === '<init>' && this.isVoid;
    }
}

class JavaField {
    #jType: string | null = null;
    #jClassName: string | null = null;
    public constructor(
        public readonly className: string,
        public readonly name: string,
        public readonly type: string,
        public readonly isStatic: boolean,
    ) {}

    public get jType(): string {
        return (this.#jType ??= Text.toPrettyType(this.type));
    }

    public get jClassName(): string {
        return (this.#jClassName ??= Text.toPrettyType(this.className));
    }
}

const Methods = {
    storage: new Map<string, JavaMethod>(),
    staticStorage: new Map<string, JavaMethod>(),
    get(jMethodId: jMethodID, isStatic: boolean): JavaMethod | null {
        return (isStatic ? this.staticStorage : this.storage)[`${jMethodId}`] ?? null;
    },
    set(jMethodId: jMethodID, isStatic: boolean, method: JavaMethod): JavaMethod {
        return ((method.isStatic ? this.staticStorage : this.storage)[`${jMethodId}`] = method);
    },
} as Cachable<JavaMethod, jMethodID>;

const Fields = {
    storage: new Map<number, JavaField>(),
    staticStorage: new Map<number, JavaField>(),
    get(jFieldId: jFieldID, isStatic: boolean): JavaField | null {
        const key = typeof jFieldId === 'number' ? jFieldId : jFieldId.toInt32();
        return (isStatic ? this.staticStorage : this.storage)[key] ?? null;
    },
    set(jFieldId: jFieldID, isStatic: boolean, method: JavaField): JavaField {
        const key = typeof jFieldId === 'number' ? jFieldId : jFieldId.toInt32();
        return ((method.isStatic ? this.staticStorage : this.storage)[key] = method);
    },
} as Cachable<JavaField, jFieldID>;

type Cachable<T, R> = {
    get(key: R, isStatic: boolean): T | null;
    set(key: R, isStatuc: boolean, value: T): T;
};

class JNIMethod {
    constructor(
        public readonly name: string,
        public readonly address: NativePointer,
    ) {}
}

export { Fields, JavaField, JavaMethod, JniInvokeMode, JNIMethod, Methods, type Cachable };
