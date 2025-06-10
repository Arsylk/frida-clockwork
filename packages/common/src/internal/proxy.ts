import Java from 'frida-java-bridge';
import type { Returnable, StructTypes } from '../types.js';

function mock<T>(): () => T {
    return () => {
        throw new Error('Stub');
    };
}

type PropertyJavaUseMapper<T> = { [Property in keyof T]: Java.Wrapper };
function proxyJavaUse<T>(data: T): PropertyJavaUseMapper<T> {
    const init = (key: string): Java.Wrapper => Java.use(key);
    const cache: { [key: string]: any } = {};
    return new Proxy(
        {},
        {
            get: (_: any, name: string) => {
                const key = data[name as keyof T];
                return cache[name] || (cache[name] ??= init(key as string));
            },
            apply: (_: any, thisArg: T, argArray: any[]): T => {
                return thisArg;
            },
        },
    );
}

type PropertyCallbackMapper<T extends { [key: string]: Returnable }> = {
    [Property in keyof T]: ReturnType<T[Property]>;
};
function proxyCallback<T extends { [key: string]: Returnable }>(data: T): PropertyCallbackMapper<T> {
    const cache: { [key: string]: any } = {};
    return new Proxy(
        {},
        {
            get: (_: any, name: string) => {
                if (name === 'toJSON') {
                    return data;
                }
                const init = data[name];
                return cache[name] || (cache[name] ??= init());
            },
            has(_: any, key: string): boolean {
                return data.has(key);
            },
            ownKeys(_: any) {
                return Reflect.ownKeys(data);
            },
            apply: (_: any, thisArg: T, argArray: any[]): T => {
                return thisArg;
            },
        },
    );
}

type PropertyStructMapper<T extends { [key: string]: StructTypes }> = {
    [Property in keyof T]: T[Property] extends 'int' | 'uint' | 'long' | 'short' | 'ushort' | 'byte'
        ? StructField<number>
        : T[Property] extends 'string' | 'char'
          ? StructField<string>
          : T[Property] extends 'uint64'
            ? StructField<UInt64>
            : T[Property] extends 'int64'
              ? StructField<Int64>
              : StructField<NativePointer>;
} & { ptr: NativePointer };
type StructField<T extends number | Int64 | UInt64 | string | NativePointer> = {
    ptr: NativePointer;
    value: T;
};
type StructCreator<T extends { [key: string]: StructTypes }> = {
    (ptr: NativePointer): PropertyStructMapper<T>;
    size: number;
};
function proxyStruct<T extends { [key: string]: StructTypes }>(data: T): StructCreator<T> {
    const creator = (ptr: NativePointer) => {
        const cache: { [key: string]: StructField<any> } = {};
        let offset = 0x0;
        for (const key in data) {
            const crnt = ptr.add(offset);
            switch (data[key]) {
                case 'char':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readCString(1);
                        },
                    };
                    offset += 0x1;
                    break;
                case 'byte':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readU8() & 0xff;
                        },
                    };
                    offset += 0x2;
                    break;
                case 'string':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readCString();
                        },
                    };
                    offset += Process.pointerSize;
                    break;
                case 'string*':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readPointer().readCString();
                        },
                    };
                    offset += Process.pointerSize;
                    break;
                case 'pointer':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readPointer();
                        },
                    };
                    offset += Process.pointerSize;
                    break;
                case 'int':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readInt();
                        },
                    };
                    offset += 0x4;
                    break;
                case 'long':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readLong();
                        },
                    };
                    offset += 0x8;
                    break;
                case 'int64':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readS64();
                        },
                    };
                    offset += 0x8;
                    break;
                case 'uint64':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readU64();
                        },
                    };
                    offset += 0x8;
                    break;
                case 'ushort':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readUShort();
                        },
                    };
                    offset += 0x2;
                    break;
                case 'short':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readShort();
                        },
                    };
                    offset += 0x2;
                    break;
            }
        }

        return new Proxy(
            {},
            {
                get: (_: any, name: string) => {
                    if (name === 'ptr') {
                        return ptr;
                    }
                    return cache[name];
                },
                has(_: any, key: string): boolean {
                    return Reflect.has(data, key);
                },
                ownKeys(_: any) {
                    return Reflect.ownKeys(data);
                },
                apply: (_: any, thisArg: T, _argArray: any[]): T => {
                    return thisArg;
                },
            },
        );
    };

    let size = 0x0;
    for (const key in data) {
        switch (data[key]) {
            case 'string':
                size += Process.pointerSize;
                break;
            case 'pointer':
                size += Process.pointerSize;
                break;
            case 'int':
                size += 0x4;
                break;
            case 'long':
                size += 0x8;
                break;
            case 'short':
                size += 0x2;
                break;
        }
    }
    size += size % Process.pointerSize;
    creator.size = size;

    return creator;
}

export {
    proxyCallback,
    proxyJavaUse,
    proxyStruct,
    type PropertyCallbackMapper,
    type PropertyJavaUseMapper,
    type PropertyStructMapper,
    type StructCreator,
};
