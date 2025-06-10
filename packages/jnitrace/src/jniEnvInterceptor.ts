import type { JavaMethod } from './model.js';
import type { EnvWrapper } from './envWrapper.js';
import { isNully, Consts } from '@clockwork/common';
const { JavaPrimitive } = Consts;

const UNION_SIZE = 8;

abstract class JNIEnvInterceptor {
    #primitives = Reflect.ownKeys(JavaPrimitive);
    #envWrapper: () => EnvWrapper;

    get envWrapper() {
        return this.#envWrapper();
    }

    constructor(envWrapper: () => EnvWrapper) {
        this.#envWrapper = envWrapper;
    }

    public getCallMethodArgs(
        caller: string,
        args: NativeCallbackArgumentValue[],
        method: JavaMethod | null,
    ): NativeCallbackArgumentValue[] | null {
        // instant skip when method is missing
        if (!method) return null;

        const isVaList = caller.endsWith('va_list') || caller.endsWith('V');
        const isArray = caller.endsWith('A');

        const callArgs = Array(method.jParameterTypes.length);
        const callArgsPtr = args[args.length - 1] as NativePointer;
        if (isVaList) this.setUpVaListArgExtract(callArgsPtr);

        for (let i = 0; i < method.jParameterTypes.length; i++) {
            const type = method.jParameterTypes[i];
            if (isVaList) {
                const currentPtr = this.extractVaListArgValue(method, i);
                callArgs[i] = this.readValue(currentPtr, type, true);
            } else if (isArray) {
                const ptr = callArgsPtr.add(0x8 * i).readPointer();
                callArgs[i] = ptr;
            } else {
                const ptr = callArgsPtr.add(UNION_SIZE * i);
                callArgs[i] = ptr;
            }
        }

        if (isVaList) this.resetVaListArgExtract();

        return callArgs;
    }

    private readValue(
        currentPtr: NativePointer,
        type: string,
        extend?: boolean,
    ): NativeCallbackArgumentValue | null {
        //console.log(`${currentPtr} ${type} ${extend}`);
        if (isNully(currentPtr)) {
            if (type in this.#primitives) {
                return 0;
            }
            return null;
        }

        if (`${currentPtr}`.length !== 12 && !this.#primitives.includes(type)) {
            return this.envWrapper.getLocalRef(currentPtr, (x) => x);
            // if (type in Reflect.ownKeys(JavaPrimitive)) {
            //     return 0;
            // }
            // return null;
        }

        let value: NativeCallbackArgumentValue;
        switch (type) {
            case 'boolean':
            case JavaPrimitive.boolean: {
                value = currentPtr.readU8();
                break;
            }
            case 'byte':
            case JavaPrimitive.byte: {
                value = currentPtr.readS8();
                break;
            }
            case 'char':
            case JavaPrimitive.char: {
                value = currentPtr.readU16();
                break;
            }
            case 'short':
            case JavaPrimitive.short: {
                value = currentPtr.readS16();
                break;
            }
            case 'int':
            case JavaPrimitive.int: {
                value = currentPtr.readS32();
                break;
            }
            case 'long':
            case JavaPrimitive.long: {
                value = currentPtr.readS64();
                break;
            }
            case 'double':
            case JavaPrimitive.double: {
                value = currentPtr.readDouble();
                break;
            }
            case 'float':
            case JavaPrimitive.float: {
                value = extend === true ? currentPtr.readDouble() : currentPtr.readFloat();
                break;
            }
            default: {
                value = currentPtr.readPointer();
                break;
            }
        }
        return value;
    }

    protected abstract setUpVaListArgExtract(vaList: NativePointer): void;

    protected abstract extractVaListArgValue(method: JavaMethod, index: number): NativePointer;

    protected abstract resetVaListArgExtract(): void;
}

export { JNIEnvInterceptor };
