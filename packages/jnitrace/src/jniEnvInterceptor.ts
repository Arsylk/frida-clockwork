import { JavaMethod } from './javaMethod.js';
import { resolveMethod } from './tracer.js';

const UNION_SIZE = 8;
const METHOD_ID_INDEX = 2;
const NON_VIRTUAL_METHOD_ID_INDEX = 3;

abstract class JNIEnvInterceptor {

    public constructor() {}

    public getCallMethodArgs(caller: string, args: NativeCallbackArgumentValue[], isStatic: boolean): NativeCallbackArgumentValue[] | null {
        let methodIndex = METHOD_ID_INDEX;
        if (caller.includes('Nonvirtual')) {
            methodIndex = NON_VIRTUAL_METHOD_ID_INDEX;
        }
        if (caller.endsWith('jmethodIDz')) return [];
        if (!caller.endsWith('va_list') && !caller.endsWith('jvalue')) {
            return null;
        }

        const jMethodId = args[methodIndex] as NativePointer;
        const isVaList = caller.endsWith('va_list');

        // ? todo do better, confusing flow
        const jMethod = resolveMethod(jMethodId, isStatic);
        if (!jMethod) {
            console.error('[JniEnvInterceptor]', 'Method not found for id:', jMethodId);
            return null;
        }
        

        const callArgs: NativeCallbackArgumentValue[] = [];
        const callArgsPtr = args[args.length - 1] as NativePointer;
        if (isVaList) this.setUpVaListArgExtract(callArgsPtr);
        
        for (let i = 0; i < jMethod.javaParams.length; i++) {
            const type = jMethod.javaParams[i];
            let value: NativeCallbackArgumentValue;
            if (isVaList) {
                const currentPtr = this.extractVaListArgValue(jMethod, i);
                value = this.readValue(currentPtr, type, true);
            } else {
                value = this.readValue(callArgsPtr.add(UNION_SIZE * i), type);
            }
            callArgs.push(value);
        }

        if (isVaList) this.resetVaListArgExtract();

        return callArgs;
    }

    private readValue(currentPtr: NativePointer, type: string, extend?: boolean): NativeCallbackArgumentValue {
        let value: NativeCallbackArgumentValue;
        switch (type) {
            case 'boolean': {
                value = currentPtr.readU8();
                break;
            }
            case 'byte': {
                value = currentPtr.readS8();
                break;
            }
            case 'char': {
                value = currentPtr.readU16();
                break;
            }
            case 'short': {
                value = currentPtr.readS16();
                break;
            }
            case 'int': {
                value = currentPtr.readS32();
                break;
            }
            case 'long': {
                value = currentPtr.readS64();
                break;
            }
            case 'double': {
                value = currentPtr.readDouble();
                break;
            }
            case 'float': {
                value = extend === true ? currentPtr.readDouble() : currentPtr.readFloat();
                break;
            }
            case 'pointer':
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
