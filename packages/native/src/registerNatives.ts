import Java from 'frida-java-bridge';
import { Color, logger } from '@clockwork/logging';
const { green, redBright, bold, dim, black } = Color.use();

// biome-ignore lint/suspicious/noExplicitAny: <explanation>
let cachedVtable: any = null;
function vtable(instance: Java.Env) {
    if (cachedVtable === null) {
        cachedVtable = instance.handle.readPointer();
    }
    return cachedVtable;
}

function find(offset: number, returnType: NativeFunctionReturnType, args: NativeFunctionArgumentType[]) {
    const env = Java.vm.tryGetEnv();
    if (!env) return null;
    const addr = vtable(env)
        .add(offset * Process.pointerSize)
        .readPointer();
    const func = new NativeFunction(addr, returnType, args);
    return func ?? null;
}

function attachRegisterNatives(fn?: (this: InvocationContext, retval: InvocationReturnValue) => void) {
    const found = find(215, 'int32', ['pointer', 'pointer', 'pointer', 'int32']);
    if (found) {
        Interceptor.attach(found, {
            onEnter(args) {
                logOnEnterRegisterNatives.call(this, args);
            },
            onLeave(retval) {
                fn?.call(this, retval);
            },
        });
        return;
    }

    // fallback previous method
    const libart = Process.getModuleByName('libart.so');
    const symbols = libart.enumerateSymbols();
    for (const { name, address } of symbols) {
        if (
            name.includes('art') &&
            name.includes('JNI') &&
            name.includes('RegisterNatives') &&
            !name.includes('CheckJNI')
        ) {
            console.log('RegisterNatives is at ', address, name);
            Interceptor.attach(address, {
                onEnter(args) {
                    logOnEnterRegisterNatives.call(this, args);
                    // TODO hook capabilities
                },
            });
        }
    }
}

/*
jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
struct JNINativeMethod< R (JNIEnv*, jclass*, Args...) > {
    const char* name;
    const char* signature;
    R (*fnPtr)(JNIEnv*, jclass*, Args...);
};
*/
function logOnEnterRegisterNatives(this: InvocationContext, args: InvocationArguments) {
    const module = Process.findModuleByAddress(this.returnAddress) ?? Process.findModuleByAddress(args[2]);

    const clazz = args[1];
    const methodsPtr = args[2];
    const nMethods = args[3].toInt32();
    const className = Java.vm.tryGetEnv()?.getClassName(clazz) ?? '<unknown>';

    logger.info({ tag: 'RegisterNatives' }, `${redBright(className)} methods: ${bold(nMethods)}`);
    addToExport({
        module: module?.name,
        name: className,
        methods_ptr: module ? methodsPtr.sub(module.base) : methodsPtr,
        nMethods: nMethods,
        backtrace: module
            ? Thread.backtrace()
                  .filter((s) => s > module.base && s < module.base.add(module.size))
                  .map((s) => s.sub(module.base))
            : undefined,
    });

    for (let i = 0; i < nMethods; i++) {
        const namePtr = methodsPtr.add(i * Process.pointerSize * 3).readPointer();
        const sigPtr = methodsPtr.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer();
        const fnPtrPtr = methodsPtr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();

        const name = namePtr.readCString() ?? '';
        const sig = sigPtr.readCString() ?? '';
        const symbol = DebugSymbol.fromAddress(fnPtrPtr);
        console.log(
            `${black(dim('  >'))}${green(name)}${sig}`,
            `at:\n    ${symbol}\n    ${DebugSymbol.fromAddress(this.returnAddress)}`,
        );
        // console.log(
        //     '[#]',
        //     JSON.stringify({
        //         class: className,
        //         name: name,
        //         sig: sig,
        //         module: symbol.moduleName,
        //         offset: badConvert(symbol),
        //     }),
        // );
    }
}

function getModuleBase(returnAddress: NativePointer): NativePointer | null {
    const debug = DebugSymbol.fromAddress(returnAddress);
    if (!debug.name) return null;
    const module = Process.findModuleByName(debug.name);
    if (!module) return null;
    return module.base;
}

function badConvert(symbol: DebugSymbol): NativePointer {
    const str = symbol.toString();
    const stripped = str.substring(str.lastIndexOf('0x'));
    return ptr(stripped);
}

function addToExport(item: object) {
    const native: object[] = ((rpc as typeof rpc & { RegisterNatives: object[] }).RegisterNatives ??= []);
    native.push(item);
}

export { attachRegisterNatives };
