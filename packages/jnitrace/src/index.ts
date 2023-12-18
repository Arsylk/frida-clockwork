import { JavaMethod } from './javaMethod.js';
import { JNIEnvInterceptorARM64 } from './jniEnvInterceptorArm64.js';
import { JNIEnvInterceptor } from './jniEnvInterceptor.js';
import { Text, Classes, Std, enumerateMembers } from '@clockwork/common';
import { Color, subLogger } from '@clockwork/logging';
import { JNIMethod } from './jniMethod.js';
import { fastpathMethod, resolveMethod } from './tracer.js';
const logger = subLogger('jnitrace');
const { black, blue, dim, redBright, yellow } = Color.use();

// TODO fix all of this
let IF_CHECK = function (thisRef: InvocationContext): boolean {
    return false;
};

function ColorMethod(jMethodId: NativePointer, method: JavaMethod): string {
    let sb = '';
    sb += redBright(`${jMethodId}` + ' -' + dim('>'));
    sb += Color.className(method.className);
    sb += '::';
    sb += Color.method(method.name);
    sb += blue('(');
    sb += method.javaParams.map(Color.className).join(', ');
    sb += blue(')');
    sb += ': ';
    sb += Color.className(method.javaRet);

    return sb;
}

function ColorMethodInvoke(method: JavaMethod, args: any[]): string {
    let sb = '';
    sb += dim('call');
    sb += ' ';
    sb += Color.className(method.className);
    sb += '::';
    sb += Color.method(method.name);
    sb += blue('(');
    if (args.length > 0) {
        sb += '\n';
        sb += args.map((arg) => `    ${arg}`).join(', \n');
        sb += '\n';
    }
    sb += blue(')');
    sb += ': ';
    sb += Color.className(method.javaRet);

    return sb;
}

function hookIf<T>(
    callback: (this: InvocationContext, args: T) => string | null | undefined,
    tag?: string,
): (this: InvocationContext, args: T) => void {
    return function (this: InvocationContext, args: T) {
        if (!IF_CHECK(this)) return;
        const msg = callback.call(this, args);
        if (!msg) return;
        console.log(`[${tag}]`, msg, DebugSymbol.fromAddress(this.returnAddress));
    };
}

function hookIfTag<T>(tag: string, callback: (this: InvocationContext, args: T) => string | null | undefined) {
    return hookIf(callback, dim(tag));
}

function formatCallMethod(nativeName: string, jMethodId: NativePointer, method: JavaMethod | null, args: any[] | null): string | null {
    if (!method) return null; // ! TODO fix
    if (args) {
        const mappedArgs: string[] = [];
        for (const i in method.parameters) {
            const param = method.parameters[i];
            mappedArgs.push(args[i] as any);

            switch (param) {
                case 'java.lang.String': {
                    const wrapped = Java.cast(args[i] as any, Classes.String);
                    mappedArgs[i] = yellow(`"${wrapped}"`);
                    break;
                }
                case 'jobject': {
                    const wrapped = Java.cast(args[i] as any, Classes.Object);
                    mappedArgs[i] = `${wrapped.toString()}`;
                }
                case 'boolean': {
                    const textBoolean = args[i] ? 'true' : 'false';
                    mappedArgs[i] = textBoolean;
                }
            }
        }
        return ColorMethodInvoke(method, mappedArgs);
    }
    return null;
}

function formatMethodReturn(value: NativePointer | null): string | null {
    if (!value || value.isNull()) return null;
    let text = `${value}`;
    let type = null; // Java.vm.tryGetEnv()?.getObjectClassName(value);
    if (type && (type = Text.toPrettyType(type))) {
        if (type == Classes.String.$className) {
            text = yellow(`"${Java.cast(value, Classes.String)}"`);
        } else if (type.includes('.')) {
            text = `${Java.cast(value, Classes.Object)}`;
        }
    }
    return `${dim('return')} ${text}`;
}

/*
GetFieldID is at  0xe39b87c5 _ZN3art3JNI10GetFieldIDEP7_JNIEnvP7_jclassPKcS6_
GetMethodID is at  0xe39a1a19 _ZN3art3JNI11GetMethodIDEP7_JNIEnvP7_jclassPKcS6_
NewStringUTF is at  0xe39cff25 _ZN3art3JNI12NewStringUTFEP7_JNIEnvPKc
RegisterNatives is at  0xe39e08fd _ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
GetStaticFieldID is at  0xe39c9635 _ZN3art3JNI16GetStaticFieldIDEP7_JNIEnvP7_jclassPKcS6_
GetStaticMethodID is at  0xe39be0ed _ZN3art3JNI17GetStaticMethodIDEP7_JNIEnvP7_jclassPKcS6_
GetStringUTFChars is at  0xe39d06e5 _ZN3art3JNI17GetStringUTFCharsEP7_JNIEnvP8_jstringPh
DefineClass is at 0x????????
FindClass is at  0xe399ae5d _ZN3art3JNI9FindClassEP7_JNIEnvPKc
*/

function hookLibart(predicate: (thisRef: InvocationContext) => boolean) {
    IF_CHECK = predicate;
    const libart = Process.getModuleByName('libart.so');
    const symbols = libart.enumerateSymbols();
    const jniInterceptor = new JNIEnvInterceptorARM64();

    let addrGetStringUTFChars: NativePointer | null = null;
    let addrNewStringUTF: NativePointer | null = null;
    const addrsDefineClass: NativePointer[] = [];
    let addrFindClass: NativePointer | null = null;
    let addrGetMethodID: NativePointer | null = null;
    let addrGetStaticMethodID: NativePointer | null = null;
    let addrGetFieldID: NativePointer | null = null;
    let addrGetStaticFieldID: NativePointer | null = null;
    let addrRegisterNatives: NativePointer | null = null;
    const addrsCallStatic: JNIMethod[] = [];
    const addrsCallNonvirtual: JNIMethod[] = [];
    const addrsCallMethod: JNIMethod[] = [];
    let ToReflectedMethod: NativeFunction<NativePointer, [NativePointerValue, NativePointerValue, NativePointerValue]> | null = null;
    let GetMethodID: NativeFunction<NativePointer, [NativePointerValue, NativePointerValue, NativePointerValue]> | null = null;

    symbols.forEach(({ name, address }) => {
        if (name.includes('art') && name.includes('JNI') && name.includes('_ZN3art3JNIILb0') && !name.includes('CheckJNI')) {
            if (name.includes('GetStringUTFChars')) {
                addrGetStringUTFChars = address;
                logger.trace('GetStringUTFChars is at', address, name);
            } else if (name.includes('NewStringUTF')) {
                addrNewStringUTF = address;
                logger.trace('NewStringUTF is at', address, name);
            } else if (name.includes('DefineClass')) {
                addrsDefineClass.push(address);
                logger.trace('DefineClass is at', address, name);
            } else if (name.includes('FindClass')) {
                addrFindClass = address;
                logger.trace('FindClass is at', address, name);
            } else if (name.includes('GetMethodID')) {
                addrGetMethodID = address;
                GetMethodID = new NativeFunction(addrGetMethodID, 'pointer', ['pointer', 'pointer', 'pointer']);
                logger.trace('GetMethodID is at', address, name);
            } else if (name.includes('GetStaticMethodID')) {
                addrGetStaticMethodID = address;
                logger.trace('GetStaticMethodID is at', address, name);
            } else if (name.includes('GetFieldID')) {
                addrGetFieldID = address;
                logger.trace('GetFieldID is at', address, name);
            } else if (name.includes('GetStaticFieldID')) {
                addrGetStaticFieldID = address;
                logger.trace('GetStaticFieldID is at', address, name);
            } else if (name.includes('RegisterNatives')) {
                addrRegisterNatives = address;
                logger.trace('RegisterNatives is at', address, name);
            } else if (name.includes('CallStatic')) {
                addrsCallStatic.push(new JNIMethod(name, address));
                logger.trace('CallStatic is at', address, name);
            } else if (name.includes('CallNonvirtual')) {
                addrsCallNonvirtual.push(new JNIMethod(name, address));
                logger.trace('CallNonvirtual is at', address, name);
            } else if (name.includes('Call') && name.includes('Method')) {
                console.warn(name);
                addrsCallMethod.push(new JNIMethod(name, address));
                logger.trace('Call<>Method is at', address, name);
            } else if (name.includes('ToReflectedMethod')) {
                ToReflectedMethod = new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'pointer']);
                logger.trace('ToReflectedMethod is at', address, name);
            } else if (name.includes('GetArrayLength')) {
                // Interceptor.attach(address, {
                //     onLeave: hookIfTag('GetArrayLength', (retval) => `${retval}`),
                // });
            } else if (name.includes('SetByteArrayRegion')) {
                // Interceptor.attach(address, {
                //     onLeave: hookIfTag('SetByteArrayRegion', (retval) => `${retval}`),
                // });
            } else if (name.includes('NewObjectArray')) {
                // Interceptor.attach(address, {
                //     onLeave: hookIfTag('NewObjectArray', (retval) => `${retval}`),
                // });
            } else if (name.includes('SetObjectArrayElement')) {
                // Interceptor.attach(address, {
                //     onEnter: hookIfTag('SetObjectArrayElement', (args) => `${args[2]} -> ${args[3]}`),
                // });
            } else if (name.includes('ReleaseByteArrayElements')) {
                // Interceptor.attach(address, {
                //     onEnter: hookIfTag('ReleaseByteArrayElements', (args) => `${args[2]} -> ${args[3]}`),
                // });
            } else if (name.includes('GetByteArrayElements')) {
                // Interceptor.attach(address, {
                //     onLeave: hookIfTag('GetByteArrayElements', (retval) => `${retval}, ${retval.readByteArray(32)}`),
                // });
            }
        }
    });

    addrGetStringUTFChars &&
        Interceptor.attach(addrGetStringUTFChars, {
            // std::tuple< UniqueStringUTFChars, bool > 	GetStringUTFChars (JNIEnv &env, jstring &string)
            onLeave: hookIfTag('GetStringUTFChars', (retval) => yellow(`"${retval.readCString()}"`)),
        });
    addrNewStringUTF &&
        Interceptor.attach(addrNewStringUTF, {
            // jstring & 	NewStringUTF (JNIEnv &env, const char *bytes)
            onEnter: hookIfTag('NewStringUTF', (args) => yellow(`"${args[1].readCString()}"`)),
        });

    // addrsDefineClass.forEach((addres) => {
    //     Interceptor.attach(addres, {
    //         // jclass & 	DefineClass (JNIEnv &env, const char *name, jobject &loader, const jbyte *buf, jsize size)
    //         // auto 	DefineClass (JNIEnv &env, const char *name, jobject &loader, const Array &buf) -> std::enable_if_t< IsArraylike< Array >::value, jclass & >
    //         onEnter: hookIfTag('DefineClass', (args) => args[1].readCString()),
    //     });
    // });

    addrFindClass &&
        Interceptor.attach(addrFindClass, {
            // jclass & 	FindClass (JNIEnv &env, const char *name)
            onEnter: hookIfTag('FindClass', (args) => args[1].readCString()),
        });

    const getMethodId = function (isStatic: boolean = false) {
        // jmethodID       GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);
        // jmethodID GetStaticMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);
        return {
            onEnter(this: InvocationContext, args: any) {
                this.env = args[0];
                this.clazz = args[1];
                this.name = args[2].readCString();
                this.sig = args[3].readCString();
            },
            onLeave: hookIfTag<NativePointer>(`Get${isStatic ? 'Static' : ''}MethodID`, function (retval) {
                const className = Java.vm.tryGetEnv().getClassName(this.clazz);
                const method = fastpathMethod(retval, className, this.name, this.sig, isStatic);
                return ColorMethod(retval, method);
            }),
        };
    };
    addrGetMethodID && Interceptor.attach(addrGetMethodID, getMethodId(false));
    addrGetStaticMethodID && Interceptor.attach(addrGetStaticMethodID, getMethodId(true));
    // addrGetFieldID &&
    //     Interceptor.attach(addrGetFieldID, {
    //         // jfieldID & 	GetFieldID (JNIEnv &env, jclass &clazz, const char *name, const char *sig)
    //         onEnter: hookIfTag('GetFieldID', (args) => {
    //             if (args[2] === null) return null;

    //             const clazz = args[1];
    //             const name = args[2].readCString();
    //             const className = Java.vm.tryGetEnv().getClassName(clazz);
    //             const sig = args[3].readCString();
    //             return `${className}::${name}${sig}`;
    //         }),
    //     });
    // addrGetStaticFieldID &&
    //     Interceptor.attach(addrGetStaticFieldID, {
    //         // jfieldID & 	GetStaticFieldID (JNIEnv &env, jclass &clazz, const char *name, const char *sig)
    //         onEnter: hookIfTag('GetStaticFieldID', (args) => {
    //             if (args[2] === null) return null;

    //             const clazz = args[1];
    //             const name = args[2].readCString();
    //             const className = Java.vm.tryGetEnv().getClassName(clazz);
    //             const sig = args[3].readCString();
    //             return `${className}::${name}${sig}`;
    //         }),
    //     });

    addrsCallStatic.forEach(({ address, name }) => {
        Interceptor.attach(address, {
            // std::enable_if_t<!std::is_void< R >::value, R > 	CallStaticMethod (JNIEnv &env, jclass &clazz, jmethodID &method, Args &&... args)
            onEnter: hookIfTag('CallStatic', (rawargs) => {
                const env = rawargs[0];
                const jclass = rawargs[1];
                const jMethodId = rawargs[2];
                const args = rawargs[3];
                const method = resolveMethod(jMethodId, true);
                const callArgs = jniInterceptor.getCallMethodArgs(name, [env, jclass, jMethodId, args], true);
                return formatCallMethod(name, jMethodId, method, callArgs);
            }),
            onLeave: hookIfTag('CallStatic', formatMethodReturn),
        });
    });
    addrsCallNonvirtual.forEach(({ address, name }) => {
        Interceptor.attach(address, {
            // std::enable_if_t< std::is_void< R >::value, R > 	CallNonvirtualMethod (JNIEnv &env, jobject *obj, jclass &clazz, jmethodID &method, Args &&... args)
            onEnter: hookIfTag('CallNonvirtual', (rawargs) => {
                const env = rawargs[0];
                const jobject = rawargs[1];
                const jclass = rawargs[2];
                const jMethodId = rawargs[3];
                const args = rawargs[4];
                const method = resolveMethod(jMethodId, false);
                const callArgs = jniInterceptor.getCallMethodArgs(name, [env, jobject, jclass, jMethodId, args], false);
                return formatCallMethod(name, jMethodId, method, callArgs);
            }),
            onLeave: hookIfTag('CallNonvirtual', formatMethodReturn),
        });
    });
    addrsCallMethod.forEach(({ address, name }) => {
        Interceptor.attach(address, {
            // std::enable_if_t<!std::is_void< R >::value, R > 	CallMethod (JNIEnv &env, jobject *obj, jmethodID &method, Args &&... args)
            onEnter: hookIfTag('CallMethod', (rawargs) => {
                const env = rawargs[0];
                const jobject = rawargs[1];
                const jMethodId = rawargs[2];
                const args = rawargs[3];
                const method = resolveMethod(jMethodId, false);
                const callArgs = jniInterceptor.getCallMethodArgs(name, [env, jobject, jMethodId, args], false);

                // TODO this logging api
                // const cn = Java.vm.tryGetEnv().getObjectClassName(jobject);
                // if (cn.includes('.')) {
                //     const str = Java.cast(jobject, Java.use('java.lang.Object'));
                //     console.warn(str['toString']());
                // }
                return formatCallMethod(name, jMethodId, method, callArgs);
            }),
            onLeave: hookIfTag('CallMethod', formatMethodReturn),
        });
    });
}

export { hookLibart as attach };
