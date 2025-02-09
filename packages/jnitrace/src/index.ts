import { Classes, ClassesString, Text, isNully, tryNull, vs, emitter } from '@clockwork/common';
import { Consts } from '@clockwork/common';
import { Color, logger as gLogger, subLogger } from '@clockwork/logging';
import { addressOf, previousReturn } from '@clockwork/native';
import { fbase64, ProcMaps } from '@clockwork/cmodules';
import {
    EnvWrapper,
    type JniDefinition,
    asFunction,
    asLocalRef,
    getClassName,
    getObjectClassName,
} from './envWrapper.js';
import { JNI } from './jni.js';
import { JniInvokeCallbacks } from './jniInvokeCallback.js';
import { JNIMethod, type JavaMethod, JniInvokeMode } from './model.js';
import { resolveMethod, signatureToPrettyTypes } from './tracer.js';
const logger = subLogger('jnitrace');
const { black, gray, dim, redBright, magenta, orange, lavender } = Color.use();
const { JavaPrimitive } = Consts;

function ColorMethod(jMethodId: NativePointer, method: JavaMethod): string {
    let sb = '';
    sb += redBright(`${jMethodId} -${dim('>')}`);
    sb += Color.className(method.className);
    sb += '::';
    sb += Color.method(method.name);
    sb += Color.bracket('(');
    sb += method.jParameterTypes.map(Color.className).join(', ');
    sb += Color.bracket(')');
    sb += ': ';
    sb += Color.className(method.jReturnType);

    return sb;
}

function ColorMethodInvoke(method: JavaMethod, args: string[]): string {
    // TODO move someplace else
    let isMultiline = true;
    // only primitive types or single param
    if (
        method.jParameterTypes.length <= 1 ||
        !method.jParameterTypes.map((p) => p in Reflect.ownKeys(JavaPrimitive)).includes(false)
    ) {
        isMultiline = false;
    }

    switch (method.className) {
        case 'android.view.MotionEvent':
            isMultiline = method.name in ['getHistoricalAxisValue', 'getAxisValue'];
            break;
        case 'com.android.internal.policy.PhoneWindow':
            isMultiline = method.name in ['setStatusBarColor'];
            break;
        case 'android.app.Activity':
            isMultiline = method.name in ['findViewById'];
            break;
        case 'java.io.FileOutputStream':
            isMultiline = method.name in ['write'];
            break;
        case 'android.app.ApplicationPackageManager':
            isMultiline = method.name in ['getApplicationInfo', 'getPackageInfo'];
            break;
        case 'org.cocos2dx.lib.Cocos2dxBitmap':
            isMultiline = method.name in ['createTextBitmapShadowStroke'];
            break;
        case 'com.cocos.lib.CocosDownload':
            isMultiline = method.name in ['createDownloader'];
            break;
        case 'org.egret.runtime.core.AndroidNativePlayer':
            isMultiline = method.name in ['emit'];
            break;
        case 'org.egret.runtime.component.label.TextBitmap':
            isMultiline = method.name in ['init', 'generateTextBitmapData', 'getTextWitdth'];
            break;
        case 'android.view.ViewGroup':
            isMultiline = method.name in ['addView'];
            break;
        case 'android.widget.LinearLayout$LayoutParams':
        case 'android.animation.PropertyValuesHolder':
        case 'android.animation.ObjectAnimator':
        case 'android.widget.FrameLayout$LayoutParams':
            isMultiline = false;
            break;
    }
    const nl = isMultiline ? '\n' : '';
    const pad = isMultiline ? '    ' : '';

    const isConstructor = method.name === '<init>';
    let sb = '';
    if (isConstructor) {
        sb += Color.keyword('new');
        sb += ' ';
        sb += Color.className(method.className);
    } else {
        sb += Color.className(method.className);
        sb += '::';
        sb += Color.method(method.name);
    }

    sb += Color.bracket('(');
    if (args.length > 0) {
        sb += nl;
        sb += args.map((arg) => `${pad}${arg}`).join(`, ${nl}`);
        sb += nl;
    }
    sb += Color.bracket(')');

    if (!isConstructor) {
        sb += ': ';
        sb += Color.className(method.jReturnType);
    }

    return sb;
}

function hookIf<T>(
    callback: (this: InvocationContext, args: T) => string | null | undefined,
    tag?: string,
): (this: InvocationContext, args: T) => void {
    return function (this: InvocationContext, args: T) {
        const msg = callback.call(this, args);
        if (!msg) return;
        console.log(`[${tag}]`, msg, addressOf(this.returnAddress));
    };
}

function hookIfTag<T extends InvocationArguments | InvocationReturnValue>(
    tag: string,
    callback: (this: InvocationContext, args: T) => string | null | undefined,
) {
    return hookIf(callback, dim(tag));
}

function formatCallMethod(
    jniEnv: NativePointer,
    jMethodId: NativePointer,
    method: JavaMethod | null,
    args: NativeCallbackArgumentValue[] | null,
): string {
    // better than nothing ...
    if (!method) {
        return `${jniEnv}::${jMethodId}(${args})`;
    }

    // colorful mapping flow
    const mappedArgs = new Array<string>(method.parameters.length);
    for (const i in method.parameters) {
        const param = method.parameters[i];
        const arg = args?.[i];
        mappedArgs[i] = vs(arg, param, jniEnv);
    }
    return ColorMethodInvoke(method, mappedArgs);
}

function formatMethodReturn(jniEnv: NativePointer, value: any, type?: string): string {
    const text = vs(value, type, jniEnv);

    return `${dim('return')} ${text}`; // + `${type}[${value}: ${typeof value}]`;
}

let envWrapper: EnvWrapper;

function hookLibart(predicate: (thisRef: InvocationContext | CallbackContext) => boolean, full: boolean) {
    envWrapper ??= new EnvWrapper(Java.vm.getEnv());

    repl(envWrapper, JNI.GetStringUTFChars, function (retval, env, str, smth) {
        if (!predicate(this) || isNully(retval)) return;

        const msg = Color.string(retval.readCString());
        gLogger.info(`[${dim('GetStringUTFChars')}] ${msg}`);
    });
    repl(envWrapper, JNI.NewStringUTF, function (retval, env, str) {
        if (!predicate(this) || isNully(str)) return;
        const text = str.readCString();
        switch (text) {
            case 'com/cocos/lib/CocosHelper':
            case 'org/cocos2dx/lib/CanvasRenderingContext2DImpl':
            case 'com/cocos/lib/CanvasRenderingContext2DImpl':
                return;
        }

        const msg = Color.string(text);
        gLogger.info(`[${dim('NewStringUTF')}] ${msg} ${this.prevRet()}`);
    });
    repl(envWrapper, JNI.FindClass, function (retval, env, str) {
        if (!predicate(this) || isNully(str)) return;

        const msg = lavender(`${str.readCString()}`);
        gLogger.info(`[${dim('FindClass')}] ${msg} ${retval} ${addressOf(this.returnAddress)}`);
    });
    repl(envWrapper, JNI.NewGlobalRef, function (retval, env, obj) {
        if (!predicate(this) || isNully(obj) || isNully(retval)) return;
        const getObjectClass = asFunction(env, JNI.GetObjectClass);
        const refClass = getObjectClass(env, obj);
        const typeName = Java.cast(refClass, Classes.Class).getName();
        if (typeName.match(/^\$Proxy[0-9]+$/) || typeName === ClassesString.Long) {
            return;
        }
        switch (typeName) {
            case 'com.android.org.conscrypt.OpenSSLX509Certificate':
            case 'android.media.MediaRouter$RouteInfo':
            case 'android.view.Display':
                return;
            default:
                if (typeName.includes('android.media.AudioDeviceInfo')) return;
        }

        const type = Text.toPrettyType(typeName);
        const value = vs(obj, type, env);
        const msg = `${Color.className(type)}: ${value}`;
        gLogger.info(`[${dim('NewGlobalRef')}] ${msg}`);
    });

    const GetMethodText = (retval: NativePointer, name: NativePointer, sig: NativePointer) => {
        let sigText = `${sig.readCString()}`;
        const types = signatureToPrettyTypes(sigText);
        if (types) {
            sigText = `(${types.splice(0, 1).join(', ')})${types[0] !== 'void' ? `: ${types[0]}` : ''}`;
        }
        return `${name.readCString()}${sigText} ? ${retval}`;
    };
    repl(envWrapper, JNI.GetMethodID, function (retval, env, clazz, name, sig) {
        if (!predicate(this) || isNully(clazz) || isNully(name) || isNully(sig)) return;
        const method = resolveMethod(env, clazz, retval, false);
        switch (method?.className) {
            case 'com.cocos.lib.CocosHelper':
            case 'org.cocos2dx.lib.CanvasRenderingContext2DImpl':
            case 'com.cocos.lib.CanvasRenderingContext2DImpl':
                return;
        }

        const msg = `${method ? ColorMethod(retval, method) : GetMethodText(retval, name, sig)}`;
        gLogger.info(`[${dim('GetMethodID')}] ${msg}`);
    });
    repl(envWrapper, JNI.GetStaticMethodID, function (retval, env, clazz, name, sig) {
        if (!predicate(this) || isNully(clazz) || isNully(name) || isNully(sig)) return;
        const method = resolveMethod(env, clazz, retval, true);
        if (method?.className === 'com.cocos.lib.CocosHelper') return;
        if (method?.className === 'com.cocos.lib.CanvasRenderingContext2DImpl') return;

        const msg = `${method ? ColorMethod(retval, method) : GetMethodText(retval, name, sig)}`;
        gLogger.info(`[${dim('GetStaticMethodID')}] ${msg} ${addressOf(this.returnAddress)}`);
    });

    const GetFieldText = (
        retval: NativePointer,
        env: NativePointer,
        clazz: NativePointer,
        name: NativePointer,
        sig: NativePointer,
    ) => {
        const clazzName = getClassName(env, clazz);
        const sigName = `${sig.readCString()}`;
        const typeName = signatureToPrettyTypes(sigName)?.[0] ?? sigName;
        const fieldName = `${name.readCString()}`;
        if (fieldName === 'refreshRateFPS' && clazzName === 'io.flutter.embedding.engine.FlutterJNI') return;

        const id = redBright(`${retval} -${dim('>')}`);
        return `${id}${Color.className(clazzName)}${Color.bracket('.')}${Color.field(fieldName)}: ${Color.className(typeName)}`;
    };
    repl(envWrapper, JNI.GetFieldID, function (retval, env, clazz, name, sig) {
        if (!predicate(this) || isNully(clazz) || isNully(name)) return;

        const msg = GetFieldText(retval, env, clazz, name, sig);
        if (!msg) return;
        gLogger.info(`[${dim('GetFieldID')}] ${msg}`);
    });
    repl(envWrapper, JNI.GetStaticFieldID, function (retval, env, clazz, name, sig) {
        if (!predicate(this) || isNully(clazz) || isNully(name)) return;

        const msg = GetFieldText(retval, env, clazz, name, sig);
        if (!msg) return;
        gLogger.info(`[${dim('GetStaticFieldID')}] ${msg}`);

        const fen = `${name.readCString()}`;
        if (fen === 'BRAND' || fen === 'MANUFACTURER' || fen === 'DISPLAY') {
            const SetStaticObjectField = asFunction(env, JNI.SetStaticObjectField);
            const NewStringUTF = asFunction(env, JNI.NewStringUTF);
            const newString = NewStringUTF(env, Memory.allocUtf8String(fen));
            SetStaticObjectField(env, clazz, retval, newString);
        }
    });

    repl(envWrapper, JNI.DefineClass, function (retval, env, name, obj, bytes, size) {
        if (!predicate(this) || isNully(name) || isNully(obj)) return;

        const msg = `${orange(`${obj}`)} ${name} ${size} `;
        gLogger.info(`[${dim('DefineClass')}] ${msg}`);
    });
    repl(envWrapper, JNI.RegisterNatives, function (retval, env, clazz, jMethodDef, count) {
        if (!predicate(this) || isNully(clazz) || isNully(jMethodDef)) return;

        const methods: string[] = [];
        for (let i = 0; i < count; i++) {
            const namePtr = jMethodDef.add(i * Process.pointerSize * 3).readPointer();
            const sigPtr = jMethodDef.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer();
            const fnPtrPtr = jMethodDef
                .add(i * Process.pointerSize * 3 + Process.pointerSize * 2)
                .readPointer();

            let sigText = `${sigPtr.readCString()}`;
            const types = signatureToPrettyTypes(sigText);
            if (types) {
                sigText = `(${types.splice(0, 1).join(', ')})${types[0] && types[0] !== 'void' ? `: ${types[0]}` : ''}`;
            }
            const text = `    ${black(dim('  >'))}${orange(`${namePtr.readCString()}`)}${sigText} ? ${gray(`${addressOf(fnPtrPtr)}`)}`;
            methods.push(text);
        }

        const clazzName = getClassName(env, clazz);
        const msg = `${orange(`${jMethodDef}`)} ${clazzName} ${addressOf(this.returnAddress, true)}\n${methods.join('\n')}`;
        gLogger.info(`[${dim('RegisterNatives')}] ${msg}`);
    });

    repl(envWrapper, JNI.GetObjectArrayElement, function (retval, env, jarray, i) {
        if (!predicate(this) || isNully(jarray) || !i) return;
        const getObjectClass = asFunction(env, JNI.GetObjectClass);
        const refClass = !isNully(retval) ? getObjectClass(env, retval) : null;
        const typeName = refClass ? Java.cast(refClass, Classes.Class).getName() : null;
        const type = typeName ? Text.toPrettyType(typeName) : null;

        switch (type) {
            case 'com.android.org.conscrypt.OpenSSLX509Certificate':
            case 'android.media.AudioDeviceInfo':
                return;
        }

        const value = vs(retval, type ?? undefined, env);
        const msg = `${type ?? jarray}[${i}] ${value}`;
        gLogger.info(`[${dim('GetObjectArrayElement')}] ${msg}`);
    });

    const fn = (arg: JniDefinition<any, any>) => envWrapper.getFunction(arg);
    const jfn = (arg: JniDefinition<any, any> & { name: string }) => new JNIMethod(arg.name, fn(arg));
    // for (const { name, address } of symbols) {
    //     if (
    //         name.includes('art') &&
    //         name.includes('JNI') &&
    //         name.includes('_ZN3art3JNIILb0') &&
    //         !name.includes('CheckJNI')
    //     ) {
    //        if (name.includes('ToReflectedMethod')) {
    //             logger.trace(`ToReflectedMethod is at ${name} ${address}`);
    //         } else if (name.includes('GetArrayLength')) {
    //             Interceptor.attach(address, {
    //                 onLeave: hookIfTag('GetArrayLength', (retval) => `${retval}`),
    //             });
    //         } else if (name.includes('SetByteArrayRegion')) {
    //             Interceptor.attach(address, {
    //                 onLeave: hookIfTag('SetByteArrayRegion', (retval) => `${retval}`),
    //             });
    //         } else if (name.includes('NewObjectArray')) {
    //             Interceptor.attach(address, {
    //                 onLeave: hookIfTag('NewObjectArray', (retval) => `${retval}`),
    //             });
    //         } else if (name.includes('SetObjectArrayElement')) {
    //             Interceptor.attach(address, {
    //                 onEnter: hookIfTag('SetObjectArrayElement', (args) => `${args[2]} -> ${args[3]}`),
    //             });
    //         } else if (name.includes('ReleaseByteArrayElements')) {
    //             Interceptor.attach(address, {
    //                 onEnter: hookIfTag('ReleaseByteArrayElements', (args) => `${args[2]} -> ${args[3]}`),
    //             });
    //         } else if (name.includes('GetByteArrayElements')) {
    //             Interceptor.attach(address, {
    //                 onLeave: hookIfTag('GetByteArrayElements', (retval) => `${retval}}`),
    //             });
    //         }
    //     }
    // }
    false &&
        Interceptor.attach(fn(JNI.IsSameObject), {
            onEnter(args) {
                this.a0 = args[0];
                this.a1 = args[1];
            },
            onLeave(retval) {
                const msg = `${this.a0} == ${this.a1} ? ${retval}`;
                gLogger.info(`[${dim('IsSameObject')}] ${msg}`);
            },
        });

    // biome-ignore lint/suspicious/noSelfCompare: <explanation>
    // biome-ignore lint/correctness/noConstantCondition: <explanation>
    if (!full) return;

    const CallObjects = [
        JNI.CallObjectMethod,
        JNI.CallObjectMethodA,
        JNI.CallObjectMethodV,
        JNI.CallIntMethod,
        JNI.CallIntMethodA,
        JNI.CallIntMethodV,
        JNI.CallBooleanMethod,
        JNI.CallDoubleMethodA,
        JNI.CallDoubleMethodV,
        JNI.CallFloatMethod,
        JNI.CallFloatMethodA,
        JNI.CallFloatMethodV,
        JNI.CallLongMethod,
        JNI.CallLongMethodA,
        JNI.CallLongMethodV,
        JNI.CallVoidMethod,
        JNI.CallVoidMethodA,
        JNI.CallVoidMethodV,
        JNI.CallStaticObjectMethod,
        JNI.CallStaticObjectMethodA,
        JNI.CallStaticObjectMethodV,
        JNI.CallStaticIntMethod,
        JNI.CallStaticIntMethodA,
        JNI.CallStaticIntMethodV,
        JNI.CallStaticBooleanMethod,
        JNI.CallStaticBooleanMethodA,
        JNI.CallStaticBooleanMethodV,
        JNI.CallStaticDoubleMethod,
        JNI.CallStaticDoubleMethodA,
        JNI.CallStaticDoubleMethodV,
        JNI.CallStaticFloatMethod,
        JNI.CallStaticFloatMethodA,
        JNI.CallStaticFloatMethodV,
        JNI.CallStaticLongMethod,
        JNI.CallStaticLongMethodA,
        JNI.CallStaticLongMethodV,
        JNI.CallStaticVoidMethod,
        JNI.CallStaticVoidMethodA,
        JNI.CallStaticVoidMethodV,
        JNI.CallNonvirtualObjectMethod,
        JNI.CallNonvirtualObjectMethodA,
        JNI.CallNonvirtualObjectMethodV,
        JNI.CallNonvirtualIntMethod,
        JNI.CallNonvirtualIntMethodA,
        JNI.CallNonvirtualIntMethodV,
        JNI.CallNonvirtualBooleanMethod,
        JNI.CallNonvirtualBooleanMethodA,
        JNI.CallNonvirtualBooleanMethodV,
        JNI.CallNonvirtualDoubleMethod,
        JNI.CallNonvirtualDoubleMethodA,
        JNI.CallNonvirtualDoubleMethodV,
        JNI.CallNonvirtualFloatMethod,
        JNI.CallNonvirtualFloatMethodA,
        JNI.CallNonvirtualFloatMethodV,
        JNI.CallNonvirtualLongMethod,
        JNI.CallNonvirtualLongMethodA,
        JNI.CallNonvirtualLongMethodV,
        JNI.CallNonvirtualVoidMethod,
        JNI.CallNonvirtualVoidMethodA,
        JNI.CallNonvirtualVoidMethodV,
        JNI.NewObject,
        JNI.NewObjectA,

        JNI.NewObjectV,
    ];
    for (const j of CallObjects) {
        const { address, name } = jfn(j);
        const mode = name.includes('Static')
            ? JniInvokeMode.Static
            : name.includes('Nonvirtual')
              ? JniInvokeMode.Nonvirtual
              : name.includes('NewObject')
                ? JniInvokeMode.Constructor
                : JniInvokeMode.Normal;
        const cb = JniInvokeCallbacks(envWrapper, j, mode, predicate, {
            onEnter({ method, env, methodID, jArgs }) {
                if (
                    ((method?.className === 'android.content.res.AssetManager$AssetInputStream' ||
                        method?.className === 'java.io.FilterInputStream' ||
                        method?.className === 'java.io.InputStream' ||
                        method?.className === 'java.io.FileOutputStream' ||
                        method?.className === 'java.io.ByteArrayOutputStream') &&
                        (method.name === 'read' || method.name === 'write')) ||
                    (method?.name === 'nanoTime' && method?.className === 'java.lang.System')
                ) {
                    this.ignore = true;
                    return;
                }
                const msg = formatCallMethod(env, methodID, method, jArgs);
                if (method?.className === ClassesString.ClassLoader && method?.name === 'loadClass') {
                    for (const skip of [
                        'org/cocos2dx/lib/CanvasRenderingContext2DImpl',
                        'com/cocos/lib/CanvasRenderingContext2DImpl',
                        'com/cocos/lib/CocosHelper',
                    ]) {
                        if (msg.includes(skip)) {
                            this.ignore = true;
                            return;
                        }
                    }
                }
                switch (method?.className) {
                    case 'org.cocos2dx.lib.CanvasRenderingContext2DImpl':
                    case 'com.cocos.lib.CocosHelper':
                    case 'com.cocos.lib.CanvasRenderingContext2DImpl':
                        this.ignore = true;
                        if (this.ignore) return;
                        break;
                    case 'android.view.Choreographer':
                        this.ignore = method?.name === 'postFrameCallback';
                        if (this.ignore) return;
                        break;
                    case 'java.lang.Long':
                        this.ignore = method?.name === 'longValue';
                        if (this.ignore) return;
                        break;
                    case 'android.media.MediaRouter$RouteInfo':
                        this.ignore = method?.name === 'getPresentationDisplay';
                        if (this.ignore) return;
                        break;
                    case 'android.media.MediaRouter':
                        this.ignore = method?.name === 'getSelectedRoute';
                        if (this.ignore) return;
                        break;
                    case 'android.view.Display':
                        this.ignore = method?.name === 'getDisplayId';
                        if (this.ignore) return;
                        break;
                    case 'android.media.AudioDeviceInfo':
                        this.ignore = method?.name === 'getType';
                        if (this.ignore) return;
                        break;
                    case 'android.media.AudioManager':
                        this.ignore = method?.name === 'getDevices';
                        if (this.ignore) return;
                        break;
                    case 'java.security.cert.Certificate':
                        this.ignore = method?.name === 'getEncoded';
                        if (this.ignore) return;
                        break;
                }

                gLogger.info(
                    `[${dim(name)}] ${msg} ${addressOf(previousReturn(this.returnAddress as any, 2)) ?? ''}`,
                );
            },
            onLeave({ env, method, obj, jArgs }, retval) {
                if (this.ignore || method?.isVoid) return;
                //if (
                //    method?.name === 'getItem' &&
                //    `${Java.cast(jArgs?.[0] as NativePointer, Classes.String)}` === 'soundC'
                //) {
                //    logger.info({ tag: 'hi' }, 'nya');
                //    const ns = asFunction(env, JNI.NewStringUTF);
                //    const p = ns(env, Memory.allocUtf8String('https://google.pl/search?q=hi'));
                //    retval.replace(p);
                //}
                //if (method?.name === 'getRawOffset') {
                //    const offs = [
                //        -10800000, -12600000, -14400000, -18000000, -21600000, -25200000, -28800000,
                //        -32400000, -34200000, -3600000, -36000000, -39600000, -43200000, -7200000, 0,
                //        10800000, 12600000, 14400000, 16200000, 18000000, 19800000, 20700000, 21600000,
                //        23400000, 25200000, 28800000, 31500000, 32400000, 34200000, 3600000, 36000000,
                //        37800000, 39600000, 43200000, 45900000, 46800000, 50400000, 7200000,
                //    ];
                //    // retval.replace(ptr(offs[0]));
                //}

                if (method?.name === 'decode') {
                    //ProcMaps.printStacktrace(this.context);
                    //const msg = Thread.backtrace(this.context, Backtracer.FUZZY).map((x) => addressOf(x));
                }
                //if (method?.className === ClassesString.String && method?.name === 'contains') {
                //    logger.info({ tag: 'contains' }, `${Java.cast(obj as NativePointer, Classes.String)}`);
                //}
                const msg = formatMethodReturn(env, retval, method?.returnType);
                gLogger.info(`[${dim(name)}] ${msg} ${addressOf(this.returnAddress as any)}`);
            },
        });
        Interceptor.attach(address, cb);
    }
}

function repl<T extends NativeFunctionReturnType, R extends [] | NativeFunctionArgumentType[]>(
    envWrapper: EnvWrapper,
    def: JniDefinition<T, R>,
    log: (
        this: (InvocationContext | CallbackContext) & { prevRet: () => any },
        retval: mFunctionReturn<T>,
        ...args: mFunctionParameters<R>
    ) => void,
) {
    const fn = envWrapper.getFunction<T, R>(def);
    const cb: NativeCallbackImplementation<any, any> = function (
        this: (InvocationContext | CallbackContext) & { prevRet: () => any },
        ...args: mFunctionParameters<R>
    ): mFunctionReturn<T> {
        const retval: mFunctionReturn<T> = fn(...args);
        this.prevRet = () => addressOf(previousReturn(this.context as Arm64CpuContext));
        log.call(this, retval, ...args);
        return retval;
    } as any;
    Interceptor.replace(
        fn,
        new NativeCallback(
            cb,
            def.retType as NativeCallbackReturnType,
            def.argTypes as [] | NativeCallbackArgumentType[],
        ),
    );
}

type RemapAllParams<T extends (...args: any[]) => any, MapFn extends (param: any) => any> = T extends (
    ...args: infer A
) => infer R
    ? (...args: { [K in keyof A]: A[K] & ReturnType<MapFn> }) => R
    : never;
type mFunction<
    T extends NativeFunctionReturnType,
    R extends [] | NativeFunctionArgumentType[],
> = RemapAllParams<ReturnType<typeof asFunction<T, R>>, () => NativePointer>;
type mFunctionReturn<T extends NativeFunctionReturnType> = ReturnType<mFunction<T, any>>;
type mFunctionParameters<R extends [] | NativeFunctionArgumentType[]> = Parameters<mFunction<any, R>>;
export { EnvWrapper, JNI, asFunction, asLocalRef, hookLibart as attach, envWrapper, getObjectClassName };
