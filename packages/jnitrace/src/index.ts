import Java from 'frida-java-bridge';
import { Classes, ClassesString, Text, isNully, tryNull, vs, emitter } from '@clockwork/common';
import { Consts } from '@clockwork/common';
import { Color, logger as gLogger, subLogger } from '@clockwork/logging';
import { addressOf, previousReturn } from '@clockwork/native';
import { fbase64, ProcMaps } from '@clockwork/cmodules';
import {
    EnvWrapper,
    type JniDefinition,
    asExceptionSafe,
    asFunction,
    asLocalRef,
    getClassName,
    getObjectClassName,
} from './envWrapper.js';
import { JNI } from './jni.js';
import { JniInvokeCallbacks } from './jniInvokeCallback.js';
import { JNIMethod, type JavaMethod, JniInvokeMode } from './model.js';
import { resolveMethod, signatureToPrettyTypes } from './tracer.js';
import { className } from '@clockwork/logging/dist/color.js';
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
        case 'com.unity3d.player.UnityGameState':
            isMultiline = method.name in ['setGameState'];
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
        mappedArgs[i] = asExceptionSafe(jniEnv, () => vs(arg, param, jniEnv));
    }
    return ColorMethodInvoke(method, mappedArgs);
}

function formatMethodReturn(jniEnv: NativePointer, value: unknown, type?: string): string {
    const text = asExceptionSafe(jniEnv, () => vs(value, type, jniEnv));

    return `${dim('return')} ${text}`; // + `${type}[${value}: ${typeof value}]`;
}

let envWrapper: EnvWrapper;

function hookLibart(predicate: (thisRef: InvocationContext | CallbackContext) => boolean, full: boolean) {
    envWrapper ??= new EnvWrapper(Java.vm.getEnv());

    // repl(envWrapper, JNI.GetStringUTFChars, function (retval, env, str, smth) {
    //     if (!predicate(this) || isNully(retval)) return;
    //
    //     const msg = Color.string(retval.readCString());
    //     gLogger.info(`[${dim('GetStringUTFChars')}] ${msg}`);
    // });
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

    const GetMethodText = (
        retval: NativePointer,
        env: NativePointer,
        clazz: NativePointer,
        name: NativePointer,
        sig: NativePointer,
    ) => {
        const clazzName = tryNull(() => asExceptionSafe(env, () => getClassName(env, clazz))) ?? `${clazz}`;
        let sigText = `${sig.readCString()}`;
        let retText = '';
        const types = signatureToPrettyTypes(sigText);
        if (types) {
            sigText = `${types.splice(0, 1).map(Color.className).join(', ')}`;
            retText = types[0] !== 'void' ? `: ${Color.className(types[0])}` : '';
        }
        const id = redBright(`0x00000000 -${dim('>')}`);
        return `${id}${Color.className(clazzName)}::${Color.method(name.readCString())}${Color.bracket('(')}${sigText}${Color.bracket(')')}${retText}`;
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

        const msg = `${method ? ColorMethod(retval, method) : GetMethodText(retval, env, clazz, name, sig)}`;
        gLogger.info(`[${dim('GetMethodID')}] ${msg}`);
    });
    repl(envWrapper, JNI.GetStaticMethodID, function (retval, env, clazz, name, sig) {
        if (!predicate(this) || isNully(clazz) || isNully(name) || isNully(sig)) return;
        const method = resolveMethod(env, clazz, retval, true);
        if (method?.className === 'com.cocos.lib.CocosHelper') return;
        if (method?.className === 'com.cocos.lib.CanvasRenderingContext2DImpl') return;

        const msg = `${method ? ColorMethod(retval, method) : GetMethodText(retval, env, clazz, name, sig)}`;
        gLogger.info(`[${dim('GetStaticMethodID')}] ${msg} ${addressOf(this.returnAddress)}`);
    });

    const GetFieldText = (
        retval: NativePointer,
        env: NativePointer,
        clazz: NativePointer,
        name: NativePointer,
        sig: NativePointer,
    ) => {
        const clazzName = tryNull(() => asExceptionSafe(env, () => getClassName(env, clazz))) ?? `${clazz}`;
        const sigName = `${sig?.readCString()}`;
        const typeName = signatureToPrettyTypes(sigName)?.[0] ?? sigName;
        const fieldName = `${name.readCString()}`;
        if (fieldName === 'refreshRateFPS' && clazzName === 'io.flutter.embedding.engine.FlutterJNI') return;

        const id = redBright(`${isNully(retval) ? '0x00000000' : retval} -${dim('>')}`);
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
                if (method?.name === 'isDebuggerConnected') {
                    this.ignore = true;
                    return;
                }
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
                    case 'org.godotengine.godot.Godot':
                        this.ignore = method?.name === 'getCACertificates';
                        break;
                    case 'com.unity3d.player.UnityPlayer':
                        this.ignore = method?.name === 'executeMainThreadJobs';
                        break;
                    case 'org.cocos2dx.lib.CanvasRenderingContext2DImpl':
                    case 'com.cocos.lib.CocosHelper':
                    case 'com.cocos.lib.CanvasRenderingContext2DImpl':
                        this.ignore = true;
                        break;
                    case 'android.view.Choreographer':
                        this.ignore = method?.name === 'postFrameCallback';
                        break;
                    case 'java.lang.Long':
                        this.ignore = method?.name === 'longValue';
                        break;
                    case 'android.media.MediaRouter$RouteInfo':
                        this.ignore = method?.name === 'getPresentationDisplay';
                        break;
                    case 'android.media.MediaRouter':
                        this.ignore = method?.name === 'getSelectedRoute';
                        break;
                    case 'android.view.Display':
                        this.ignore = method?.name === 'getDisplayId';
                        break;
                    case 'android.media.AudioDeviceInfo':
                        this.ignore = method?.name === 'getType';
                        break;
                    case 'android.media.AudioManager':
                        this.ignore = method?.name === 'getDevices';
                        break;
                    case 'java.security.cert.Certificate':
                        this.ignore = method?.name === 'getEncoded';
                        break;
                }
                if (this.ignore) return;

                gLogger.info(
                    `[${dim(name)}] ${msg} ${addressOf(previousReturn(this.returnAddress as any, 2)) ?? ''}`,
                );
            },
            onLeave({ env, method, obj, jArgs }, retval) {
                if (this.ignore || method?.isVoid) return;
                if (method?.name === 'isDebuggerConnected') {
                    this.ignore = true;
                    return;
                }
                //ProcMaps.printStacktrace(this.context);
                //const msg = Thread.backtrace(this.context, Backtracer.FUZZY).map((x) => addressOf(x));
                //if (method?.className === ClassesString.String && method?.name === 'contains') {
                //    logger.info({ tag: 'contains' }, `${Java.cast(obj as NativePointer, Classes.String)}`);
                //}
                const msg = formatMethodReturn(env, retval, method?.returnType);
                gLogger.info(`[${dim(name)}] ${msg} ${addressOf(this.returnAddress)}`);
            },
        });
        Interceptor.attach(address, cb);
    }
}

function barebone(predicate: (thisRef: InvocationContext | CallbackContext) => boolean) {
    envWrapper ??= new EnvWrapper(Java.vm.getEnv());

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
        const msg = `${method ? ColorMethod(retval, method) : GetMethodText(retval, name, sig)}`;
        gLogger.info(`[${dim('GetMethodID')}] ${msg}`);
    });
    repl(envWrapper, JNI.GetStaticMethodID, function (retval, env, clazz, name, sig) {
        if (!predicate(this) || isNully(clazz) || isNully(name) || isNully(sig)) return;
        const method = resolveMethod(env, clazz, retval, true);
        const msg = `${method ? ColorMethod(retval, method) : GetMethodText(retval, name, sig)}`;
        gLogger.info(`[${dim('GetStaticMethodID')}] ${msg} ${addressOf(this.returnAddress)}`);
    });
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
export {
    EnvWrapper,
    JNI,
    asFunction,
    asLocalRef,
    hookLibart as attach,
    envWrapper,
    getObjectClassName,
    barebone,
};
