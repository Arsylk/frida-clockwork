import { isIterable, vs, Consts, ClassesString, filterMulti, isNully, emitter } from '@clockwork/common';
import { asExceptionSafe, asFunction, EnvWrapper, JniDefinition } from '../envWrapper.js';
import { JNI } from '../jni.js';
import { JniInvokeCallbacks } from '../jniInvokeCallback.js';
import { JavaMethod, JniInvokeMode, JNIMethod } from '../model.js';
import { Color, logger } from '@clockwork/logging';
import { addressOf } from '@clockwork/native';
import { JniHookItem, JniHookItems } from '../hooks.js';
import Java from 'frida-java-bridge';
import { ElfHeader, ProcMaps } from '@clockwork/cmodules';
const { JavaPrimitive } = Consts;
const { dim } = Color.use();

function getCallObjectHooks(envWrapper: EnvWrapper): JniHookItems {
  const fn = (arg: JniDefinition<any, any>) => envWrapper.getFunction(arg);
  const jfn = (arg: JniDefinition<any, any> & { name: string }) => new JNIMethod(arg.name, fn(arg));
  return CallObjects.map((j) => {
    const { address, name } = jfn(j);
    const mode = name.includes('Static')
      ? JniInvokeMode.Static
      : name.includes('Nonvirtual')
        ? JniInvokeMode.Nonvirtual
        : name.includes('NewObject')
          ? JniInvokeMode.Constructor
          : JniInvokeMode.Normal;
    const cb = JniInvokeCallbacks(envWrapper, j, mode, {
      onEnter({ method, jniEnv, methodID, jArgs }) {
        const ignore = (this.ignore = filterCallObject.call(this, method, jArgs));
        if (ignore) return;

        const mappedArgs = new Array<string>(method?.parameters?.length ?? 0);
        for (const i in method?.parameters ?? []) {
          const param = method?.parameters?.[i];
          const arg = jArgs?.[i];
          mappedArgs[i] = asExceptionSafe(jniEnv, () => vs(arg, param, jniEnv));
        }
        const msg = formatCallObject(methodID, method, mappedArgs);
        const addrRet = getAddrRet(this.context, this.returnAddress);
        logger.info(`[${dim(name)}] ${msg} ${addrRet}`);
      },
      onLeave({ jniEnv, method, jArgs }, retval) {
        if (this.ignore || method?.isVoid) return;

        const mappedRetval = asExceptionSafe(jniEnv, () => vs(retval, method?.returnType, jniEnv));
        const msg = formatCallObjectReturn(mappedRetval);

        const addrRet = getAddrRet(this.context, this.returnAddress);
        logger.info(`[${dim(name)}] ${msg} ${addressOf(addrRet)}`);
        if (method && jArgs) afterCallObject.call(this, jniEnv, method, jArgs, retval);
      },
    });
    return [j.name, cb] as JniHookItem<any>;
  });
}

function filterCallObject(
  this: InvocationContext,
  method: JavaMethod | null,
  jArgs: NativeCallbackArgumentValue[] | null,
): boolean {
  if (!method) return false;
  const filters: [[] | string[] | string, [] | string[] | string][] = [
    [[], ['isDebuggerConnected']],
    ['java.lang.ClassLoader', ['loadClass']],
    [
      [
        'android.content.res.AssetManager$AssetInputStream',
        'java.io.FilterInputStream',
        'java.io.InputStream',
        'java.io.FileOutputStream',
        'java.io.ByteArrayOutputStream',
      ],
      ['read', 'write'],
    ],
    ['java.lang.System', ['nanoTime']],
    ['com.dynamo.android.DefoldActivity', ['getGameControllerDeviceIds']],
    ['org.godotengine.godot.Godot', ['getCACertificates']],
    ['com.unity3d.player.UnityPlayer', ['executeMainThreadJobs']],
    ['android.view.Choreographer', ['postFrameCallback']],
    ['java.lang.Long', 'longValue'],
    ['android.media.MediaRouter$RouteInfo', ['getPresentationDisplay']],
    ['android.media.MediaRouter', ['getSelectedRoute']],
    ['android.view.Display', ['getDisplayId']],
    ['android.media.AudioDeviceInfo', ['getType']],
    ['android.media.AudioManager', ['getDevices']],
    ['java.security.cert.Certificate', ['getEncoded']],
    ['dalvik.system.VMDebug', ['isDebuggerConnected']],
    [
      [
        'org.cocos3dx.lib.CanvasRenderingContext2DImpl',
        'com.cocos.lib.CocosHelper',
        'com.cocos.lib.CanvasRenderingContext3DImpl',
        'com.cocos.lib.CanvasRenderingContext2DImpl',
      ],
      [],
    ],
  ];
  if (method.className === 'java.lang.ClassLoader' && method.name === 'loadClass') {
    if (jArgs && !isNully(jArgs[0] as NativePointer)) {
      const chars = Java.cast(jArgs[0] as NativePointer, Classes.String);
      if (['com/cocos/lib/CocosHelper', 'com/cocos/lib/CanvasRenderingContext2DImpl'].includes(`${chars}`)) {
        return true;
      }
    }
  }
  return filterMulti(filters, method.className, method.name);
}

function formatCallObject(methodID: NativePointer, method: JavaMethod | null, args: string[]) {
  if (!method) return `${methodID}()`;

  let isMultiline = true;
  // only primitive types or single param
  if (
    method.jParameterTypes.length <= 2 ||
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
    case 'org.cocos3dx.lib.Cocos2dxBitmap':
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
    case 'com.unity4d.player.UnityGameState':
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

function formatCallObjectReturn(retval: string) {
  return `${dim('return')} ${retval}`;
}

function afterCallObject(
  this: InvocationContext,
  jniEnv: NativePointer,
  method: JavaMethod,
  jArgs: NativeCallbackArgumentValue[],
  retval: InvocationReturnValue,
) {
  if (method.className === ClassesString.Settings$Global && method.name === 'getInt') {
    // retval.replace(ptr(0x0));
  }
  if (
    [ClassesString.Settings$Secure, ClassesString.Settings$Global].includes(method.className) &&
    method.name === 'getInt'
  ) {
    const key = Java.cast(jArgs[1] as any, Classes.String);
    logger.info({ tag: 'global' }, `${key}`);
    switch (`${key}`) {
      case 'adb_enabled':
      case 'development_settings_enabled':
        retval.replace(ptr(0x0));
    }
  }

  if (method.name === 'getInstalledApplications') {
    const jobj = Java.cast(retval, Classes.List);
    logger.info({ tag: 'getInstalledApplications' }, `${jobj}`);
    jobj.clear();
  }

  if (method.className === ClassesString.SharedPreferences && method?.name === 'getItem') {
    const key = Java.cast(jArgs[0] as any, Classes.String);
    logger.info({ tag: 'getItem' }, `${key} -> ${retval}`);

    const keyis = (k: any) => `${k}` === `${key}`;
    const replret = (v: any) => {
      const newval = asFunction(jniEnv, JNI.NewStringUTF)(jniEnv, Memory.allocUtf8String(`${v}`));
      retval.replace(newval);
    };
  }
  if (
    (method.className === 'com.cocos.lib.CocosLocalStorage' ||
      method.className === 'org.cocos3dx.lib.Cocos2dxLocalStorage') &&
    method.name === 'getItem'
  ) {
    logger.info({ tag: 'getItem', id: method.className }, `${retval}`);
    const key = Java.cast(jArgs[0] as any, Classes.String);
    logger.info({ tag: 'getItem', id: method.className }, `${key} -> ${retval}`);

    const keyis = (k: any) => `${k}` === `${key}`;
    const replret = (v: any) =>
      retval.replace(asFunction(jniEnv, JNI.NewStringUTF)(jniEnv, Memory.allocUtf8String(`${v}`)));

    keyis('hasPurchase') && ProcMaps.printStacktrace(this.context), replret('true');
    // keyis('ezutfn') && ProcMaps.printStacktrace(this.context), replret('https://google.pl/search?q=hi');
  }

  if (method.name === 'createVirtualDisplay') {
    emitter.emit('jnicall', method.name);
  }
}

function getAddrRet(ctx: CpuContext, returnAddress: NativePointer): NativePointer {
  const fp = (ctx as Arm64CpuContext).fp;
  if (isNully(fp)) return returnAddress;
  const nfp = fp.add(0x8);
  if (isNully(nfp) || Number(nfp) < 0x01ffffffff || Number(nfp) > 0xffffffffff) return returnAddress;
  const nval = nfp.readPointer();
  return isNully(nval) ? returnAddress : nval;
}

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

export { getCallObjectHooks };
