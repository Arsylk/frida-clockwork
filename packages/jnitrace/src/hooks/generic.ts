import { ClassesString, isNully, isNullyVararg, Text, tryNull, vs } from '@clockwork/common';
import { asExceptionSafe, asFunction, EnvWrapper, getClassName } from '../envWrapper.js';
import { JniArgumentType, JniExtendedHook, JniHookItems, JniHookItemsObject } from '../hooks.js';
import { Color, logger } from '@clockwork/logging';
import { JNI } from '../jni.js';
import { addressOf } from '@clockwork/native';
import Java from 'frida-java-bridge';
import { parseJniSignature, signatureToPrettyTypes } from '../tracer.js';
const { lavender, orange, dim, black, gray } = Color.use();

function getOtherHooks(envWrapper: EnvWrapper): JniHookItems {
  const hooks: JniHookItemsObject = {
    FindClass: function ({ args: [jniEnv, str], retval }) {
      if (isNullyVararg(jniEnv, str)) return;
      const clazzName = `${str.readCString()}`;
      if (filterFindClass.call(this, clazzName)) return;
      const msg = `${lavender(clazzName)} = ${isNully(retval) ? Color.keyword(null) : retval}`;
      logger.info(`[${dim(JNI.FindClass.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
    NewGlobalRef: function ({ args: [jniEnv, jobject], retval }) {
      if (isNullyVararg(jniEnv, jobject)) return;

      const getObjectClass = asFunction(jniEnv, JNI.GetObjectClass);
      const refClass = getObjectClass(jniEnv, jobject);
      const typeName = Java.cast(refClass, Classes.Class).getName();
      if (filterGlobalRef.call(this, typeName)) return;

      const type = Text.toPrettyType(typeName);
      const value = asExceptionSafe(jniEnv, () => vs(jobject, type, jniEnv)) ?? `${retval}`;
      const msg = `${Color.className(type)}: ${value}`;
      logger.info(`[${dim(JNI.NewGlobalRef.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
    DefineClass: function ({ args: [jniEnv, name, loader, bytes, size], retval }) {
      if (isNullyVararg(jniEnv, name, loader, bytes)) return;
      const nameText = `${name.readCString()}`;
      const msg = `${orange(nameText)} ${loader} ${dim(Text.toByteSize(Number(size)))}`;
      logger.info(`[${dim(JNI.DefineClass.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
    RegisterNatives: {
      onEnter(this: InvocationContext, args: JniArgumentType<'RegisterNatives'>) {
        const [jniEnv, clazz, jMethodDef, count] = args;
        if (isNullyVararg(jniEnv, clazz, jMethodDef)) return;

        const countnum = Number(count);
        const methods = Array(countnum);
        for (let i = 0; i < countnum; i += 1) {
          const base = jMethodDef.add(i * Process.pointerSize * 3);
          const namePtr = base.readPointer();
          const sigPtr = base.add(Process.pointerSize).readPointer();
          const fnPtrPtr = base.add(Process.pointerSize * 2).readPointer();

          let sigText = `${sigPtr.readCString()}`;
          const types = parseJniSignature(sigText);
          if (types) {
            sigText = `(${types.args.join(', ')})${types.ret !== 'void' ? `: ${types.ret}` : ''}`;
          }
          const text = `    ${black(dim('  >'))}${orange(`${namePtr.readCString()}`)}${sigText} ? ${gray(`${addressOf(fnPtrPtr)}`)}`;
          methods[i] = text;
        }

        const clazzName =
          tryNull(() => asExceptionSafe(jniEnv, () => getClassName(jniEnv, clazz))) ?? `${clazz}`;
        const msg = `${orange(`${jMethodDef}`)} ${clazzName} ${Color.number(countnum)} ${addressOf(this.returnAddress, true)}\n${methods.join('\n')}`;
        // const trace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        //   .map((x) => addressOf(x))
        //   .join('\n\t');
        const trace = '';
        logger.info(`[${dim(JNI.RegisterNatives.name)}] ${msg} ${trace}`);
      },
      onLeave: function (
        this: InvocationContext & { args: JniArgumentType<'RegisterNatives'> },
        retval: InvocationReturnValue,
      ) {
        const [jniEnv, clazz, jMethodDef, count] = this.args;
        if (isNullyVararg(jniEnv, clazz, jMethodDef)) return;
        const code = retval.toInt32();
        const isError = code !== 0;
        const msg = !isError ? `success ${retval}` : `error ${retval}`;
        logger.info(`[${dim(JNI.RegisterNatives.name)}] ${msg}`);
      },
    },
  };
  return Object.entries(hooks) as JniHookItems;
}

function filterFindClass(this: InvocationContext, clazzName: string): boolean {
  const filters = [
    'dalvik/system/VMDebug',
    'android/os/Debug',
    'com/cocos/lib/CocosHelper',
    'org/cocos3dx/lib/CanvasRenderingContext2DImpl',
    'com/cocos/lib/CanvasRenderingContext3DImpl',
  ];
  if (filters.includes(clazzName)) return true;
  return false;
}

function filterGlobalRef(this: InvocationContext, typeName: string): boolean {
  const filters = [
    ClassesString.Long,
    'com.android.org.conscrypt.OpenSSLX510Certificate',
    'android.media.MediaRouter$RouteInfo',
    'android.view.Display',
    'android.media.AudioDeviceInfo',
  ];
  if (typeName.match(/^\$Proxy[0-9]+$/)) return true;
  if (filters.includes(typeName)) return true;
  return false;
}

export { getOtherHooks };
