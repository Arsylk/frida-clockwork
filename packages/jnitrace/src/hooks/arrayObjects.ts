import { isNully, isNullyVararg, Text, vs } from '@clockwork/common';
import { asExceptionSafe, asFunction, EnvWrapper, getClassName } from '../envWrapper.js';
import { JniHookItems, JniHookItemsObject } from '../hooks.js';
import { JNI } from '../jni.js';
import { Color, logger } from '@clockwork/logging';
import { addressOf } from '@clockwork/native';
import Java from 'frida-java-bridge';
const { dim, redBright } = Color.use();

function getArrayObjectHooks(envWrapper: EnvWrapper): JniHookItems {
  const newHooks = [
    [JNI.NewBooleanArray, 'boolean'] as const,
    [JNI.NewByteArray, 'byte'] as const,
    [JNI.NewCharArray, 'char'] as const,
    [JNI.NewShortArray, 'short'] as const,
    [JNI.NewDoubleArray, 'double'] as const,
    [JNI.NewFloatArray, 'float'] as const,
  ].map(([j, typeName]) => {
    const fn = function ({ args: [jniEnv, size], retval }) {
      if (isNully(jniEnv) || isNully(size)) return;
      const msg = formatNewArray(retval, size, typeName);

      logger.info(`[${dim(j.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    };

    return [j.name, fn];
  });
  const newObjHook = [
    JNI.NewObjectArray.name,
    function ({ args: [jniEnv, size, clazz, obj], retval }) {
      if (isNully(jniEnv) || isNully(size) || isNully(clazz)) return;
      const clazzName = asExceptionSafe(jniEnv, () => getClassName(jniEnv, clazz));
      const clazzText = Text.toPrettyType(clazzName);
      const msg = formatNewArray(retval, size, clazzText);

      logger.info(`[${dim(JNI.NewObjectArray.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
  ];
  const elmHooks = [
    [JNI.GetBooleanArrayElements, 'boolean'] as const,
    [JNI.GetByteArrayElements, 'byte'] as const,
    [JNI.GetCharArrayElements, 'char'] as const,
    [JNI.GetShortArrayElements, 'short'] as const,
    [JNI.GetDoubleArrayElements, 'double'] as const,
    [JNI.GetFloatArrayElements, 'float'] as const,
  ].map(([j, typeName]) => {
    const fn = function ({ args: [jniEnv, array, isCopy], retval }) {
      if (isNullyVararg(jniEnv, array)) return;
      const msg = `${Color.className(typeName)}[]: ${vs(retval, `${typeName}[]`, jniEnv)}`;

      logger.info(`[${dim(j.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    };
  });
  const elmObjHook = [
    JNI.GetObjectArrayElement.name,
    function ({ args: [jniEnv, jarray, i], retval }) {
      if (isNullyVararg(jniEnv, jarray)) return;

      const getObjectClass = asFunction(jniEnv, JNI.GetObjectClass);
      const refClass = !isNully(retval) ? getObjectClass(jniEnv, retval) : null;
      const typeName = refClass ? Java.cast(refClass, Classes.Class).getName() : null;
      const type = typeName ? Color.className(Text.toPrettyType(typeName)) : null;

      const value = vs(retval, type ?? undefined, jniEnv);
      const msg = `${type ?? jarray}[${i}] ${value}`;
      logger.info(`[${dim(JNI.GetObjectArrayElement.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
  ];
  const lengthHook = [
    JNI.GetArrayLength.name,
    function ({ args: [jniEnv, jarray], retval }) {
      if (isNullyVararg(jniEnv, jarray)) return;

      const getObjectClass = asFunction(jniEnv, JNI.GetObjectClass);
      const refClass = getObjectClass(jniEnv, jarray);
      const typeName = refClass ? Java.cast(refClass, Classes.Class).getName() : null;
      const type = typeName ? Color.className(Text.toPrettyType(typeName)) : null;
      const msg = `${jarray} ${type ?? ''} { ${Color.number(Number(retval))} }`;
      logger.info(`[${dim(JNI.GetArrayLength.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
  ];
  return [...newHooks, newObjHook, ...elmHooks, elmObjHook, lengthHook] as JniHookItems;
}

function formatNewArray(retval: NativePointer, size: number, clazzText: string): string {
  let sb = '';

  sb += `${retval} `;
  sb += `${Color.keyword('new')} `;
  sb += `${Color.className(clazzText)}[] `;
  sb += `${'{'}`;
  sb += ` ${Color.number(Number(size))} `;
  sb += `${'}'}`;

  return sb;
}

export { getArrayObjectHooks };
