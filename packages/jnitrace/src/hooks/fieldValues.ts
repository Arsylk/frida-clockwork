import { isNully, isNullyVararg, Text, tryNull, vs } from '@clockwork/common';
import { asExceptionSafe, asFunction, EnvWrapper, getClassName, getObjectClassName } from '../envWrapper.js';
import { JniHookItems, JniHookItemsObject } from '../hooks.js';
import { jFieldID, JNI } from '../jni.js';
import { Color, logger } from '@clockwork/logging';
import { addressOf, getEnumerated } from '@clockwork/native';
import Java from 'frida-java-bridge';
const { dim, redBright } = Color.use();

function getFieldValueHooks(envWrapper: EnvWrapper): JniHookItems {
  const libart = Process.getModuleByName('libart.so');
  const GetFieldNamePtr = getEnumerated(libart, '_ZN3art8ArtField7GetNameEv');
  const GetFieldName = new NativeFunction(GetFieldNamePtr, 'pointer', ['pointer']);
  const getNameText = (id: jFieldID) => tryNull(() => GetFieldName(id).readCString()) ?? `${id}`;

  const getHooks = [
    [JNI.GetBooleanField, 'boolean'] as const,
    [JNI.GetByteField, 'byte'] as const,
    [JNI.GetCharField, 'char'] as const,
    [JNI.GetShortField, 'short'] as const,
    [JNI.GetIntField, 'int'] as const,
    [JNI.GetDoubleField, 'double'] as const,
    [JNI.GetFloatField, 'float'] as const,
  ].map(([j, typeName]) => {
    const fn = function ({ args: [jniEnv, jobject, fieldId], retval }) {
      if (isNully(jniEnv) || isNully(jobject) || isNully(fieldId)) return;
      const clazzName = jobject ? Java.cast(jobject, Classes.Object).$className : null;
      const clazzText = clazzName ? Color.className(Text.toPrettyType(clazzName)) : null;
      const msg = formatGetField(retval, typeName, clazzText ?? '', getNameText(fieldId), false);

      logger.info(`[${dim(j.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    };

    return [j.name, fn];
  });
  const getStaticHooks = [
    [JNI.GetStaticBooleanField, 'boolean'] as const,
    [JNI.GetStaticByteField, 'byte'] as const,
    [JNI.GetStaticCharField, 'char'] as const,
    [JNI.GetStaticShortField, 'short'] as const,
    [JNI.GetStaticIntField, 'int'] as const,
    [JNI.GetStaticDoubleField, 'double'] as const,
    [JNI.GetStaticFloatField, 'float'] as const,
  ].map(([j, typeName]) => {
    const fn = function ({ args: [jniEnv, jclass, fieldId], retval }) {
      if (isNully(jniEnv) || isNully(jclass) || isNully(fieldId)) return;
      const clazzName = jclass ? Java.cast(jclass, Classes.Class).getName() : null;
      const clazzText = clazzName ? Color.className(Text.toPrettyType(clazzName)) : null;
      const msg = formatGetField(retval, typeName, clazzText ?? '', getNameText(fieldId), true);

      logger.info(`[${dim(j.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    };

    return [j.name, fn];
  });
  const getObjHook = [
    JNI.GetObjectField.name,
    function ({ args: [jniEnv, jobject, fieldId], retval }) {
      if (isNully(jniEnv) || isNully(jobject) || isNully(fieldId)) return;
      const clazzName = asExceptionSafe(jniEnv, () => getObjectClassName(jniEnv, jobject));
      const clazzText = clazzName ? Color.className(Text.toPrettyType(clazzName)) : null;
      const valClazzName = asExceptionSafe(jniEnv, () => getObjectClassName(jniEnv, retval));
      const valClazzText = Text.toPrettyType(valClazzName);
      const msg = formatGetField(retval, valClazzText, clazzText ?? '', getNameText(fieldId), false);

      logger.info(`[${dim(JNI.GetObjectField.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
  ];

  const getStaticObjHook = [
    JNI.GetStaticObjectField.name,
    function ({ args: [jniEnv, jclass, fieldId], retval }) {
      if (isNully(jniEnv) || isNully(jclass) || isNully(fieldId)) return;
      const clazzName = jclass ? Java.cast(jclass, Classes.Class).getName() : null;
      const clazzText = clazzName ? Color.className(Text.toPrettyType(clazzName)) : null;
      const valClazzName = asExceptionSafe(jniEnv, () => getObjectClassName(jniEnv, retval));
      const valClazzText = Text.toPrettyType(valClazzName);
      const msg = formatGetField(retval, valClazzText, clazzText ?? '', getNameText(fieldId), true);

      logger.info(`[${dim(JNI.GetStaticObjectField.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
  ];

  const setHooks = [
    [JNI.SetBooleanField, 'boolean'] as const,
    [JNI.SetByteField, 'byte'] as const,
    [JNI.SetCharField, 'char'] as const,
    [JNI.SetShortField, 'short'] as const,
    [JNI.SetIntField, 'int'] as const,
    [JNI.SetDoubleField, 'double'] as const,
    [JNI.SetFloatField, 'float'] as const,
  ].map(([j, typeName]) => {
    const fn = function ({ args: [jniEnv, jobject, fieldId, newval], retval }) {
      if (isNully(jniEnv) || isNully(jobject) || isNully(fieldId)) return;
      const clazzName = jobject ? Java.cast(jobject, Classes.Object).$className : null;
      const clazzText = clazzName ? Color.className(Text.toPrettyType(clazzName)) : null;
      const msg = formatSetField(newval, typeName, clazzText ?? '', getNameText(fieldId), false);

      logger.info(`[${dim(j.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    };

    return [j.name, fn];
  });
  const setStaticHooks = [
    [JNI.SetStaticBooleanField, 'boolean'] as const,
    [JNI.SetStaticByteField, 'byte'] as const,
    [JNI.SetStaticCharField, 'char'] as const,
    [JNI.SetStaticShortField, 'short'] as const,
    [JNI.SetStaticIntField, 'int'] as const,
    [JNI.SetStaticDoubleField, 'double'] as const,
    [JNI.SetStaticFloatField, 'float'] as const,
  ].map(([j, typeName]) => {
    const fn = function ({ args: [jniEnv, jclass, fieldId, newval], retval }) {
      if (isNully(jniEnv) || isNully(jclass) || isNully(fieldId)) return;
      const clazzName = jclass ? Java.cast(jclass, Classes.Class).getName() : null;
      const clazzText = clazzName ? Color.className(Text.toPrettyType(clazzName)) : null;
      const msg = formatSetField(newval, typeName, clazzText ?? '', getNameText(fieldId), true);

      logger.info(`[${dim(j.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    };

    return [j.name, fn];
  });

  const setObjHook = [
    JNI.SetObjectField.name,
    function ({ args: [jniEnv, jobject, fieldId, newval], retval }) {
      if (isNully(jniEnv) || isNully(jobject) || isNully(fieldId)) return;
      const clazzName = asExceptionSafe(jniEnv, () => getObjectClassName(jniEnv, jobject));
      const clazzText = clazzName ? Color.className(Text.toPrettyType(clazzName)) : null;
      const valClazzName = !isNully(newval)
        ? asExceptionSafe(jniEnv, () => getObjectClassName(jniEnv, newval))
        : null;
      const valClazzText = Text.toPrettyType(valClazzName);
      const msg = formatSetField(newval, valClazzText, clazzText ?? '', getNameText(fieldId), false);

      logger.info(`[${dim(JNI.SetObjectField.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
  ];
  const setStaticObjHook = [
    JNI.SetStaticObjectField.name,
    function ({ args: [jniEnv, jclass, fieldId, newval], retval }) {
      if (isNully(jniEnv) || isNully(jclass) || isNully(fieldId)) return;
      const clazzName = jclass ? Java.cast(jclass, Classes.Class).getName() : null;
      const clazzText = clazzName ? Color.className(Text.toPrettyType(clazzName)) : null;
      const valClazzName = !isNully(newval)
        ? asExceptionSafe(jniEnv, () => getObjectClassName(jniEnv, newval))
        : null;
      const valClazzText = Text.toPrettyType(valClazzName);
      const msg = formatSetField(newval, valClazzText, clazzText ?? '', getNameText(fieldId), true);

      logger.info(`[${dim(JNI.SetStaticObjectField.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
  ];

  return [
    ...getHooks,
    ...getStaticHooks,
    getObjHook,
    getStaticObjHook,
    ...setHooks,
    ...setStaticHooks,
    setObjHook,
    setStaticObjHook,
  ] as JniHookItems;
}

function formatGetField(
  retval: NativePointer,
  typeName: string,
  parentText: string,
  idText: string,
  isStatic: boolean,
) {
  const prefix = isStatic ? `${Color.keyword('static')} ` : '';
  return `get ${prefix}${parentText}${Color.bracket('.')}${Color.field(idText)}: ${Color.className(typeName)} = ${vs(retval, typeName)}`;
}

function formatSetField(
  newval: NativePointer,
  typeName: string,
  parentText: string,
  idText: string,
  isStatic: boolean,
) {
  const prefix = isStatic ? `${Color.keyword('static')} ` : '';
  return `set ${prefix}${parentText}${Color.bracket('.')}${Color.field(idText)}: ${Color.className(typeName)} = ${vs(newval, typeName)}`;
}

export { getFieldValueHooks };
