import { isNullyVararg } from '@clockwork/common';
import { asFunction, EnvWrapper } from '../envWrapper.js';
import { JniHookItems, JniHookItemsObject } from '../hooks.js';
import { JNI } from '../jni.js';
import { Color, logger } from '@clockwork/logging';
import { addressOf } from '@clockwork/native';
import Java from 'frida-java-bridge';
const { dim } = Color.use();

function getStringHooks(envWrapper: EnvWrapper): JniHookItems {
  const hooks: JniHookItemsObject = {
    GetStringUTFChars: function ({ args: [jniEnv, string, _], retval }) {
      if (isNullyVararg(jniEnv, string, retval)) return;
      const len = asFunction(jniEnv, JNI.GetStringUTFLength)(jniEnv, string);
      const msg = `${Color.string(retval.readCString(len))}`;
      logger.info(`[${dim(JNI.GetStringUTFChars.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
    GetStringChars: function ({ args: [jniEnv, string, _], retval }) {
      if (isNullyVararg(jniEnv, string, retval)) return;
      const uchars = asFunction(jniEnv, JNI.GetStringUTFChars)(jniEnv, string, ptr(0x0));
      const msg = `${Color.string(uchars.readCString())}`;
      logger.info(`[${dim(JNI.GetStringChars.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
    NewStringUTF: function ({ args: [jniEnv, string], retval }) {
      if (isNullyVararg(jniEnv, string)) return;
      const strText = `${string.readCString()}`;
      if (filterNewString(strText)) return;
      const msg = `${Color.string(strText)}`;
      logger.info(`[${dim(JNI.NewStringUTF.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
    NewString: function ({ args: [jniEnv, string], retval }) {
      if (isNullyVararg(jniEnv, string, retval)) return;
      const msg = `${Color.string(Java.cast(retval, Classes.String))}`;
      logger.info(`[${dim(JNI.NewString.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
    GetStringUTFLength: function ({ args: [jniEnv, string], retval }) {
      if (isNullyVararg(jniEnv, string)) return;
      const chars = asFunction(jniEnv, JNI.GetStringUTFChars)(jniEnv, string, ptr(0x0));
      const len = Number(retval);
      const msg = `${Color.string(chars.readCString(len))} | ${Color.number(len)}`;
      logger.info(`[${dim(JNI.GetStringUTFLength.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
    GetStringLength: function ({ args: [jniEnv, string], retval }) {
      if (isNullyVararg(jniEnv, string)) return;
      const chars = asFunction(jniEnv, JNI.GetStringUTFChars)(jniEnv, string, ptr(0x0));
      const len = Number(retval);
      const msg = `${Color.string(chars.readCString(len))} | ${Color.number(len)}`;
      logger.info(`[${dim(JNI.GetStringLength.name)}] ${msg} ${addressOf(this.returnAddress)}`);
    },
  };
  return Object.entries(hooks) as JniHookItems;
}

function filterNewString(strText: string) {
  const filters = ['com/cocos/lib/CocosHelper', 'com/cocos/lib/CanvasRenderingContext2DImpl'];
  if (filters.includes(strText)) return true;
  return false;
}
export { getStringHooks };
