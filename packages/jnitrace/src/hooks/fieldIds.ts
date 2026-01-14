import { filterMulti, isNully, Text } from '@clockwork/common';
import { asExceptionSafe, EnvWrapper, getClassName } from '../envWrapper.js';
import { JniHookItem, JniHookItems, JniHookItemsObject } from '../hooks.js';
import { Color, logger } from '@clockwork/logging';
import { addressOf } from '@clockwork/native';
import { JNI } from '../jni.js';
const { dim, redBright } = Color.use();

function getFieldIdHooks(envWrapper: EnvWrapper): JniHookItems {
  const hook = (isStatic: boolean) =>
    function ({ args: [jniEnv, clazz, name, sig], retval }) {
      if (isNully(jniEnv) || isNully(clazz) || isNully(name) || isNully(sig)) return;
      const fieldName = `${name.readCString()}`;
      const clazzName = asExceptionSafe(jniEnv, () => getClassName(jniEnv, clazz));
      if (filterFieldId.call(this, fieldName, clazzName)) return;

      const sigName = `${sig?.readCString()}`;
      const msg = formatGetFieldId(retval, fieldName, clazzName, sigName, isStatic);
      const label = isStatic ? JNI.GetStaticFieldID.name : JNI.GetFieldID.name;
      logger.info(`[${dim(label)}] ${msg} ${addressOf(this.returnAddress)}`);
    };
  const hooks: JniHookItemsObject = {
    GetFieldID: hook(false),
    GetStaticFieldID: hook(true),
  };
  return Object.entries(hooks)
    .filter(([_, v]) => v)
    .map(([k, v]) => [k, v] as JniHookItem<any>);
}

function filterFieldId(this: InvocationContext, fieldName: string, clazzName: string): boolean {
  const filters: [any, any][] = [['io.flutter.embedding.engine.FlutterJNI', ['refreshRateFPS']]];
  return filterMulti(filters, clazzName, fieldName);
}

function formatGetFieldId(
  retval: NativePointer,
  fieldName: string,
  clazzName: string,
  sigName: string,
  isStatic: boolean,
): string {
  const typeName = Text.toPrettyType(sigName);

  const id = redBright(`${isNully(retval) ? '0x????????' : retval} -${dim('>')}`);
  const prefix = isStatic ? `${Color.keyword('static')} ` : '';
  return `${id}${prefix}${Color.className(clazzName)}${Color.bracket('.')}${Color.field(fieldName)}: ${Color.className(typeName)}`;
}

export { getFieldIdHooks };
