import { filterMulti, isNully, Text } from '@clockwork/common';
import { asExceptionSafe, EnvWrapper, getClassName } from '../envWrapper.js';
import { JniHookItem, JniHookItems, JniHookItemsObject } from '../hooks.js';
import { Color, logger } from '@clockwork/logging';
import { addressOf } from '@clockwork/native';
import { parseJniSignature, resolveMethod } from '../tracer.js';
import { JavaMethod } from '../model.js';
const { dim, redBright } = Color.use();

function getMethodIdHooks(envWrapper: EnvWrapper): JniHookItems {
  const hook = (isStatic: boolean) =>
    function ({ args: [jniEnv, clazz, name, sig], retval }) {
      if (isNully(jniEnv) || isNully(clazz) || isNully(name) || isNully(sig)) return;
      const method = resolveMethod(jniEnv, clazz, retval, isStatic);

      let msg = '';
      if (method) {
        if (filterMethodId.call(this, method.name, method.className)) return;
        msg = formatGetMethodId(retval, method);
      } else {
        const methodName = `${name.readCString()}`;
        const clazzName = asExceptionSafe(jniEnv, () => getClassName(jniEnv, clazz));
        if (filterMethodId.call(this, methodName, clazzName)) return;
        const sigText = `${sig.readCString()}`;
        msg = formatFallbackGetMethodId(retval, methodName, clazzName, sigText, isStatic);
      }

      logger.info(
        `[${dim(`Get${isStatic ? 'Static' : ''}MethodID`)}] ${msg} ${addressOf(this.returnAddress)}`,
      );
    };
  const hooks: JniHookItemsObject = {
    GetMethodID: hook(false),
    GetStaticMethodID: hook(true),
  };
  return Object.entries(hooks)
    .filter(([_, v]) => v)
    .map(([k, v]) => [k, v] as JniHookItem<any>);
}

function filterMethodId(this: InvocationContext, methodName: string, clazzName: string): boolean {
  const filters: [any, any][] = [
    [
      [
        'com.cocos.lib.CocosHelper',
        'org.cocos3dx.lib.CanvasRenderingContext2DImpl',
        'com.cocos.lib.CanvasRenderingContext3DImpl',
        'com.cocos.lib.CanvasRenderingContext2DImpl',
      ],
      [],
    ],
  ];
  return filterMulti(filters, clazzName, methodName);
}

function formatGetMethodId(retval: NativePointer, method: JavaMethod): string {
  let sb = '';

  sb += redBright(`${retval} -${dim('>')}`);
  if (method.isStatic) {
    sb += `${Color.keyword('static')} `;
  }
  if (method.isConstructor) {
    sb += Color.keyword('new');
    sb += ' ';
    sb += Color.className(method.className);
  } else {
    sb += Color.className(method.className);
    sb += '::';
    sb += Color.method(method.name);
  }
  sb += Color.bracket('(');
  sb += method.jParameterTypes.map(Color.className).join(', ');
  sb += Color.bracket(')');
  if (!method.isConstructor) {
    sb += `: ${Color.className(method.jReturnType)}`;
  }

  return sb;
}

function formatFallbackGetMethodId(
  retval: NativePointer,
  methodName: string,
  clazzName: string,
  sigText: string,
  isStatic: boolean,
): string {
  const types = parseJniSignature(sigText);

  let sb = '';

  sb += redBright(`${isNully(retval) ? '0x????????' : retval} -${dim('>')}`);
  if (isStatic) {
    sb += `${Color.keyword('static')} `;
  }
  sb += `${Color.className(clazzName)}::${Color.method(methodName)}`;
  sb += `${Color.bracket('(')}`;
  if (types) {
    sb += `${types.args.map(Color.className).join(', ')}`;
  } else {
    sb += sigText;
  }
  sb += `${Color.bracket(')')}`;
  if (types && types.ret !== 'void') {
    sb += `: ${Color.className(types.ret)}`;
  }

  return sb;
}

export { getMethodIdHooks };
