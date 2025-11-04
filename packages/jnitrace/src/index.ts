import Java from 'frida-java-bridge';
import { Color, logger as gLogger, subLogger } from '@clockwork/logging';
import { addressOf, previousReturn } from '@clockwork/native';
import { ElfHeader, ProcMaps } from '@clockwork/cmodules';
import { EnvWrapper, type JniDefinition, asFunction, asLocalRef, getObjectClassName } from './envWrapper.js';
import { JNI } from './jni.js';
import { getMethodIdHooks } from './hooks/methodIds.js';
import { attachHooks, JniHookItems } from './hooks.js';
import { getFieldIdHooks } from './hooks/fieldIds.js';
import { getArrayObjectHooks } from './hooks/arrayObjects.js';
import { getCallObjectHooks } from './hooks/callObjects.js';
import { getStringHooks } from './hooks/strings.js';
import { getOtherHooks } from './hooks/generic.js';
const logger = subLogger('jnitrace');
const { black, gray, dim, redBright, magenta, orange, lavender } = Color.use();

let envWrapper: EnvWrapper;

function hookLibart(predicate: (thisRef: InvocationContext | CallbackContext) => boolean, full: boolean) {
  envWrapper ??= new EnvWrapper(Java.vm.getEnv());
  const items: JniHookItems = [];
  items.push(...getMethodIdHooks(envWrapper));
  items.push(...getFieldIdHooks(envWrapper));
  if (full) {
    items.push(...getCallObjectHooks(envWrapper));
    items.push(...getArrayObjectHooks(envWrapper));
    items.push(...getStringHooks(envWrapper));
    items.push(...getOtherHooks(envWrapper));
  }
  attachHooks(items, predicate);
}

function barebone(
  predicate: (thisRef: InvocationContext | CallbackContext) => boolean,
  fn: (clazz: string, method: string) => void = () => {},
) {
  envWrapper ??= new EnvWrapper(Java.vm.getEnv());
  const items: JniHookItems = [];
  items.push(...getMethodIdHooks(envWrapper));
  items.push(...getOtherHooks(envWrapper));
  attachHooks(items, predicate, ['RegisterNatives', 'NewGlobalRef']);
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
