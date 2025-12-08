import Java from 'frida-java-bridge';
import { EnvWrapper, type JniDefinition } from './envWrapper.js';
import { JNI } from './jni.js';

type JniType = typeof JNI;
type JniKey = keyof JniType;
type JniArgumentType<T extends JniKey> = GetNativeCallbackArgumentValue<JniType[T]['argTypes']>;
type JniInvocationContext<T extends JniKey> = {
  args: JniArgumentType<T>;
  retval: InvocationReturnValue;
};
type JniSimpleHook<T extends JniKey> = (this: InvocationContext, ctx: JniInvocationContext<T>) => void;

type JniExtendedHook<T extends JniKey> = {
  onEnter(this: InvocationContext, args: JniArgumentType<T>): void;
  onLeave(this: InvocationContext & { args: JniArgumentType<T> }, retval: InvocationReturnValue): void;
};
type JniHook<T extends JniKey> = JniSimpleHook<T> | JniExtendedHook<T>;

type JniHookItem<T extends JniKey> = [T, JniHook<T>];
type JniHookItems = JniHookItem<JniKey>[];
type JniHookItemsObject = Partial<{ [key in JniKey]: JniHook<key> }>;

let envWrapper: EnvWrapper | null = null;
function attachHooks(
  items: JniHookItems,
  predicate: (context: InvocationContext) => boolean,
  exclude: JniKey[] = [],
) {
  envWrapper ??= new EnvWrapper(Java.vm.getEnv());
  for (let i = 0; i < items.length; i += 1) {
    const item = items[i];
    if (!item) continue;
    const [key, val] = item;
    if (exclude.includes(key)) continue;
    const def = JNI[key];
    const fn = envWrapper.getFunction<any, any>(def);
    Interceptor.attach(fn, {
      onEnter(args) {
        if ((this.enabled = predicate(this))) {
          const argarr = Array(def.argTypes.length);
          for (let a = 0; a < def.argTypes.length; a += 1) {
            argarr[a] = args[a];
          }
          this.args = argarr;
          (val as any)?.onEnter?.call(this, argarr);
        }
      },
      onLeave(retval) {
        if (this.enabled) {
          if (typeof val === 'function') {
            (val as any).call(this, { args: this.args, retval: retval });
          } else {
            (val as any)?.onLeave?.call(this, retval);
          }
        }
      },
    });
  }
}

export {
  type JniExtendedHook,
  type JniHook,
  type JniHookItem,
  type JniHookItems,
  type JniHookItemsObject,
  type JniArgumentType,
  attachHooks,
};
