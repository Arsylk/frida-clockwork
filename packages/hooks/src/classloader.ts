import Java from 'frida-java-bridge';
import { Classes } from '@clockwork/common';
import { hook } from './hook.js';

type Listener = (classLoader: Java.Wrapper | null) => void;

namespace ClassLoader {
  export let autorun = true;

  const listeners: Listener[] = [];
  export function perform(fn: Listener) {
    listeners.push(fn);
  }

  function notify(classLoader: Java.Wrapper | null) {
    for (const listener of listeners) listener(classLoader);
  }

  function onNewClassLoader(this: Java.Wrapper) {
    notify(this);
  }

  function invoke() {
    hook(Classes.ClassLoader, '$init', {
      after: onNewClassLoader,
      logging: { arguments: false, call: false },
    });
    // hook(Classes.BaseDexClassLoader, '$init', {
    //     after: onNewClassLoader,
    //     logging: { arguments: false },
    // });
    // hook(Classes.DexClassLoader, '$init', {
    //     after: onNewClassLoader,
    //     logging: { arguments: false },
    // });
    // hook(Classes.InMemoryDexClassLoader, '$init', {
    //     after: onNewClassLoader,
    //     logging: { arguments: false },
    // });
    // hook(Classes.PathClassLoader, '$init', {
    //     after: onNewClassLoader,
    //     logging: { arguments: false },
    // });

    hook(Classes.Application, 'onCreate', {
      before() {
        const loader = this.getClassLoader() ?? null;
        onNewClassLoader.call(loader);
      },
    });

    hook(Classes.Application, '$init', {
      before() {
        onNewClassLoader.call(null as any);
      },
    });

    notify(null);
  }

  autorun && setImmediate(() => Java.performNow(invoke));
}

export { ClassLoader };
