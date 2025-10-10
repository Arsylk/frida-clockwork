import { ClassLoader, hook } from '@clockwork/hooks';
import { dump, replace } from './dump.js';

type CocosLocalStorageScope = {
  fallback(): string | null;
};

function hookLocalStorage(fn?: (this: CocosLocalStorageScope, key: string) => string | undefined | void) {
  let Cocos2dxLocalStorage: any | undefined;
  ClassLoader.perform(() => {
    if (
      !Cocos2dxLocalStorage &&
      (Cocos2dxLocalStorage = findClass('org.cocos2dx.lib.Cocos2dxLocalStorage'))
    ) {
      hook(Cocos2dxLocalStorage, 'getItem', {
        replace: fn
          ? function (method, ...args) {
              const fallback: () => string | null = () => method.call(this, ...args);
              const result = fn.call({ fallback: fallback }, args[0]);
              return result !== undefined ? result : method.call(this, ...args);
            }
          : undefined,
        logging: { multiline: false },
      });
    }
  });
}

export { hookLocalStorage, dump, replace };
