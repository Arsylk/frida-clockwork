import { ClassLoader } from './classloader.js';
import { findHook, getHookUnique, hook } from './hook.js';
export * from './addons.js';
export * from './filter.js';
export type * from './types.js';
export { getLogger as getHookLogger } from './logger.js';

Object.defineProperties(globalThis, {
  hook: {
    value: hook,
  },
});

export { ClassLoader, findHook, getHookUnique, hook };
