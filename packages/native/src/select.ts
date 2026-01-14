import { ProcMaps } from '@clockwork/cmodules';
import { Consts, isIterable, Text } from '@clockwork/common';
import { logger } from '@clockwork/logging';
import { log } from './index.js';

type fnOrNames = string[] | ((module: Module) => boolean);
function select(ignore: fnOrNames = [], logging: boolean = true) {
  const fn = isIterable(ignore)
    ? ({ name }: Module) => (ignore as string[]).includes(name)
    : (ignore as (module: Module) => boolean);

  Process.attachModuleObserver({
    onAdded(module) {
      const { base, name, size, path } = module;
      if (!path.includes(Reflect.get(globalThis, 'packageName'))) return;
      if (fn(module)) return;

      logging &&
        logger.info(
          { tag: 'phdr_add' },
          `${Text.stringify({ name: name, base: base, size: size, path: path })}`,
        );
      ProcMaps.addRange(module);
    },
  });

  log(Libc.mprotect, 'pi2', {
    predicate: ProcMaps.inRange,
    nolog: logging,
    transform: { 2: Consts.prot },
    call(args) {
      this.base = args[0];
      this.size = args[1].toInt32();
      this.prot = args[2].toInt32();
    },
    ret(retval) {
      const range = { base: this.base, size: this.size };
      if (this.prot & 4) ProcMaps.addRange(range);
    },
  });
}

export { select };
