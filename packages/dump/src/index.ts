import { getSelfFiles } from '@clockwork/native';
import { dumpLib } from './soDump.js';

export * from './dexDump.js';
export * from './soDump.js';
export * from './inMemoryDexDump.js';
export * from './byteBuffer.js';

function dumpExports(libname: string) {
  const module = Process.findModuleByName(libname);
  if (module) {
    const exports = module.enumerateExports();
    const text = JSON.stringify(exports, null, 2);

    //@ts-ignore
    File.writeAllText(`${getSelfFiles()}/${libname}_exports.json`, text);
  }
}

Object.defineProperties(globalThis, {
  dumpLib: {
    value: dumpLib,
    writable: false,
  },
});

export { dumpExports };
