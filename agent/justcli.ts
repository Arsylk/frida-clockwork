import * as Native from '@clockwork/native';
import * as Unity from '@clockwork/unity';
import * as Anticloak from '@clockwork/anticloak';
import * as Cocos2dx from '@clockwork/cocos2dx';
import {
  ClassesString,
  Linker,
  Text,
  emitter,
  enumerateMembers,
  findChoose,
  getFindUnique,
  hookException,
  stacktrace,
  tryNull,
  vs,
} from '@clockwork/common';
import { dumpLib, hookArtDexFile, hookArtLoader, initDexDump, initSoDump } from '@clockwork/dump';
import {
  ClassLoader,
  Filter,
  always,
  compat,
  getHookUnique,
  hook,
  ifKey,
  getHookLogger,
} from '@clockwork/hooks';
import * as JniTrace from '@clockwork/jnitrace';
import { logger } from '@clockwork/logging';
import { Inject, Logcat, Strings, System, addressOf, getSelfFiles, readFdPath } from '@clockwork/native';
import * as Network from '@clockwork/network';
import Java from 'frida-java-bridge';
import { ElfHeader, memcmp, memmove, ProcMaps } from '@clockwork/cmodules';
const uniqHook = getHookUnique(false);
const uniqFind = getFindUnique(false);
const uniqEnum = (clazzName: string, depth?: number) => {
  uniqFind(clazzName, (clazz) => {
    hook(clazz, '$init', { loggingPredicate: (method) => method.argumentTypes.length > 0 });
    enumerateMembers(
      clazz,
      {
        onMatchMethod(clazz, member, depth) {
          hook(clazz, member);
        },
      },
      depth,
    );
  });
};

Object.defineProperties(globalThis, {
  Fn: {
    value: { get: () => Fn },
  },
  Vn: {
    value: { get: () => Vn },
  },
  log: {
    value: { get: () => Native.log },
  },
});

const Vn = {
  isJniEnabled: true,
};

const AD_ID = 'fwqna41l-mrux-l4pi-mi6q-imrr3t83da4n';
const INSTALL_REFERRER = `utm_source=facebook_ads&utm_medium=Non-organic&media_source=true_network&http_referrer=BingSearch&utm_campaign=Non-organic&campaign=Non-organic&af_ad=${AD_ID}`;
Java.performNow(() => {
  hook(Classes.Class, 'getDeclaredFields', { logging: { call: false, return: false } });
  hook(Classes.Class, 'getDeclaredMethods', { logging: { call: false, return: false } });
});
JniTrace.attach((x) => ProcMaps.inRange(x.returnAddress), true);
// JniTrace.barebone(
//   (x) => ProcMaps.inRange(x.returnAddress),
//   () => {},
// );
Network.injectSsl();
Network.injectNative();

// hookArtDexFile();

Native.attachSystemPropertyGet(ProcMaps.inRange as any, (key) => {
  const value = Anticloak.BuildProp.propMapper(key);
  return value;
});
Logcat.hookLogcat();
Java.performNow(() => {
  Anticloak.generic();
  Anticloak.hookDevice();
  Anticloak.hookSettings();
  Anticloak.hookNetwork();
  Anticloak.hookAdId(AD_ID);
  Anticloak.hookPackageManager();
  Anticloak.Country.mock('VN');
  Anticloak.InstallReferrer.replace({
    install_referrer: INSTALL_REFERRER,
  });
  hook(Classes.DexPathList, '$init', {
    logging: { short: true, multiline: false },
  });
  hook(Classes.SystemProperties, 'get', {
    loggingPredicate: Filter.systemproperties,
    logging: { multiline: false, short: true },
    replace: ifKey((key) => {
      const value = Anticloak.BuildProp.propMapper(key);
      return value;
    }),
  });
  hook(Classes.System, 'getProperty', {
    loggingPredicate: Filter.systemprop,
    logging: { multiline: false, short: true },
    replace(method, ...args) {
      const fallback = () => method.call(this, ...args);
      const value = Anticloak.BuildProp.systemMapper(args[0], fallback);
      return value ?? fallback();
    },
  });
});

Java.performNow(() => {
  hook(Classes.DexPathList, '$init', {
    logging: { short: true, multiline: false },
  });
  for (const cls of [Classes.SharedPreferencesImpl, Classes.Bundle]) {
    for (const str of ['getInt', 'getString', 'getBoolean']) {
      hook(cls, str, {
        replace: ifKey(function (arg) {
          if (arg === 'status') return 0;
          if (arg === 'plugged') return 0;
          if (arg === 'userType') return 1;
          if (arg === 'is_logged_in' || arg === 'ipboolean') return true;
        }),
        logging: { multiline: false, short: true },
      });
    }
  }
  hook(Classes.WebView, 'loadUrl');
});
ClassLoader.perform(() => {
  uniqHook(ClassesString.Fragment, '$init', {
    logging: { call: false, return: false },
    after(method, returnValue, ...args) {
      logger.info({ tag: 'fragment' }, `$init: ${this.$className}`);
    },
  });
});
Network.attachGetAddrInfo();

// Cocos2dx.dump({ name: 'libcocos2djs.so', fn_dump: ptr(0x007b99ac), fn_key: ptr(0x006aa670) });
//     logger.info({ tag: 'localcocos' }, `${kccxxxxxxxxxxxxxxxxey} -> ${this.fallback()}`);
//     return undefined;
// });
// Unity.patchSsl();
// Unity.attachScenes();
// Unity.attachStrings();

Native.log(Libc.mprotect, 'pii', {
  nolog: true,
  predicate: ProcMaps.inRange,
  call(args) {
    this.base = args[0];
    this.size = args[1].toInt32();
  },
  ret(retval) {
    const range = { base: this.base, size: this.size };
    ProcMaps.addRange(range);
  },
});

System.hookSystem();
const libart = Process.getModuleByName('libart.so');
Process.attachModuleObserver({
  onAdded(module) {
    const { base, size, path, name } = module;
    if (name === 'base.odex') {
      Linker.patchSoList((name) => name.includes('memfd') || name.includes('libart.so'));
      logger.info({ tag: 'phdr_add' }, `${Text.stringify({ name: name, base: base, size: size })}`);
      ProcMaps.addRange(module);
      return;
    }
    if (!path.includes(Reflect.get(globalThis, 'packageName'))) return;
    for (const skipname in ['libsentry.so', 'libsentry-android.so']) if (name === skipname) return;
    if (name === 'libd79E1FB729E42.so') return;
    if (name === 'libd8BC92D2D4920.so') return;
    if (name === 'libd882B40CF4232.so') return;
    if (name === 'libqppdsw.so') return;
    if (name === 'libsigner.so') return;
    if (name === 'libimmortal.so') return;
    if (name === 'libnms.so') return;
    if (name === 'libunity.so') return;
    if (name === 'libmmkv.so') return;
    if (name === 'libapminsighta.so') return;
    if (name === 'libswappywrapper.so') return;
    if (name === 'libc++_shared.so') return;
    if (name === 'l7e2f4a6e.so') return;
    logger.info({ tag: 'phdr_add' }, `${Text.stringify({ name: name, base: base, size: size })}`);
    ProcMaps.addRange(module);
  },
});
Native.Files.hookRemove(() => true);

emitter.on('dexart', () => hookArtLoader());
emitter.on('dexdump', () => initDexDump());
emitter.on('sodump', () => initSoDump());
emitter.on('module', (libname: string) => dumpLib(libname));
emitter.on('savetext', (content: string, name: string) =>
  //@ts-ignore
  File.writeAllText(content, `${getSelfFiles()}/${name}`),
);
emitter.on('savebin', (content: unknown, name: string) =>
  //@ts-ignore
  File.writeAllBytes(content, `${getSelfFiles()}/${name}`),
);

const Fn = {
  hook: hook,
  hookArtLoader: () => emitter.emit('dexart'),
  initDexDump: () => emitter.emit('dexdump'),
  initSoDump: () => emitter.emit('sodump'),
  dumpLib: (libname: string) => emitter.emit('module', libname),
  save: (content: string, name: string) => {
    if (typeof content === 'string') {
      emitter.emit('savetext', content, name);
    } else {
      emitter.emit('saveany', content, name);
    }
  },
};

// hookArtDexFile(libart);
