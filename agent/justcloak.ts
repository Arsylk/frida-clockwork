import { BuildProp, generic, hookDevice, InstallReferrer } from '@clockwork/anticloak';
import { mock } from '@clockwork/anticloak/dist/country';
import { memcmp, memmove, ProcMaps, strlen } from '@clockwork/cmodules';
import * as Cocos2dx from '@clockwork/cocos2dx';
import {
  Consts,
  emitter,
  enumerateMembers,
  getApplicationContext,
  getFindUnique,
  hookException,
  Linker,
  Std,
} from '@clockwork/common';
import { dumpLib, hookArtDexFile, hookArtLoader } from '@clockwork/dump';
import { always, ClassLoader, Filter, getHookUnique, hook, ifKey } from '@clockwork/hooks';
import { attach, barebone, EnvWrapper, envWrapper, JNI } from '@clockwork/jnitrace';
import { Color, logger } from '@clockwork/logging';
import {
  addressOf,
  attachSystemPropertyGet,
  getEnumerated,
  getSelfProcessName,
  log,
  readFdPath,
  replace,
  Stalker as StalkerKt,
} from '@clockwork/native';
import Java from 'frida-java-bridge';
import * as Unity from '@clockwork/unity';
import { hookOpen, hookRemove } from '@clockwork/native/dist/files';
const { red, green, redBright, magentaBright: pink, gray, dim, black } = Color.use();

dumpLib;
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

// let enabled = true;
// barebone((x) => ProcMaps.inRange(x.returnAddress));
// attach((x) => ProcMaps.inRange(x.returnAddress), true);
Process.attachModuleObserver({
  onAdded(module) {
    if (!module.path.includes(Reflect.get(globalThis, 'packageName')) || !module.name.endsWith('.so')) return;
    if (
      [
        'libcocos.so',
        'libcocos2djs.so',
        'libunity.so',
        // 'libil2cpp.so',
        'libmmkv.so',
        'libdE9CCDAF38955.so',
        'libsigner.so',
        'libamaplog.so',
        'libsharetripnavimain.so',
        'libd70666BD7B1F2.so',
      ].includes(module.name)
    )
      return;
    ProcMaps.addRange(module);
  },
});
Interceptor.replace(
  Libc.mprotect,
  new NativeCallback(
    function (a0, a1, a2) {
      if (ProcMaps.inRange(this.returnAddress) && a2 & 4) {
        const range = { base: a0, size: a1.toNumber() };
        ProcMaps.addRange(range);
      }
      return Libc.mprotect(a0, a1, a2).value;
    },
    'int',
    ['pointer', 'size_t', 'int'],
  ),
);

InstallReferrer.replace({
  install_referrer:
    'utm_source=facebook_ads&utm_medium=Non-organic&media_source=tiktok_s&utm_content=Non-organic&http_referrer=BingSearch&utm_campaign=Non-organic&campaign=Non-organic&af_ad=1111',
});
generic();
hookDevice();
mock('PK');
hookRemove(ProcMaps.inRange);
// // Unity.unitypatchSsl();
// Unity.setVersion('6000.2.7f2');
// Unity.attachStrings();
// Cocos2dx.dump({ name: 'libcocos.so', fn_dump: ptr(0x00ba1898), fn_key: ptr(0x00b8044c) });
// Interceptor.attach(Libc.memcmp, memcmp);
// Interceptor.attach(Libc.strlen, strlen);
// memmove.verbose.writeU8(1);
// Interceptor.attach(Libc.memmove, memmove);
// log(Libc.strcmp, 'ss', {predicate: ProcMaps.inRange})
Java.performNow(() => {
  let one = true;

  hook(Classes.SharedPreferencesImpl, 'contains', {
    replace: ifKey(function (arg) {
      switch (arg) {
        case 'eu':
          return true;
      }
    }),
    logging: { multiline: false, short: true },
    loggingPredicate: (method, args) => {
      return Filter.prefs(method, args) && Filter.bundle(method, args);
    },
  });
  for (const cls of [Classes.SharedPreferencesImpl, Classes.Bundle]) {
    for (const str of ['getInt', 'getString', 'getBoolean']) {
      hook(cls, str, {
        replace: ifKey(function (arg) {
          switch (arg) {
            case 'ipboolean':
            case 'is_logged_in':
              return true;
            case 'plugged':
              return 0;
            case 'jkfdfd':
              return true;
            case 'eu':
              if (one) {
                one = false;
              }
              return '{"keynya": "valnya0", "KwbkaPqoibpl": ""}';
          }
        }),
        logging: { multiline: false, short: true },
        loggingPredicate: (method, args) => {
          return Filter.prefs(method, args) && Filter.bundle(method, args);
        },
      });
    }
  }
  hook(Classes.WebView, 'loadUrl');
  Classes.File.delete.implementation = () => true;
});

ClassLoader.perform(() => {
  uniqHook('com.sequence.speed.jthidgirfdhh.ActivityHelper', 'check_app_status', { replace: () => false });
});
Process.attachModuleObserver({
  onAdded(module) {
    const { name, base, size, path } = module;
    if (name === 'base.odex') {
      Linker.patchSoList((name) => name.includes('memfd'));
      // syscallme();
    }
  },
});
