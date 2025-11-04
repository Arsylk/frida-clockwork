import { generic, hookDevice, InstallReferrer } from '@clockwork/anticloak';
import { mock } from '@clockwork/anticloak/dist/country';
import { ProcMaps } from '@clockwork/cmodules';
import { Consts, enumerateMembers, getFindUnique, hookException, Std } from '@clockwork/common';
import { dumpLib, hookArtDexFile } from '@clockwork/dump';
import { always, ClassLoader, getHookUnique, hook, ifKey } from '@clockwork/hooks';
import { attach, barebone, EnvWrapper, envWrapper, JNI } from '@clockwork/jnitrace';
import { Color, logger } from '@clockwork/logging';
import { addressOf, log, replace } from '@clockwork/native';
import Java from 'frida-java-bridge';
import * as Unity from '@clockwork/unity';
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
attach((x) => ProcMaps.inRange(x.returnAddress), true);
Process.attachModuleObserver({
  onAdded(module) {
    if (!module.path.includes(Reflect.get(globalThis, 'packageName')) || !module.name.endsWith('.so')) return;
    if (['libunity.so', 'libmmkv.so', 'libdE9CCDAF38955.so', 'libsigner.so'].includes(module.name)) return;
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

InstallReferrer.replace();
generic();
hookDevice();
mock('VN');
ClassLoader.perform(() => {});
// hookArtDexFile();
Unity.setVersion('6000.0.31f1');
Unity.unitypatchSsl();
Unity.attachStrings();
Java.performNow(() => {
  for (const cls of [Classes.SharedPreferencesImpl, Classes.Bundle]) {
    for (const str of ['getInt', 'getString', 'getBoolean']) {
      hook(cls, str, {
        replace: ifKey(function (arg) {
          switch (arg) {
            case 'cvqdzww':
            case 'jlifzly':
              return `{"pjkzu": ["nya"]}`;
          }
        }),
        logging: { multiline: false, short: true },
      });
    }
  }
  hook(Classes.WebView, 'loadUrl');
});
