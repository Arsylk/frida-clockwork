import { BuildProp, Country, generic, hookSettings, InstallReferrer } from '@clockwork/anticloak';
import { SoInfo } from '@clockwork/common/dist/define/linker';

import { ElfHeader, LinkerSym, memcmp, memmove, ProcMaps, strlen } from '@clockwork/cmodules';
import { ClassesString, Consts, enumerateMembers, getFindUnique, Text, tryNull } from '@clockwork/common';
import { dumpLib, hookArtDexFile, initSoDump } from '@clockwork/dump';
import { always, ClassLoader, Filter, getHookUnique, hook, ifKey } from '@clockwork/hooks';
import { attach, barebone } from '@clockwork/jnitrace';
import * as Unity from '@clockwork/unity';
import { log, Logcat } from '@clockwork/native';
import { attachGetAddrInfo, attachNativeSocket, injectSsl } from '@clockwork/network';
import Java from 'frida-java-bridge';
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

const libc = Process.getModuleByName('libc.so');
Logcat.hookLogcat(function (msgx) {});
ClassLoader.perform(injectSsl);
attach((x) => ProcMaps.inRange(x.returnAddress), true);
Process.attachModuleObserver({
  onAdded(module) {
    if (!module.path.includes(Reflect.get(globalThis, 'packageName')) || !module.name.endsWith('.so')) return;
    if (module.name === 'libsigner.so') return;
    if (module.name === 'libil2cpp.so') return;
    if (module.name === 'libunity.so') return;
    if (module.name === 'libmain.so') return;
    if (module.name === 'libd882B40CF4232.so') return;
    ProcMaps.addRange(module);
  },
});
log(Libc.mprotect, 'pi2', {
  predicate: ProcMaps.inRange,
  transform: { 2: Consts.prot },
  call(args) {
    this.base = args[0];
    this.size = args[1].toInt32();
  },
  ret(retval) {
    const range = { base: this.base, size: this.size };
    ProcMaps.addRange(range);
  },
});

log(LinkerSym.__dl__ZN6soinfo17call_constructorsEv, 'p', {
  tag: 'call_constructors',
  transform: {
    0: (ptr) => tryNull(() => new SoInfo(ptr).getRealpath()) ?? `${ptr}`,
    NaN: function (ptr) {
      return (
        tryNull(() =>
          Text.stringify(JSON.parse(JSON.stringify(Process.getModuleByAddress(this.soinfo.getBase())))),
        ) ?? `${ptr}`
      );
    },
  },
  call(args) {
    this.soinfo = new SoInfo(args[0]);
  },
});
log(Libc.strdup, 's', { predicate: ProcMaps.inRange });
log(Libc.memchr, 'pci', { predicate: ProcMaps.inRange });
log(Libc.strstr, 'ss', { predicate: ProcMaps.inRange });
log(Libc.strcmp, 'ss', { predicate: ProcMaps.inRange });
memmove.verbose.writeByteArray([0x1]);
Interceptor.attach(Libc.memmove, memmove);
Interceptor.attach(Libc.memcmp, memcmp);
Interceptor.attach(Libc.strlen, strlen);
Java.performNow(() => {
  generic();
  hook(Classes.Locale, 'getDefault', {
    loggingPredicate: always(false),
    replace(method) {
      return Classes.Locale.$new('vn', 'VN');
    },
  });
  hook(Classes.TimeZone, 'getDefault', {
    loggingPredicate: always(false),
    replace(method) {
      // return Classes.TimeZone.getDefault();
      return Classes.TimeZone.getTimeZone('Asia/Saigon');
    },
  });
  hook(Classes.WebView, 'loadUrl');
  hook(Classes.SharedPreferencesImpl, 'getBoolean', {
    replace: ifKey((key) => {
      if (key === 'campaign') return 'Non-organic';
    }),
  });
  hookSettings();
});

Unity.setVersion('6000.1.13f1');
Unity.patchSsl();
Unity.attachScenes();
Unity.attachStrings();

attachGetAddrInfo(true);
attachNativeSocket();
InstallReferrer.replace();

Process.attachModuleObserver({
  onAdded(module) {
    if (module.name === 'libil2cpp.so') {
    }
  },
});

ClassLoader.perform(() => {});
