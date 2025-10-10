import { BuildProp, Country, generic, InstallReferrer } from '@clockwork/anticloak';
import { SoInfo } from '@clockwork/common/dist/define/linker';

import { ElfHeader, LinkerSym, memcmp, memmove, ProcMaps } from '@clockwork/cmodules';
import { ClassesString, Consts, Text, tryNull } from '@clockwork/common';
import { dumpLib, hookArtDexFile, initSoDump } from '@clockwork/dump';
import { always, ClassLoader, Filter, getHookUnique, hook, ifKey } from '@clockwork/hooks';
import { attach, barebone } from '@clockwork/jnitrace';
import { logger } from '@clockwork/logging';
import { log, Logcat } from '@clockwork/native';
import { attachGetAddrInfo, injectNative, injectSsl, useTrustManager } from '@clockwork/network';
import Java from 'frida-java-bridge';
import * as Unity from '@clockwork/unity';
import { mock } from '@clockwork/anticloak/dist/country';
dumpLib;

const libc = Process.getModuleByName('libc.so');
Logcat.hookLogcat(function (msgx) {
  if (msgx.includes('UnityTls')) {
    ProcMaps.printStacktrace();
  }
});
injectSsl();
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
  ret(retval) {
    if (this.soinfo.getName().includes('jiagu')) {
    }
  },
});
// Process.attachModuleObserver({
//   onAdded(module) {
//     const { name, base, size } = module;
//     if (name === 'libjiagu.so') {
//       log(getEnumerated(module, 'JNI_OnLoad'), 'pp', {
//         call(args) {
//           Interceptor.detachAll();
//           Stalker.stalk(this.threadId, base);
//           Interceptor.replace(
//             libc.getExportByName('tgkill'),
//             new NativeCallback(
//               function (code) {
//                 console.log('tgkill', code);
//                 console.log(
//                   Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n\t'),
//                 );
//               },
//               'void',
//               ['int'],
//             ),
//           );
//         },
//       });
//     }
//   },
// });
log(Libc.strdup, 's', { predicate: ProcMaps.inRange });
Interceptor.attach(Libc.memmove, memmove);
Interceptor.attach(Libc.memcmp, memcmp);
Java.performNow(() => {
  generic();
  hook(Classes.Locale, 'getDefault', {
    loggingPredicate: always(false),
    replace(method) {
      return Classes.Locale.$new('vi', 'VN');
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
  hook(Classes.SharedPreferencesImpl, 'getInt', {
    replace: ifKey((key) => {
      if (key === 'H4rX7pR5_3') return 1;
    }),
  });
});
hookArtDexFile();
