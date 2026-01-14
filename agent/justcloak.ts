import { BuildProp, generic, hookDevice, hookSettings, InstallReferrer } from '@clockwork/anticloak';
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
  isNully,
  Linker,
  Std,
  Struct,
  Text,
  tryNull,
} from '@clockwork/common';
import {
  dumpLib,
  hookArtDexFile,
  hookArtLoader,
  hookByteBufferDump,
  hookInMemoryDexDump,
} from '@clockwork/dump';
import { always, ClassLoader, Filter, getHookUnique, hook, ifKey } from '@clockwork/hooks';
import { attach, barebone, EnvWrapper, envWrapper, JNI } from '@clockwork/jnitrace';
import { Color, logger } from '@clockwork/logging';
import {
  addressOf,
  attachSystemPropertyGet,
  getEnumerated,
  getSelfFiles,
  getSelfProcessName,
  isInRange,
  log,
  readFdPath,
  replace,
  select,
  Stalker as StalkerKt,
} from '@clockwork/native';
import Java from 'frida-java-bridge';
import * as Unity from '@clockwork/unity';
import { hookDirent, hookOpendir, hookOpen, hookRemove } from '@clockwork/native/dist/files';
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

function hookOrganicResponse() {
  hook(Classes.HttpsURLConnectionImpl, 'getInputStream', {
    replace(method, ...args) {
      const returnValue = method.call(this, ...args);
      const url = this.getURL().toString();
      logger.info({ tag: 'url' }, Color.url(url));
      const UTF_8 = Classes.StandardCharsets.UTF_8.value;
      const text = Classes.String.$new(returnValue.readAllBytes(), UTF_8);
      const json: object | null = tryNull(() => JSON.parse(text));
      if (!json) return returnValue;
      logger.info({ tag: 'url', id: 'json' }, Text.stringify(json));
      if (!url.includes('/install_data')) return returnValue;
      const nowBase = Date.now();
      const dateOffset = (off: number) =>
        new Date(nowBase + off)
          .toISOString()
          .replace('T', ' ')
          .replace(/\.\d+Z$/, '');
      const applyJson = {
        af_status: 'Non-Organic',
        af_message: 'Install attributed',
        af_channel: 'Nya',
        media_source: 'facebook',
        campaign: 'a_b_c_d_e_f_R4bhbQgt_h_chickenhoops35',
        adgroup: 'nya',
        adset: 'nya',
        install_time: dateOffset(-15 * 60),
        click_time: dateOffset(-15),
      };
      return Classes.ByteArrayInputStream.$new(
        Classes.String.$new(JSON.stringify(Object.assign(json, applyJson))).getBytes(UTF_8),
      );
    },
  });
}

select([
  'libcocos.so',
  'libcocos2djs.so',
  // 'libunity.so',
  // 'libil2cpp.so',
  'libswappywrapper.so',
  'libmmkv.so',
  'libdE9CCDAF38955.so',
  'libsigner.so',
  'libamaplog.so',
  'libsharetripnavimain.so',
  'libd70666BD7B1F2.so',
  'libdFF894CEE81D1.so',
]);
// barebone((x) => ProcMaps.inRange(x.returnAddress));
attach((x) => ProcMaps.inRange(x.returnAddress), true);
InstallReferrer.replace({
  install_referrer:
    'utm_source=facebook_ads&utm_medium=Non-organic&media_source=tiktok_s&utm_content=Non-organic&http_referrer=BingSearch&utm_campaign=Non-organic&campaign=Non-organic&af_ad=1111',
});
generic();
hookDevice();
hookSettings();
mock('BR');
hookRemove(ProcMaps.inRange);
Unity.setVersion('6000.2.7f2');
Unity.unitypatchSsl();
Unity.attachStrings();
// Cocos2dx.dump({ name: 'libcocos2djs.so', fn_dump: ptr(0x00b8ec34), fn_key: ptr(0x01a87f50) });
// Interceptor.attach(Libc.strlen, strlen);
// Interceptor.attach(Libc.memcmp, memcmp);
// memmove.verbose.writeByteArray([0x1]);
// Interceptor.attach(Libc.memmove, memmove);
// log(Libc.strcmp, 'ss', { predicate: ProcMaps.inRange });
log(Libc.access, 'si', {
  predicate: ProcMaps.inRange,
});
// log(DebugSymbol.fromName('AAssetManager_open').address, 'psi');
// hookOpen(ProcMaps.inRange, () => null);
// hookDirent(ProcMaps.inRange);
// hookOpendir(ProcMaps.inRange);
Java.performNow(() => {
  hookOrganicResponse();
  hookByteBufferDump();

  hook(Classes.SharedPreferencesImpl, 'contains', {
    replace: ifKey(function (arg) {
      switch (arg) {
      }
    }),
    logging: { multiline: false, short: true },
    loggingPredicate: (method, args) => {
      return Filter.prefs(method, args) && Filter.bundle(method, args);
    },
  });
  for (const m of ['getBooleanExtra', 'getIntExtra']) {
    hook(Classes.Intent, m, {
      replace: ifKey(function (arg) {
        switch (arg) {
          case 'connected':
            return false;
          case 'plugged':
            return m === 'getIntExtra' ? 0 : false;
          case 'status':
            return 0;
        }
      }),
      logging: { multiline: false, short: true },
    });
  }
  for (const str of ['getInt', 'getString', 'getBoolean']) {
    hook(Classes.Bundle, str, {
      replace: ifKey(function (arg) {
        switch (arg) {
          case 'plugged':
            return str === 'getInt' ? 0 : false;
          case 'status':
            if (str === 'getInt') return 0;
          case 'ipboolean':
          case 'is_logged_in':
            return true;
        }
      }),
      logging: { multiline: false, short: true },
      loggingPredicate: Filter.bundle,
    });
  }

  for (const item of ['getBoolean', 'getFloat', 'getInt', 'getLong', 'getString', 'getStringSet']) {
    hook(Classes.SharedPreferencesImpl, item, {
      loggingPredicate: Filter.prefs,
      logging: { multiline: false, short: true },
      replace: ifKey(function (key) {
        switch (key) {
          case 'Atc4CUF':
            return 1;
          case 'zaF9m3kX':
            return 'https://googl.pl/search?q=hi';
          case 'jFtLhI2R':
            return 4;
        }
      }),
    });
  }
  hook(Classes.WebView, 'loadUrl');
});

let m: any = null;
ClassLoader.perform(() => {});
Process.attachModuleObserver({
  onAdded(module) {
    const { name, base, size, path } = module;
    if (name === 'base.odex') {
      Linker.patchSoList((name) => name.includes('memfd'));
      // syscallme();
    }
    if (name === 'libjiagu_64.so   ') {
      m = { name: name, base: base, size: size, path: path };

      Interceptor.attach(base.add(0x4f74), {
        onEnter: function (args) {
          const OFFSET_CTX_PHDR_CNT = 0x48; // Offset in ElfParserContext to ph_num (long)
          const OFFSET_CTX_PHDR_PTR = 0x50; // Offset in ElfParserContext to ph_table

          console.log('[+] Hooked FUN_00004f74 (Mapper)');

          // arg0 is the ElfParserContext pointer
          var ctx = args[0];

          // Read the pointer to the decrypted Program Header Table
          var phdrTablePtr = ctx.add(OFFSET_CTX_PHDR_PTR).readPointer();

          // Read the number of Program Headers
          // The decompilation shows: *(ulong *)(param_1 + 0x48) = uVar13 / 0x38;
          var phdrCount = ctx.add(OFFSET_CTX_PHDR_CNT).readU64().toNumber();

          console.log('    [-] Context Address: ' + ctx);
          console.log('    [-] Decrypted Phdr Table: ' + phdrTablePtr);
          console.log('    [-] Phdr Count: ' + phdrCount);

          if (phdrTablePtr && phdrCount > 0) {
            var phdrSize = 0x38; // sizeof(Elf64_Phdr)
            var totalSize = phdrCount * phdrSize;

            console.log('    [-] Dumping ' + totalSize + ' bytes of Phdrs...');

            // Read the memory containing the valid headers
            var phdrData = phdrTablePtr.readByteArray(totalSize);

            // You can now write this to a file or inspect it
            // For demonstration, hexdumping the first entry:
            console.log(
              hexdump(phdrTablePtr, {
                offset: 0,
                length: totalSize,
                header: true,
                ansi: true,
              }),
            );

            // Logic to save to file (requires host-side script handling or standard Frida file IO)
            var file = new File(`${getSelfFiles()}/restored.phdrs.bin`, 'wb');
            file.write(phdrData);
            file.flush();
            file.close();
            console.log('[+] Dump saved to', path);
          }
        },
      });
      Interceptor.attach(base.add(0x3bfc), {
        onEnter: function (args) {
          console.log('\n[+] Hooked FUN_00003bfc (Dynamic Parser)');

          //screenshot.googleplex.com/56BmsQua2j7eMkK         // args[0] is the ElfModuleObject*
          https: var moduleObj = args[0];

          // Offset 0x100 holds the pointer to the .dynamic section in memory
          // Decompilation: puVar14 = (ulong *)param_1[0x20]; (long* array index 0x20 == byte offset 0x100)
          var dynSectionPtr = moduleObj.add(0x100).readPointer();

          console.log('    [-] Module Object: ' + moduleObj);
          console.log('    [-] .dynamic Ptr:  ' + dynSectionPtr);

          if (dynSectionPtr) {
            console.log('\n    [=] Dumping .dynamic Section [Tag | Value]:');
            console.log('    -------------------------------------------');

            let offset = 0;
            while (true) {
              const entryAddr = dynSectionPtr.add(offset);

              // Read Elf64_Dyn: { int64_t d_tag; uint64_t d_val_ptr; }
              const tag = entryAddr.readPointer();
              const val = entryAddr.add(8).readU64().toNumber();

              const tagName = Consts.d_tag(Number(tag));
              console.log('    [+]', offset, tagName, ptr(val));

              // console.log(
              //   '    ' +
              //     ptr(offset).toString().padEnd(6) +
              //     ' : ' +
              //     tagName.padEnd(15) +
              //     '(' +
              //     tag.toString(16) +
              //     ') ' +
              //     ' -> ' +
              //     val.toString(16),
              // );
              //
              // // Stop at DT_NULL (0)
              if (isNully(tag)) {
                console.log('[.] DT_NULL found');
                break;
              }
              //
              // // Safety break for loop
              // if (offset > 0x1000) {
              //   console.log('    [!] Safety break reached.');
              //   break;
              // }

              offset += 16; // sizeof(Elf64_Dyn)
            }

            // Dump raw bytes to file
            const path = `${getSelfFiles()}/restored.dyns.bin`;
            var file = new File(path, 'wb');
            var rawBytes = dynSectionPtr.readByteArray(offset + 16);
            file.write(rawBytes);
            file.flush();
            file.close();
            console.log('[+] Dump saved to /data/local/tmp/restored.dyns.bin');
          }
        },
      });

      // log(getEnumerated(module, 'ffi_call'), 'p1pp', {
      //   transform: {
      //     1: (p) => DebugSymbol.fromAddress(p).toString(),
      //     3: (p) => hexdump(p.readPointer(), { ansi: true, header: false }),
      //   },
      //   call(args) {
      //     const _name = DebugSymbol.fromAddress(args[1]);
      //     const name = _name.name ?? base.sub(_name.address).toString();
      //
      //     const a0 = tryNull(() => {
      //       const x = args[3].add(0x0).readPointer().readPointer();
      //       return tryNull(() => x.readCString()) ?? x;
      //     });
      //     const a1 = tryNull(() => {
      //       const x = args[3].add(0x8).readPointer().readPointer();
      //       return tryNull(() => x.readCString()) ?? x;
      //     });
      //     logger.info({ tag: name }, `${a0} ${a1}`);
      //     // if (name !== 'strstr') return;
      //     //
      //     // this.h = log(args[1], '00', {
      //     //   tag: name,
      //     //   transform: {
      //     //     0: (p) => `${p} ${p.readCString().replaceAll(/\n/gi, '\\n')}`,
      //     //   },
      //     // });
      //   },
      //   ret(retval) {
      //     (this.h as InvocationListener)?.detach();
      //   },
      // });
    }
  },
});

let r: { base: NativePointer; size: number; done: boolean } | null = null;
// log(Libc.mmap, 'pp2i4p', {
//   predicate: ProcMaps.inRange,
//   transform: { 2: Consts.prot, 4: (x) => readFdPath(x.toInt32()) ?? `${x}` },
//   ret(retval) {
//     if (r === null && !isNully(retval)) {
//       r = { base: ptr(Number(retval)), size: this.arg1.toInt32(), done: false };
//
//       // setTimeout(() => installWatchpoint(r.base.add(0xa2ed0), () => {}), 100);
//       // setInterval(() => {
//       //   if (r.done) return;
//       //   log(r.base.add(0xa2ed0), '', {
//       //     call(args) {
//       //       logger.info({ tag: '0xa2ed0' }, `${this.returnAddress}`);
//       //       if (r.done) return;
//       //       ProcMaps.printStacktrace(this.context, '0xa2ed0');
//       //       const ranges = Process.enumerateRanges({ protection: '', coalesce: false });
//       //       for (const range of ranges) {
//       //         if (isInRange(r, range.base) || isInRange(r, range.base.add(range.size))) {
//       //           console.log(Text.stringify(range));
//       //           Memory.protect(range.base, range.size, 'r' + range.protection.substring(1));
//       //           // r.size = Number(range.base.sub(r.base));
//       //         }
//       //       }
//       //       File.writeAllBytes(`${getSelfFiles()}/annon_${r.base}`, r.base.readByteArray(r.size));
//       //       dumpLib('libjiagu_64.so');
//       //       console.log(Text.stringify(m));
//       //       r.done = true;
//       //     },
//       //   });
//       // }, 7);
//     }
//   },
// });

function installWatchpoint(addr: NativePointer, fn: () => void) {
  const thread = Process.enumerateThreads()[0];

  Process.setExceptionHandler((e) => {
    if (Process.getCurrentThreadId() === thread.id) {
      if (['breakpoint', 'single-step'].includes(e.type)) {
        console.log(Text.stringify(e));
        fn.call(this, e);
        thread.unsetHardwareWatchpoint(0);
        return true;
      }
    }
    return false;
  });

  thread.setHardwareWatchpoint(0, addr, 4, 'rw');
}

ClassLoader.perform((l) => {
  uniqHook('androidx/datastore/core/MyDataStoreImpKt', 'getStoreData');
  uniqEnum('androidx/datastore/core/MyDataStoreImpKt');

  uniqEnum('androidx.datastore.preferences.core.PreferencesKt', 1);

  // uniqFind('com.cocos.middle.kaiguan.ace_kaiguan$KaiguanListener', clzz);
  uniqHook('kotlinx.coroutines.BuildersKt__Builders_commonKt', 'launch$default');
});
