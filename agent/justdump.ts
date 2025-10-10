import { ElfHeader, LinkerSym, memcmp, memmove, ProcMaps } from '@clockwork/cmodules';

import { ClassLoader, Filter, always, compat, findHook, getHookUnique, hook, ifKey } from '@clockwork/hooks';
import {
  hookException,
  Text,
  Linker,
  tryNull,
  Consts,
  isNully,
  getFindUnique,
  enumerateMembers,
  stacktrace,
  Struct,
  getApplicationContext,
} from '@clockwork/common';
import { dumpLib, hookArtDexFile } from '@clockwork/dump';
import { logger } from '@clockwork/logging';
import {
  addressOf,
  asExportedObject,
  Files,
  getEnumerated,
  getSelfFiles,
  getSelfProcessName,
  hardBreakPoint,
  isInRange,
  log,
  previousReturn,
  Pthread,
  readFdPath,
  replace,
  Stalker as StalkerKt,
  TheEnd,
} from '@clockwork/native';
import { dump } from '@clockwork/cocos2dx';
import Java from 'frida-java-bridge';
import { injectNative, injectSsl } from '@clockwork/network';
import { ClassesString } from '@clockwork/common';
import { hookDirent, hookFopen, hookOpendir } from '@clockwork/native/dist/files';
import { hookPtrace } from '@clockwork/anticloak/dist/debug';
import { SoInfo } from '@clockwork/common/dist/define/linker';
import { attach } from '@clockwork/jnitrace';
import { stalk } from '@clockwork/native/dist/stalker';
import { mock } from '@clockwork/anticloak/dist/country';

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
injectNative();
injectSsl();
ClassLoader.perform(() => {
  uniqHook(ClassesString.File, 'delete' /*{ replace: always(true) }*/);
  uniqHook(ClassesString.DexPathList, '$init', {
    logging: { short: true, multiline: false },
  });
});
mock('BR');
Java.performNow(() => {
  for (const cls of [Classes.SharedPreferencesImpl, Classes.Bundle]) {
    for (const str of ['getInt', 'getString', 'getBoolean']) {
      hook(cls, str, {
        replace: ifKey(function (arg) {
          if (arg === 'oqNmdODwT1HuJh') return 'nya';
        }),
      });
    }
  }
});

const libc = Process.getModuleByName('libc.so');
log(libc.getExportByName('mprotect'), 'pi2', {
  predicate: ProcMaps.inRange,
  transform: { 2: Consts.prot },
  call(args) {
    this.base = args[0];
    this.size = args[1].toInt32();
  },
  ret(retval) {
    const range = { base: this.base, size: this.size };
    mprots.push(range);
    ProcMaps.addRange(range);
  },
});
const libdl = Process.getModuleByName('libdl.so');
log(libdl.getExportByName('dlopen'), 'si', {
  call(args) {
    const name = args[0].readCString();
    this.name = name;
  },
  ret(retval) {
    const name = this.name;
    if (name) {
      if (!found) {
        // hookmore(name);
      }
    }
  },
});

let found = false;
const mprots = new Array<{ base: NativePointer; size: number }>();
const addrs = new Set<string>();
const dl_iter_cb = new Set<string>();
const dexes = new Map<string, number>();

const libart = Process.getModuleByName('libart.so');
const linker = Process.getModuleByName('linker64');

log(libdl.getExportByName('dl_iterate_phdr'), 'pp', {
  predicate: ProcMaps.inRange,
  call(args) {
    const key = `${args[0]}`;
    if (dl_iter_cb.has(key)) return;
    dl_iter_cb.add(key);
    Interceptor.replaceFast(
      args[0],
      new NativeCallback(
        function (a0, a1, a2) {
          const info = Struct.Linker.dl_phdr_info(a0);
          console.log(Text.stringify(Struct.toObject(info)));
          return 0;
        },
        'int',
        ['pointer', 'int', 'pointer'],
      ),
    );
    this.h = Interceptor.attach(args[0], {
      onEnter(args) {
        const info = (this.info = Struct.Linker.dl_phdr_info(args[0]));
        console.log(Text.stringify(Struct.toObject(info)));
      },
    });
  },
  ret(retval) {
    this.h?.detach();
  },
});
log(libdl.getExportByName('dlsym'), 'ps', {
  nolog: true,
  predicate: ProcMaps.inRange,
  call(args) {
    this.text = args[1].readCString();
  },
  ret(retval) {
    const text = this.text;
    const newret = new NativeCallback(
      function () {
        logger.info({ tag: 'dlsym', id: text }, `${addressOf(this.returnAddress)}`);
        return ptr(0x0);
      },
      'pointer',
      [],
    );
    retval.replace(newret);
  },
});
log(libdl.getExportByName('dladdr'), 'p1', {
  call(args) {
    ProcMaps.printStacktrace(this.context);
  },
  predicate: ProcMaps.inRange,
  transform: {
    1: (x) => addressOf(x),
  },
});
log(libdl.getExportByName('dlclose'), 'p', {
  predicate: ProcMaps.inRange,
});

// log(Module.getGlobalExportByName('__cxa_atexit'), '000', {
//     transform: {libjiagu
//         0: (ptr) => DebugSymbol.fromAddress(ptr).toString()
//     }
// });

log(libc.getExportByName('mmap'), 'pp2i4p', {
  predicate: ProcMaps.inRange,
  transform: { 2: Consts.prot, 4: (x) => readFdPath(x.toInt32()) ?? `${x}` },
});

log(libc.getExportByName('opendir'), 's', {
  predicate: ProcMaps.inRange,
  call(args) {
    // if (args[0].readCString().endsWith('/fd')) {
    //   this.close = true;
    //   args[0] = Memory.allocUtf8String('/dev/null');
    // }
  },
  ret(retval) {
    // if (true || this.close) {
    //   Libc.closedir(retval);
    // }
  },
});
log(libc.getExportByName('munmap'), 'hi', {
  predicate: ProcMaps.inRange,
  call(args) {
    // const file = `${getSelfFiles()}/munmap_${this.returnAddress}`;
    // logger.info({ tag: 'writetofile' }, file);
    // File.writeAllBytes(file, args[0].readByteArray(args[1].toInt32()));
  },
});
log(libc.getExportByName('time'), 'p', { predicate: ProcMaps.inRange });
log(libc.getExportByName('system'), 'si', { predicate: ProcMaps.inRange });
log(libc.getExportByName('rmdir'), 's', { predicate: ProcMaps.inRange });
log(libc.getExportByName('readlink'), 's', {
  predicate: ProcMaps.inRange,
  call(args) {
    this.a0 = args[0];
    this.a1 = args[1];
    this.a2 = args[2];
  },
  ret(retval) {
    const ln = this.a0.readCString();
    const real = this.a1.readCString();
    logger.info({ tag: 'readlink' }, `${ln ?? this.a0} -> ${real ?? retval}`);
  },
});
log(libc.getExportByName('readlinkat'), 'is', { predicate: ProcMaps.inRange });
log(libc.getExportByName('fstat'), '0p', {
  predicate: ProcMaps.inRange,
  transform: { 0: (x) => readFdPath(x.toInt32()) ?? `${x}` },
});
log(libc.getExportByName('printf'), 'si', { predicate: ProcMaps.inRange });
log(libc.getExportByName('sprintf'), 'ssi', { predicate: ProcMaps.inRange });
log(libc.getExportByName('time'), 'p', { predicate: ProcMaps.inRange });
log(libc.getExportByName('setenv'), 'ss', { predicate: ProcMaps.inRange });
log(libc.getExportByName('mkdir'), 'si', { predicate: ProcMaps.inRange });
log(libc.getExportByName('epoll_create'), 'i', { predicate: ProcMaps.inRange });
log(libc.getExportByName('epoll_wait'), 'ipii', { predicate: ProcMaps.inRange });
log(libc.getExportByName('epoll_ctl'), 'iiip', { predicate: ProcMaps.inRange });
log(libc.getExportByName('raise'), 'i', { predicate: ProcMaps.inRange });
log(libc.getExportByName('getenv'), 's', { predicate: ProcMaps.inRange });
log(libc.getExportByName('sysconf'), 'i', { predicate: ProcMaps.inRange });
log(libc.getExportByName('strcpy'), 'ss', { predicate: ProcMaps.inRange, ret: false });
log(libc.getExportByName('strchr'), 'si', { predicate: ProcMaps.inRange });
log(libc.getExportByName('strtok'), 's', { predicate: ProcMaps.inRange });
log(libc.getExportByName('strcat'), 'ss', { call: true, ret: false, predicate: ProcMaps.inRange });
log(libc.getExportByName('strcmp'), 'ssu', {
  predicate: ProcMaps.inRange,
  call(args) {
    // this.arg0 = args[0].readCString();
    // this.arg1 = args[1].readCString();
  },
  ret(retval) {
    // if (this.arg1.startsWith(' RES_RULE')) {
    //   retval.replace(ptr(0x0));
    // }
  },
});

log(libc.getExportByName('strstr'), 'ss', { predicate: ProcMaps.inRange });
log(libc.getExportByName('strlen'), 's', { predicate: ProcMaps.inRange });
log(libc.getExportByName('strdup'), 's', { predicate: ProcMaps.inRange });
log(libc.getExportByName('syscall'), 'i', {
  predicate: ProcMaps.inRange,
  call(args) {
    if (args[0].toInt32() === 56) {
      const path = args[1].readCString();
      logger.info({ tag: 'syscall' }, `${path}`);
      if (path === '/proc/self/task') {
        // args[1] = Memory.allocUtf8String('/dev/null');
      }
    }
  },
});
log(libc.getExportByName('prctl'), 'pp', { predicate: ProcMaps.inRange });

log(libc.getExportByName('fork'), '', { predicate: ProcMaps.inRange });
log(libc.getExportByName('pthread_kill'), 'p', { predicate: ProcMaps.inRange });
log(libc.getExportByName('pthread_detach'), 'p', { predicate: ProcMaps.inRange });
log(libc.getExportByName('pthread_create'), 'pp2p', {
  predicate: ProcMaps.inRange,
  transform: {
    2: (ptr) => addressOf(ptr),
  },
});
log(libc.getExportByName('access'), 's', {
  predicate: ProcMaps.inRange,
  call(args) {
    // if (args[0].readCString() === '/proc/self/mounts') {
    //   args[0] = Memory.allocUtf8String('/dev/null');
    // }
  },
});
log(libc.getExportByName('fopen'), 'si', {
  predicate: ProcMaps.inRange,
  call(args) {
    ProcMaps.printStacktrace(this.context);
    const path = args[0].readCString();
    if (path?.includes('/maps')) {
      // args[0] = Memory.allocUtf8String('/dev/null');
    }
    if (path.endsWith('/libc.so')) {
      // const newpath = `${getSelfFiles()}/fakelibc.so`;
      // const bytesto = libc.base.readByteArray(libc.size);
      // File.writeAllBytes(newpath, bytesto);
      // args[0] = Memory.allocUtf8String(`/data/data/${getSelfProcessName()}/fakelibc`);
    }
    // if (args[0].readCString()?.includes('/cmdline')) {
    //   args[0] = Memory.allocUtf8String('/dev/null');
    // }
    // if (args[0].readCString()?.includes('/libc.so')) {
    //   args[0] = Memory.allocUtf8String('/dev/null');
    // }
  },
});
log(libc.getExportByName('openat'), 'isi', { predicate: ProcMaps.inRange });
log(libc.getExportByName('open64'), 'si', {
  predicate: ProcMaps.inRange,
});
log(libc.getExportByName('__open_2'), 'si', { predicate: ProcMaps.inRange });
log(libc.getExportByName('sigfillset'), 'pp', { predicate: ProcMaps.inRange });
log(libc.getExportByName('setpgid'), 'pp', { predicate: ProcMaps.inRange });
log(libc.getExportByName('lstat'), 'sp', { predicate: ProcMaps.inRange });
log(libc.getExportByName('lseek'), '0p2', {
  predicate: ProcMaps.inRange,
  transform: {
    0: (ptr) => readFdPath(ptr.toInt32()),
    2: (ptr) => Consts.whence[ptr.toInt32()],
  },
});
// log(libc.getExportByName('read'), '0pi', {
//   predicate: ProcMaps.inRange,
//   call(args) {
//     this.a1 = args[1];
//   },
//   transform: {
//     0: (x) => readFdPath(x.toInt32()) ?? `${x}`,
//     NaN: function (ptr) {
//       return hexdump(this.a1, { length: Math.min(ptr.toInt32(), 0x100) });
//     },
//   },
// });
// Interceptor.replace(
//   libc.getExportByName('remove'),
//   new NativeCallback(
//     (a0) => {
//       logger.info({ tag: 'remove' }, a0.readCString());
//       return 0;
//     },
//     'int',
//     ['pointer'],
//   ),
// );
// Interceptor.replace(
//   libc.getExportByName('unlink'),
//   new NativeCallback(
//     (a0) => {
//       logger.info({ tag: 'unlink' }, a0.readCString());
//       return 0;
//     },
//     'int',
//     ['pointer'],
//   ),
// );

// hookPtrace();
// TheEnd.hook();
// Interceptor.attach(Libc.memmove, memmove);
// Interceptor.attach(Libc.memcmp, memcmp);
attach((x) => ProcMaps.inRange(x.returnAddress), true);
// hookArtDexFile();
Process.attachModuleObserver({
  onAdded(module) {
    const { base, name, size, path } = module;
    if (
      !path.includes(Reflect.get(globalThis, 'packageName')) ||
      name === 'libmonochrome_64.so' ||
      name === 'libunity.so' ||
      name === 'libil2cpp.so' ||
      name === 'libandroid.so' ||
      name === 'libhwui.so' ||
      name === 'libsigner.so' ||
      name === 'libnms.so' ||
      name === 'libmmkv.so' ||
      name === 'ibdB2CB406F37A3.so' ||
      name === 'libd47052F4E9E58.so' ||
      name === 'libflutter.so' ||
      name === 'libtobEmbedPagEncrypt.so' ||
      name === 'libapminsighta.so'
    )
      return;
    if (name === 'base.odex') {
      Linker.patchSoList((name) => {
        for (const t of ['frida', 'memfd', 'libart.so', 'libdl.so']) {
          if (name.includes(t)) return true;
        }
        return false;
      });
    }
    logger.info({ tag: 'phdr_add' }, `${Text.stringify({ name: name, base: base, size: size, path: path })}`);
    ProcMaps.addRange(module);
    if (name.includes('libtodefy.so')) {
      Interceptor.attach(getEnumerated(module, 'JNI_OnLoad'), {
        onEnter(args) {
          Interceptor.detachAll();
          StalkerKt.stalk(this.threadId, module.base);
        },
      });
      return;
      log(base.add(0x11d6c), 'pp');
      log(base.add(0xd07c), 'pp', { tag: 'set_phdr_protections' });
      log(base.add(0x363d4), 'pp', { tag: 'apply_relocs_and_search_deps' });
      log(base.add(0xa890), 'pp', {
        tag: 'exec_encoded_function_calls',
        call(args) {
          const size = args[1].toInt32();
          const int64s = new Uint8Array(args[0].readByteArray(size));
          console.log(int64s.join(', '));
        },
      });
      log(base.add(0xd378), 'pp', {
        tag: 'decrypt_and_assign',
        ret(retval) {
          const base = this.arg0.add(0x50);
          const size = Number(this.arg1.add(0x18).readU64());
          logger.info({ tag: '0xd378' }, `e_phnum: ${this.arg0.add(0x48).readS16()} size: ${size}`);
          logger.info({ tag: '0xd378' }, `${hexdump(base)}`);

          const file = `${getSelfFiles()}/0xd378_${base}.so`;
          const ptr = base;
          // if (!Memory.protect(ptr, size, 'rwx')) {
          //   if (!Memory.protect(ptr, size, 'r')) {
          //     for (let r = ptr; r < base.add(size); r = r.add(Process.pageSize)) {
          //       console.log(r);
          //       Memory.protect(r, Process.pageSize, 'r');
          //     }
          //   }
          // }
        },
      });
      log(base.add(0xcec0), 'pp', { tag: 'alloc_relocation_memory', call(args) {} });
      log(base.add(0xb6d8), 'pp', {
        tag: 'parse_and_load_dynamic_sectioin',
        call(args) {
          const base = args[0].add(0x190).readPointer();
          const dyn = args[0].add(0x100).readPointer();
          const diff = Number(base.sub(module.base));
          logger.info({ tag: 'diff' }, `${diff}`);
          logger.info({ tag: 'dynamic' }, hexdump(base));
          logger.info({ tag: 'dyn' }, hexdump(dyn));

          const file = `${getSelfFiles()}/base_${base}`;
          logger.info({ tag: 'writetofile' }, file);
          File.writeAllBytes(file, base.readByteArray(module.size - diff));
        },
      });
    }
  },
});

function hookmore(name: string) {
  const module = Process.findModuleByName(name);
  console.log('hookmore:', module.name);
  if (!module) return;
  for (const range of [module, ...mprots]) {
    logger.info({ tag: 'memscan' }, `${range.base} - ${range.base.add(range.size)}`);
    for (let _base = range.base; _base < range.base.add(range.size); _base = _base.add(Process.pageSize)) {
      try {
        const match = Memory.scanSync(_base, Process.pageSize, '01 00 b4 ?? 01 00 b4 ?0 0? 3f d6');
        if (match.length === 0) continue;
        const address = match[0].address;
        logger.info({ tag: 'memmatch' }, `${address}`);
        const inst = Instruction.parse(address.sub(0x1 + 0x4 * 2)) as Arm64Instruction;
        if (inst.mnemonic === 'bl') {
          found = true;
          const op = inst.operands[0] as Arm64ImmOperand;
          const f = ptr(`${op.value}`);
          logger.info({ tag: 'memfound' }, `${inst.address} ${inst} ${f}`);

          dumpLib('libjiagu_64.so');
          log(f, 'ps', {
            call(args) {
              this.symbol = args[1].readCString();
            },
            ret(retval) {
              if (this.symbol === 'mprotect') {
                return retval;
              } else {
              }
              retval.replace(ptr(0x0));
            },
          });
        }
      } catch {}
    }
    if (found) break;
  }
  // if (found) hooksyscall();
}

function hooksyscall() {
  hookException([56, 62], {
    onBefore(context, num) {
      if (num === 56) {
        const path = context.x1.readCString();
        this.path = path;
        const mode = context.x2.toInt32();
        this.mode = mode;
      } else if (num === 62) {
        this.fd = context.x0.toInt32();
        this.offset = context.x1.toInt32();
        this.whence = context.x2.toUInt32();
      } else if (num === 63 || num === 67) {
        this.fd = context.x0.toInt32();
        this.buf = context.x1;
      } else if (num === 78) {
        this.path = context.x1.readCString();
        this.buf = context.x2;
        this.bufsize = context.x3.toInt32();
      } else if (num === 80) {
        this.fd = context.x1.toInt32();
      } else if (num === 130) {
        logger.info({ tag: 'tkill' }, `${context.x0.toInt32()}`);
      } else if (num === 160) {
        this.buf = context.x0;
        logger.info({ tag: 'uname' }, `${context.x0}`);
      } else if (num === 226) {
        this.base = context.x0;
        this.size = context.x1.toInt32();
        this.prot = context.x2.toUInt32();
      }
    },
    onAfter(context, num) {
      if (num === 56) {
        const path = this.path;
        if (
          path?.startsWith('/proc/') &&
          (path.endsWith('/maps') ||
            path.endsWith('/fd ') ||
            path.endsWith('/task ') ||
            path.endsWith('/cmdline ') ||
            path.endsWith('/status '))
        ) {
          const numFd = context.x0.toInt32();
          if (numFd > 0) {
            Libc.close(numFd);
          }
          const arg1ptr = this.rawargs.add((1 + 1) * Process.pointerSize);
          arg1ptr.writePointer(Memory.allocUtf8String('/data/data/com.be.myaa.game/'));
          this.redo_call();
        }
        logger.info(
          { tag: '__openat' },
          `${this.path} ${this.mode} ? ${context.x0.toInt32()}`, // ${addressOf(context.lr)}`,
        );
      } else if (num === 62) {
        const fdpath = this.fd;
        logger.info(
          { tag: 'lseek' },
          `${fdpath} ${this.offset} ${Consts.whence[this.whence]} ? ${context.x0.toInt32()}`,
        );
      } else if (num === 63) {
        const length = context.x0.toInt32();
        // Memory.protect(this.buf, length, 'rw');
        const content = this.buf.readCString(length);
        // const patch = content.replace(/frida/gi, 'nyasi');
        // this.buf.writeUtf8String(patch);
        // const mempatch = Memory.alloc(length);
        // mempatch.writeUtf8String(patch);
        // File.writeAllBytes(MEMFD, mempatch.readByteArray(length));
        // const nfd = Libc.open(Memory.allocUtf8String(MEMFD), 0).value;
        // const arg1ptr = this.rawargs.add((1 + 1) * Process.pointerSize);
        // arg1ptr.writePointer(ptr(nfd));
        // this.redo_call();
        logger.info({ tag: 'read' }, `${this.fd} -> \n${content}`);
      } else if (num === 67) {
        const length = context.x0.toInt32();
        // Memory.protect(this.buf, length, 'rw');
        const content = this.buf.readCString(length);
        // const patch = content.replace(/frida/gi, 'nyasi');
        // this.buf.writeUtf8String(patch);
        logger.info({ tag: 'pread64' }, `${readFdPath(this.fd)} -> \n${content}`);
      } else if (num === 78) {
        const result = this.buf.readCString(context.x0.toInt32())?.replace(/�/gi, '');
        logger.info({ tag: 'readlinkat' }, `${this.path} -> ${result}`);
      } else if (num === 80) {
        const path = readFdPath(this.fd);
        logger.info({ tag: 'fstat' }, `${path} -> ${''}`);
      } else if (num === 160) {
        const addr = this.buf.add(0x41 * 2);
        const text = addr.readCString().toLowerCase();

        for (const key of ['ksu', 'kernelsu', 'lineage', 'dirty']) {
          const i = text.indexOf(key);
          if (i !== -1) {
            addr.add(i).writeByteArray(new Array(key.length).fill(0x0));
          }
        }
      } else if (num === 226) {
        logger.info({ tag: 'mprotect' }, `${this.base} ${this.size} ${Consts.prot(this.prot)}`);
      }
    },
  });
}

function runme(offset: number, count = 322) {
  const { base } = Process.getModuleByName('libjiagu.so');
  const map = {};
  for (let i = 0; i < count; i += 1) {
    const at = offset + 0x8 * i;
    const value = tryNull(() => base.add(at).readPointer());
    const info = DebugSymbol.fromAddress(value);
    // logger.info({ tag: 'runme', id: base.add(at) }, `${value} ${info}`);
    if (info.name && info.moduleName !== 'libjiagu.so') {
      map[`${at}`] = [info.name, info.moduleName];
    }
  }
  logger.info({ tag: 'runme' }, JSON.stringify(map));
}
Object.defineProperty(globalThis, 'runme', runme);
rpc.exports.runme = runme;

// log(LinkerSym.__dl__ZN6soinfo17call_constructorsEv, 'p', {
//   tag: 'call_constructors',
//   transform: {
//     0: (ptr) => tryNull(() => new SoInfo(ptr).getRealpath()) ?? `${ptr}`,
//     NaN: function (ptr) {
//       return (
//         tryNull(() =>
//           Text.stringify(JSON.parse(JSON.stringify(Process.getModuleByAddress(this.soinfo.getBase())))),
//         ) ?? `${ptr}`
//       );
//     },
//   },
//   call(args) {
//     this.soinfo = new SoInfo(args[0]);
//   },
//   ret(retval) {},
// });
