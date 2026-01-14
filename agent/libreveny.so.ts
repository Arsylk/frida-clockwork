import * as Anticloak from '@clockwork/anticloak';
import * as JniTrace from '@clockwork/jnitrace';
import { Color, logger } from '@clockwork/logging';
import * as Native from '@clockwork/native';
import { Text, hookException, Linker } from '@clockwork/common';
import { ProcMaps } from '@clockwork/cmodules';
const { red, magentaBright: pink, gray, dim, green } = Color.use();

const predicate: (ptr: NativePointer) => true | undefined = () => true;

Native.attachSystemPropertyGet(predicate, (key) => {
  const value = Anticloak.BuildProp.propMapper(key);
  // const chars = new Array(value.toString().length);
  return value;
});

Native.Files.hookFopen(predicate, true, (path) => {
  if (path?.endsWith('/su') || path?.endsWith('/mountinfo') || path?.endsWith('/maps')) {
    //@ts-ignore
    Native.stalk(this.threadId, this.returnAddress);
    // return path.replace(/\/(su|mountinfo|maps)$/i, '/nya');
  }
  if (path?.includes('magisk') || path?.includes('supolicy') || path?.toLowerCase()?.includes('superuser')) {
    return path.replace(/(magisk|supolicy|superuser)/gi, 'nya');
  }
});

Interceptor.replace(
  Libc.fgets,
  new NativeCallback(
    function (buffer, size, fp) {
      const retval = Libc.fgets(buffer, size, fp);

      if (predicate(this.returnAddress)) {
        const endUserMssg = buffer.readCString()?.trimEnd();
        if (
          endUserMssg?.includes('KSU') ||
          endUserMssg?.includes('debug_ramdisk') ||
          endUserMssg?.includes('devpts') ||
          endUserMssg?.includes('tracefs') ||
          endUserMssg?.includes('tmpfs') ||
          endUserMssg?.includes('ramdisk') ||
          endUserMssg?.includes('virtio') ||
          endUserMssg?.includes('weishu') ||
          endUserMssg?.includes('magisk') ||
          endUserMssg?.includes('frida') ||
          endUserMssg?.includes('gbond') ||
          endUserMssg?.includes('termux')
        ) {
          logger.info({ tag: 'fgets' }, `${endUserMssg} ${red('SKIP')}`);
          Libc.fclose(fp);
          return Libc.fgets(buffer, size, fp);
        }
      }
      return retval;
    },
    'pointer',
    ['pointer', 'int', 'pointer'],
  ),
);

Native.replace(Libc.popen, 'pointer', ['pointer', 'pointer'], (path: NativePointer, type: NativePointer) => {
  const pathstr = path.readCString();
  let newpath: string | null = null;
  if (pathstr?.includes('getenforce')) {
    newpath = 'echo Enforcing';
  }

  if (newpath) path = Memory.allocUtf8String(newpath);
  const msg = newpath ? `${red(pathstr)} -> ${green(newpath)}` : `${pathstr}`;
  logger.info({ tag: 'popen' }, msg);
  return Libc.popen(path, type);
});

Native.Inject.onPrelinkOnce((module: Module) => {
  const { base, name, size } = module;
  if (name === 'base.odex') {
    Linker.patchSoList();
  }
  if (name === 'libreveny.so' || name === 'libhunter.so') {
  }
  Native.Files.hookOpen(
    (r) => !ProcMaps.isFridaAddress(r),
    (path) => {
      if (path?.endsWith('/build.prop')) return '/dev/null';
      if (path?.endsWith('/maps')) return '/dev/null';
      if (path?.endsWith('/status')) return '/dev/null';
      if (path?.endsWith('/mounts')) return '/dev/null';
      if (path?.endsWith('/mods')) return '/dev/null';
      if (path?.endsWith('/comm')) return '/dev/null';

      if (path?.includes('.dex')) {
        logger.info({ tag: 'dclme' }, path);
        // dumpLib(name);
      }
    },
  );

  Native.replace(Libc.dlopen, 'pointer', ['pointer', 'int'], (s0, i1) => {
    const str = s0.readCString();
    const list = Linker.getParsedList();
    for (const { base, name } of list) {
      if (str === name) {
        return base;
      }
    }
  });

  hookException([160], {
    onBefore({ x0 }, num) {
      switch (num) {
        case 160:
          this._x0 = x0;
          break;
      }
    },
    onAfter(_, num) {
      switch (num) {
        case 160:
          {
            const addr = this._x0.add(0x41 * 2);
            const text = addr.readCString().toLowerCase();

            for (const key of ['ksu', 'kernelsu', 'lineage', 'dirty']) {
              const i = text.indexOf(key);
              if (i !== -1) {
                addr.add(i).writeByteArray(new Array(key.length).fill(0x0));
              }
            }
          }
          break;
      }
    },
  });

  Native.Files.hookDirent((x) => ProcMaps.isFridaAddress(x));
  Native.Files.hookOpendir(predicate, (path) => {
    if (
      path?.startsWith('/proc') &&
      (path?.includes('/task') ||
        path.endsWith('/fd') ||
        path.endsWith('/status') ||
        path.endsWith('/fs/jbd2'))
    )
      return '/dev/null';
  });
});
