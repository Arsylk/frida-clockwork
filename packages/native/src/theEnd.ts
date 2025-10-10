import { ProcMaps } from '@clockwork/cmodules';
import { Libc, Struct, Text } from '@clockwork/common';
import { log, logger } from '@clockwork/logging';
import { addressOf } from './utils.js';

function hookExit(predicate: (ptr: NativePointer) => boolean) {
  const array: ('exit' | '_exit')[] = ['exit', '_exit'];
  for (const key of array) {
    const func = Libc[key];
    Interceptor.replace(
      func,
      new NativeCallback(
        function (code) {
          //const stacktrace = Thread.backtrace(this?.context, Backtracer.FUZZY)
          //    .map((x) => addressOf(x, true))
          //    .join('\n\t');
          logger.info({ tag: key }, `code: ${code} ${addressOf(this?.returnAddress ?? NULL)}`);
          ProcMaps.printStacktrace(this?.context, key);
          // return func(code);
          return;
        },
        'void',
        ['int'],
      ),
    );
  }
  Interceptor.replace(
    Libc.raise,
    new NativeCallback(
      function (err) {
        //const stacktrace = Thread.backtrace(this?.context, Backtracer.FUZZY)
        //    .map((x) => addressOf(x, true))
        //    .join('\n\t');
        logger.info({ tag: 'raise' }, `err: ${err} ${addressOf(this?.returnAddress ?? NULL)}`);
        ProcMaps.printStacktrace(this?.context, 'raise');
        return 0;
      },
      'int',
      ['int'],
    ),
  );
  Interceptor.attach(Libc.abort, {
    onEnter(args) {
      logger.info({ tag: 'abort' }, `code: ${args[0].toInt32()}`);
      ProcMaps.printStacktrace(this?.context, 'abort');
    },
  });
}

function hookKill(predicate: (ptr: NativePointer) => boolean) {
  Interceptor.replace(
    Libc.kill,
    new NativeCallback(
      // for some reason entire `this` object can be undefined here ?
      function (pid, code) {
        //const stacktrace = Thread.backtrace(this?.context, Backtracer.FUZZY).join('\n\t');
        const strAddress = addressOf(this?.returnAddress ?? NULL);
        logger.info({ tag: 'kill' }, `kill(${pid}, ${code}) ${strAddress}`);
        ProcMaps.printStacktrace(this?.context, 'kill');
        return 0;
      },
      'int',
      ['int', 'int'],
    ),
  );
}

function hookSignal(predicate: (ptr: NativePointer) => boolean) {
  try {
    Interceptor.replace(
      Libc.signal,
      new NativeCallback(
        function (sig, handler) {
          //const stacktrace = Thread.backtrace(this.context, Backtracer.FUZZY).join('\n\t');
          logger.info(
            { tag: 'signal' },
            `signal(${sig}, ${handler}) ${addressOf(this?.returnAddress ?? NULL)}`,
          );
          ProcMaps.printStacktrace(this?.context, 'signal');
          return Libc.signal(sig, handler);
        },
        'pointer',
        ['int', 'pointer'],
      ),
    );
  } catch (e) {
    Interceptor.attach(Libc.signal, {
      onEnter({ 0: sig, 1: handler }) {
        logger.info(
          { tag: 'signal' },
          `signal(${sig}, ${handler}) ${addressOf(this?.returnAddress ?? NULL)}`,
        );
        ProcMaps.printStacktrace(this?.contextt, 'signal');
      },
    });
  }
}

function hookSigaction(predicate: (ptr: NativePointer) => boolean) {
  try {
    Interceptor.replace(
      Libc.sigaction,
      new NativeCallback(
        function (sig, act, oldact) {
          //const stacktrace = Thread.backtrace(this.context, Backtracer.FUZZY).join('\n\t');
          const sigact = Struct.Sigaction(act);
          logger.info(
            { tag: 'sigaction' },
            `sigaction(${sig}, ${Text.stringify(Struct.toObject(sigact))}, ${oldact}) ${addressOf(this?.returnAddress ?? NULL)}`,
          );
          // ProcMaps.printStacktrace(this?.context, 'sigaction');
          return Libc.sigaction(sig, act, oldact);
        },
        'int',
        ['int', 'pointer', 'pointer'],
      ),
    );
  } catch (e) {
    Interceptor.attach(Libc.signal, {
      onEnter({ 0: sig, 1: handler }) {
        logger.info(
          { tag: 'signal' },
          `signal(${sig}, ${handler}) ${addressOf(this?.returnAddress ?? NULL)}`,
        );
        ProcMaps.printStacktrace(this?.contextt, 'signal');
      },
    });
  }
}

function hookPError(predicate: (ptr: NativePointer) => boolean) {
  try {
    Interceptor.replace(
      Libc.perror,
      new NativeCallback(
        function (err) {
          //const stacktrace = Thread.backtrace(this.context, Backtracer.FUZZY).join('\n\t');
          logger.info(
            { tag: 'perror' },
            `perror(${err.readCString()}) ${addressOf(this?.returnAddress ?? NULL)}`,
          );
          ProcMaps.printStacktrace(this?.context, 'perror');
          return Libc.perror(err);
        },
        'void',
        ['pointer'],
      ),
    );
  } catch (error) {}
}
function hook(fn?: (this: InvocationContext) => void) {
  hookKill(() => true);
  hookExit(() => true);
  hookSignal(() => true);
  hookSigaction(() => true);
  hookPError(() => true);

  const art_end = Process.getModuleByName('libart.so')
    .enumerateSymbols()
    .filter((x) => x.name.includes('art_sigsegv_fault'))[0]?.address;
  art_end &&
    Interceptor.attach(art_end, {
      onEnter(args) {
        logger.info({ tag: 'art_sigsegv_fault' }, `${addressOf(this.returnAddress)}`);
        logger.info(
          { tag: 'art_sigsegv_fault' },
          Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map((x) => x)
            .join('\t\n'),
        );
        ProcMaps.printStacktrace(this.context);
        fn?.call(this);
        Thread.sleep(10000);
      },
    });
}

export { hook, hookExit, hookKill };
