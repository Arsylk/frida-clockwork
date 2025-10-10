import { Text } from '@clockwork/common';
import { isNully, tryNull } from '@clockwork/common';
import { Color, logger } from '@clockwork/logging';
import { addressOf, readTidName, tryDemangle } from './utils.js';
const { bold, dim, green, red, gray, black } = Color.use();

type PthreadCreateHookParams = {
  // biome-ignore lint/suspicious/noConfusingVoidType: why ?
  before?: (returnAddress: NativePointer, startRoutine: NativePointer) => void | undefined | null | number;
  after?: (threadId: number, returnAddress: NativePointer) => void;
};

function hookPthread_create(params?: PthreadCreateHookParams) {
  const { before, after } = params || {};
  Interceptor.replace(
    Libc.pthread_create,
    new NativeCallback(
      function (thread, attr, start_routine, arg) {
        const skipValue = before?.call(this as InvocationContext, this.returnAddress, start_routine);
        if (typeof skipValue === 'number' && skipValue !== null && skipValue !== undefined) return skipValue;

        const ret = Libc.pthread_create(thread, attr, start_routine, arg);
        // magic ?
        const tid = thread.readPointer().add(16).readUInt();

        // const method = addressOf(start_routine);
        const name = '';
        const threadName = tryNull(() => readTidName(tid));
        if (threadName?.startsWith('xcDgk')) {
          Thread.sleep(1000000);
        }

        const fTid = dim(ret === 0 ? green(tid) : red(tid));
        const fThreadName = threadName ? `, ${bold(Text.noLines(threadName))} ` : ' ';
        const fMethod = `[${gray(`${''}`)} ${black(`${name}`)}] ${gray(`${start_routine}`)}`;
        logger.info(
          { tag: 'pthread_create' },
          `${gray('tid:')} ${fTid}, ${attr}${fThreadName}${fMethod}, ${!isNully(arg) ? arg.readPointer() : arg} ${addressOf(this.returnAddress)}`,
        );
        after?.(tid, this.returnAddress);

        return ret;
      },
      'int',
      ['pointer', 'pointer', 'pointer', 'pointer'],
    ),
  );
}

function hookPthread_join() {
  const NAME_LENGTH = 16;
  Interceptor.replace(
    Libc.pthread_join,
    new NativeCallback(
      (thread, args) => {
        const tid = thread.readPointer().add(16).readUInt();
        const tidv2 = Libc.pthread_gettid_np(thread);
        const buf = Memory.alloc(NAME_LENGTH);
        Libc.pthread_getname_np(thread, buf, NAME_LENGTH);
        logger.info(
          { tag: 'pthread_join' },
          `tid: ${dim(green(tid))} -> ${tidv2} ${buf.readCString()} ${thread}`,
        );
        const ret = Libc.pthread_join(thread, args);
        return ret;
      },
      'int',
      ['pointer', 'pointer'],
    ),
  );
}

export { hookPthread_create, hookPthread_join };
