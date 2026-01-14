import { isIterable, stacktraceList, Text, tryErr } from '@clockwork/common';
import { hook, LoggingPredicate } from '@clockwork/hooks';
import { Color, logger } from '@clockwork/logging';
import { getSelfFiles } from '@clockwork/native';
import { createHash } from '@frida/crypto';
import Java from 'frida-java-bridge';
const { dim, gray } = Color.use();

function hookByteBufferDump() {
  const stored = new Set<string>();

  const logPred = function (method, k, args) {
    if (stored.has(k)) return false;
    stored.add(k);

    const v = args[0];
    if (!v || !isIterable(v) || v.maxByteLength < 256) return false;
    return true;
  };

  for (const cls of [Classes.ByteBuffer, Classes.HeapByteBuffer, Classes.DirectByteBuffer]) {
    const name = cls.$className.toLowerCase();
    hook(cls, 'wrap', {
      logging: { call: false, return: false },
      before(_, ...args) {
        const bytes = new Uint8Array(args[0]);
        const k = createHash('sha256').update(bytes.buffer).digest('hex').toString();
        const path = `${getSelfFiles()}/${name}_${k}`;
        if (stored.has(k) || bytes.byteLength < 256) return;
        stored.add(k);
        const st = stacktraceList();
        if (
          st.find((x) => x.includes('<clinit>') && x.includes('com.appsflyer.internal.')) &&
          st.find((x) => x.includes('java.lang.reflect.Method.invoke'))
        )
          return;
        //@ts-ignore
        const result = tryErr(() => File.writeAllBytes(path, bytes.buffer));
        logger.info({ tag: name }, `${path} ${result ? dim(Text.toByteSize(bytes.byteLength)) : 'error'}`);
      },
    });
  }
}

export { hookByteBufferDump };
