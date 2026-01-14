import { Text, tryNull } from '@clockwork/common';
import { hook } from '@clockwork/hooks';
import { logger } from '@clockwork/logging';
import { getSelfFiles } from '@clockwork/native';
import { createHash } from '@frida/crypto';
import Java from 'frida-java-bridge';

function doFinalDump(decrypt: boolean = true, encrypt: boolean = false) {
  hook(Classes.Cipher, 'doFinal', {
    after(_, returnValue, ...args) {
      const isEnc = this.opmode.value === 1;
      const isDec = this.opmode.value === 2;
      if (!isEnc && !isDec) return;
      let tag: string | null = null;
      let data: any | null = null;
      if (isEnc) {
        data = args[0];
        tag = 'encrypt';
      }
      if (isDec) {
        data = returnValue;
        tag = 'decrypt';
      }
      if (tag == null || data == null) return;

      let str = tryAsAnyString(data);
      logger.info({ tag: tag }, `${str} ${Text.toByteSize(data.size ?? data.length ?? 0)}`);

      if ((isEnc && encrypt) || (isDec && decrypt)) {
        // this can save bytes to file easily
        try {
          const buffer = Java.array('byte', data);
          //@ts-ignore
          const barr = ptr(buffer).readByteArray(buffer.length);
          logger.info({ tag: 'dump', id: tag }, `${barr}`);
          const bytes = new Uint8Array(data);
          const k = createHash('sha256').update(bytes.buffer).digest('hex').toString();
          const path = `${getSelfFiles()}/${tag}_${k}`;
          logger.info({ tag: 'dump', id: tag }, `${path}`);
          //@ts-ignore
          File.writeAllBytes(path, uint8s.buffer);
        } catch (e) {
          logger.warn({ tag: 'dump', id: tag }, `${e}`);
        }
      }
    },
    logging: { arguments: false, return: false },
  });
}

function tryAsAnyString(data: any): string {
  let str = tryNull(() => Classes.String.$new(data, Classes.StandardCharsets.UTF_8.value));
  str ??= tryNull(() => Classes.String.$new(data));
  str ??= tryNull(() =>
    (Classes.Arrays.toString as Java.MethodDispatcher).overload('[B').call(Classes.Arrays, data),
  );
  str ??= tryNull(() => `${(Classes.String.valueOf as Java.MethodDispatcher).call(Classes.String, data)}`);
  str ??= `${data}`;

  return str;
}

export { doFinalDump };
