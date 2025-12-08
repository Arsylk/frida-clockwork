import { Text, tryErr } from '@clockwork/common';
import { hook } from '@clockwork/hooks';
import { Color, logger } from '@clockwork/logging';
import { getSelfFiles } from '@clockwork/native';
const { dim, gray } = Color.use();

function hookByteBufferDump() {
  hook(Classes.ByteBuffer, 'wrap', {
    predicate: (m) => m.argumentTypes.length === 3,
    before(method, ...args) {
      const bytes = new Uint8Array(args[0]);
      const path = `${getSelfFiles()}/bytebuffer_${args[0].$h}`;
      //@ts-ignore
      const result = tryErr(() => File.writeAllBytes(path, bytes.buffer));
      logger.info(
        { tag: 'bytebuffer' },
        `${path} ${result ? dim(Text.toByteSize(bytes.byteLength)) : 'error'}`,
      );
    },
  });
}

export { hookByteBufferDump };
