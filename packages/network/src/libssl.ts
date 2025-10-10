import { logger } from '@clockwork/logging';
import { addressOf, Inject } from '@clockwork/native';

function injectSsl() {
  return;
  const injected = new Set<string>();
  Inject.afterInitArray(() => {
    const matches = new ApiResolver('module').enumerateMatches('exports:*!*SSL_set_custom_verify*');
    for (const match of matches) {
      const key = `${match.address}`;
      if (injected.has(key)) continue;
      injected.add(key);

      Interceptor.replace(
        match.address,
        new NativeCallback(
          function (a0, a1) {
            logger.info({ tag: 'libssl' }, `bypassed ${addressOf(match.address)} -> 0`);
            return 0;
          },
          'int',
          ['pointer', 'pointer'],
        ),
      );
    }
  });
}

export { injectSsl };
