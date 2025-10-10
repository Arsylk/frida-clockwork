import { logger } from '@clockwork/logging';
import { addressOf, Inject } from '@clockwork/native';

const CURLOPT_CUSTOMREQUEST = 10036;
const CURLOPT_URL = 10002;
const CURLOPT_POSTFIELDS = 10015;
const CURLOPT_HTTPHEADER = 10023;

const CURLOPT_SSL_VERIFYPEER = 64;
const CURLOPT_SSL_VERIFYHOST = 81;
const CURLOPT_PINNEDPUBLICKEY = 10230;

const CURLOPT_PROXY = 10004;
const CURLOPT_PROXYTYPE = 101;

function injectCurl() {
  const injected = new Set<string>();
  Inject.afterInitArray(() => {
    const matches = new ApiResolver('module').enumerateMatches('exports:*!*curl_easy_setopt*');
    for (const match of matches) {
      const key = `${match.address}`;
      if (injected.has(key)) continue;
      injected.add(key);

      const fn = new NativeFunction(match.address, 'void', ['pointer', 'int32', 'pointer']);
      Interceptor.attach(match.address, {
        onEnter: (args) => {
          // Log requests for brief overview
          const opt = args[1].toInt32();
          switch (opt) {
            case CURLOPT_CUSTOMREQUEST:
              logger.info({ tag: 'curl' }, `method = ${args[2].readCString()}`);
              break;
            case CURLOPT_URL:
              logger.info({ tag: 'curl' }, `url = ${args[2].readCString()}`);
              break;
            case CURLOPT_POSTFIELDS:
              logger.info({ tag: 'curl' }, 'method = POST');
              break;
          }

          // Clear SSL related options
          fn(args[0], CURLOPT_SSL_VERIFYPEER, NULL);
          fn(args[0], CURLOPT_SSL_VERIFYHOST, NULL);
          fn(args[0], CURLOPT_PINNEDPUBLICKEY, NULL);

          if (
            opt === CURLOPT_SSL_VERIFYPEER ||
            opt === CURLOPT_SSL_VERIFYHOST ||
            opt === CURLOPT_PINNEDPUBLICKEY
          ) {
            args[2] = NULL;
            logger.info({ tag: 'curl' }, `bypassed ${addressOf(match.address)} for (opt=${opt})`);
          }
        },
      });
    }
  });
}

export { injectCurl };
