export {
  attachGetAddrInfo,
  attachGetHostByName,
  attachInteAton,
} from './hostaddr.js';
export { attachNativeSocket } from './socket.js';
export { useTrustManager, injectSsl } from './trustmanager.js';
export { hookSslPinning as flutterInjectSsl } from './flutter.js';
import { tryNull } from '@clockwork/common';
import { injectCurl } from './libcurl.js';
import { injectSsl } from './libssl.js';

function injectNative() {
  tryNull(() => injectCurl());
  tryNull(() => injectSsl());
}
export { injectNative };
