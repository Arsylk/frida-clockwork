import { Jigau } from '@clockwork/anticloak';
import * as Dump from '@clockwork/dump';

Jigau.memoryPatch();
Dump.scheduleDexDump(10_000);
Dump.initSoDump();
// Native.attachSystemPropertyGet(function (key) {
//     switch (key) {
//         case 'ro.debuggable':
//             return '0';
//         case 'ro.product.model':
//             return 'Raven';
//         case 'ro.product.brand':
//             return 'Xiaomi';
//         case 'ro.build.flavor':
//             return 'raven-release';
//     }

//     if (Native.Inject.modules.findPath(this.returnAddress)?.includes('/data') === true) return 'nya';
// });
