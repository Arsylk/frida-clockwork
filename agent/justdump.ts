import { Jigau } from '@clockwork/anticloak';
import * as Dump from '@clockwork/dump';
import * as Native from '@clockwork/native';

Jigau.memoryPatch();
Dump.scheduleDexDump(10_000);
Dump.initSoDump();
Native.attachSystemPropertyGet(function (key) {
    switch (key) {
        case 'ro.debuggable':
            return '0';
        case 'ro.product.model':
            return 'Raven';
        case 'ro.product.brand':
            return 'Xiaomi';
        case 'ro.build.flavor':
            return 'raven-release';
        case 'ro.product.board':
            return 'sdm720';
        case 'gsm.version.baseband':
            return 's';
    }

    // if (Native.Inject.isWithinOwnRange(this.returnAddress)) return 'nya';
});
