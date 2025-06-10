import { logger } from '@clockwork/logging';
import { addressOf, Inject, isInRange } from '@clockwork/native';

const config = {
    android: {
        modulename: 'libflutter.so',
        patterns: {
            arm64: [
                'F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9',
                'F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9',
                'FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9',
            ],
            arm: ['2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8'],
            x64: [
                '55 41 57 41 56 41 55 41 54 53 50 49 89 f? 4c 8b 37 49 8b 46 30 4c 8b a? ?? 0? 00 00 4d 85 e? 74 1? 4d 8b',
                '55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74',
                '55 41 57 41 56 41 55 41 54 53 48 83 EC 38 C6 02 50 48 8B AF A? 00 00 00 48 85 ED 74 7? 48 83 7D 00 00 74',
            ],
        },
    },
};

// // Main function to disable TLS validation for Flutter
function hookSslPinning() {
    let TLSValidationDisabled = false;
    Inject.afterInitArrayModule((module) => {
        const { name, base } = module;
        if (TLSValidationDisabled || name !== 'libflutter.so') return;
        const ranges = Process.enumerateRanges({ protection: 'r-x', coalesce: false }).filter((p) =>
            isInRange(module, p.base),
        );
        TLSValidationDisabled = findAndPatch(
            ranges,
            config.android.patterns[Process.arch],
            Process.arch === 'arm' ? 1 : 0,
        );
    });
}

// Find and patch the method in memory to disable TLS validation
function findAndPatch(ranges: MemoryRange[], patterns: any[], thumb: number) {
    logger.info({ tag: 'flutterssl' }, `${ranges?.join(',')} ${patterns?.join(', ')}`);
    let found = false;
    for (const range of ranges) {
        for (const pattern of patterns) {
            const matches = Memory.scanSync(range.base, range.size, pattern);
            for (const match of matches) {
                const info = addressOf(match.address);
                logger.info({ tag: 'flutterssl' }, `ssl_verify_peer_cert found at offset: ${info}`);
                found = true;
                hook_ssl_verify_peer_cert(match.address.add(thumb));
                logger.info({ tag: 'flutterssl' }, 'ssl_verify_peer_cert has been patched');
            }
            if (matches.length > 1) {
                logger.info(
                    { tag: 'flutterssl' },
                    '[!] Multiple matches detected. This can have a negative impact and may crash the app. Please open a ticket',
                );
            }
        }
    }
    return found;
}

// Replace the target function's implementation to effectively disable the TLS check
function hook_ssl_verify_peer_cert(address: NativePointer) {
    Interceptor.replace(
        address,
        new NativeCallback(
            (pathPtr, flags) => {
                logger.info({ tag: 'ssl_verify_peer_cert' }, `${pathPtr.readCString()} ${flags}`);
                return 0;
            },
            'int',
            ['pointer', 'int'],
        ),
    );
}

export { hookSslPinning };
