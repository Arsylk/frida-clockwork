import * as JniTrace from '@clockwork/jnitrace';
import * as Cocos2dx from '@clockwork/cocos2dx';
import * as Unity from '@clockwork/unity';
import * as Anticloak from '@clockwork/anticloak';
import { emitter, Text } from '@clockwork/common';
import { dumpLib, hookArtLoader, initSoDump, initDexDump } from '@clockwork/dump';
import { hook, getHookLogger } from '@clockwork/hooks';
import { addressOf, getSelfFiles, Inject, Logcat, Strings } from '@clockwork/native';
import { logger } from '@clockwork/logging';

const Vn = {
    isJniEnabled: true,
};

// let h: NodeJS.Timer | null = null;
// h = setInterval(() => {
//     for (const range of Inject.ownRanges) {
//         Memory.scan(range.base, range.size, '64 6F 63 2D 68 6F 73 74 69 6E 67', {
//             onMatch(address, size) {
//                 clearInterval(h);
//                 console.log(`${range.base} | ${addressOf(address)} => ${address.readCString()}`);
//             },
//         });
//     }
// }, 100);

Logcat.hookLogcat();
Java.performNow(() => {
    const AD_ID = 'fwqna41l-mrux-l4pi-mi6q-imrr3t83da4n';
    const INSTALL_REFERRER = `utm_source=facebook_ads&utm_medium=Non-organic&media_source=true_network&http_referrer=BingSearch&utm_campaign=Non-organic&campaign=Non-organic&af_ad=${AD_ID}`;
    Anticloak.generic();
    Anticloak.hookDevice();
    Anticloak.hookSettings();
    Anticloak.hookNetwork();
    Anticloak.hookAdId(AD_ID);
    Anticloak.hookPackageManager();
    Anticloak.Country.mock('BR');
    Anticloak.InstallReferrer.replace({
        install_referrer: INSTALL_REFERRER,
    });

    const logger = getHookLogger({ multiline: false });
    hook(Classes.Method, 'invoke', {
        logging: {
            call: false,
            return: true,
        },
        after(methpd, returnValue, ...args) {
            const id = '#id:-1';
            const className = this.getDeclaringClass().getName();
            const methodName = this.getName();
            const argTypes = this.getParameterTypes().map((x) => x.getName());
            const returnType = this.getReturnType().getName();
            console.log(Text.toPrettyType(returnType));
            const refArgs = args[1];
            logger.printCall(className, methodName, refArgs, argTypes, returnType, id, false);
            logger.printReturn(returnValue, returnType, id);
        },
    });
});

// Cocos2dx.dump({ name: 'libcocos2djs.so', fn_dump: ptr(0x006edf7c), fn_key: ptr(0x006248e0) });
// Cocos2dx.hookLocalStorage(function (key) {
//     logger.info({ tag: 'localcocos' }, `${key}`);
// } as any);
// Unity.patchSsl();
// Unity.attachScenes();
// Unity.attachStrings();

Strings.hookStrstr(Inject.isInOwnRange);
JniTrace.attach((ptr) => Vn.isJniEnabled && Inject.isInOwnRange(ptr.returnAddress), true);
emitter.on('dexart', () => hookArtLoader());
emitter.on('dexdump', () => initDexDump());
emitter.on('sodump', () => initSoDump());
emitter.on('module', (libname: string) => dumpLib(libname));
emitter.on('savetext', (content: string, name: string) =>
    //@ts-ignore
    File.writeAllText(content, `${getSelfFiles()}/${name}`),
);
emitter.on('savebin', (content: any, name: string) =>
    //@ts-ignore
    File.writeAllBytes(content, `${getSelfFiles()}/${name}`),
);

const Fn = {
    hook: hook,
    hookArtLoader: () => emitter.emit('dexart'),
    initDexDump: () => emitter.emit('dexdump'),
    initSoDump: () => emitter.emit('sodump'),
    dumpLib: (libname: string) => emitter.emit('module', libname),
    save: (content: string | any, name: string) => {
        if (typeof content === 'string') {
            emitter.emit('savetext', content, name);
        } else {
            emitter.emit('saveany', content, name);
        }
    },
};
Object.defineProperties(global, {
    Fn: {
        value: Fn,
        writable: false,
    },
    Vn: {
        value: Vn,
        writable: false,
    },
});
