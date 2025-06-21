import * as Native from '@clockwork/native';
import * as Anticloak from '@clockwork/anticloak';
import * as Cocos2dx from '@clockwork/cocos2dx';
import { Text, emitter, enumerateMembers, getFindUnique, hookException } from '@clockwork/common';
import { dumpLib, hookArtLoader, initDexDump, initSoDump } from '@clockwork/dump';
import {
    ClassLoader,
    Filter,
    always,
    compat,
    getHookUnique,
    hook,
    ifKey,
    getHookLogger,
} from '@clockwork/hooks';
import * as JniTrace from '@clockwork/jnitrace';
import { logger } from '@clockwork/logging';
import { Inject, Logcat, Strings, System, addressOf, getSelfFiles, readFdPath } from '@clockwork/native';
import * as Network from '@clockwork/network';
import Java from 'frida-java-bridge';
const uniqHook = getHookUnique(false);
const uniqFind = getFindUnique(false);
const uniqEnum = (clazzName: string, depth?: number) => {
    uniqFind(clazzName, (clazz) => {
        hook(clazz, '$init');
        enumerateMembers(
            clazz,
            {
                onMatchMethod(clazz, member, depth) {
                    hook(clazz, member);
                },
            },
            depth,
        );
    });
};

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

// Java.performNow(() => {
//     hook(Classes.File, 'delete', {
//         replace: always(true),
//         after(method, returnValue, ...args) {
//             logger.info({ tag: 'file', id: '!' }, `${this}`);
//         },
//         logging: { call: false, return: false },
//     });
// });

JniTrace.attach((x) => Inject.isInOwnRange(x.returnAddress), true);
Network.injectSsl();
Network.injectCurl();
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

    // const logger = getHookLogger({ multiline: false });
    // hook(Classes.Method, 'invoke', {
    //     logging: {
    //         call: false,
    //         return: true,
    //     },
    //     after(methpd, returnValue, ...args) {
    //         const id = '#id:-1';
    //         const className = this.getDeclaringClass().getName();
    //         const methodName = this.getName();
    //         const argTypes = this.getParameterTypes().map((x) => x.getName());
    //         const returnType = this.getReturnType().getName();
    //         console.log(Text.toPrettyType(returnType));
    //         const refArgs = args[1];
    //         logger.printCall(className, methodName, refArgs, argTypes, returnType, id, false);
    //         logger.printReturn(returnValue, returnType, id);
    //     },
    // });
    ClassLoader.perform(() => {
        uniqHook('com.liements.opmethor.LuanchActivity', 'startGame', {
            replace(method, args) {
                return method.call(this, '1');
            },
        });
    });
});

// Cocos2dx.dump({ name: 'libcocos2djs.so', fn_dump: ptr(0x006edf7c), fn_key: ptr(0x006248e0) });
// Cocos2dx.hookLocalStorage(function (key) {
//     logger.info({ tag: 'localcocos' }, `${key} -> ${this.fallback()}`);
//     return undefined;
// });
// Unity.patchSsl();
// Unity.attachScenes();
// Unity.attachStrings();
System.hookSystem();
// Process.attachModuleObserver({
//     onAdded(module) {
//         if (module.name === 'libcom.common.core.so') {
//             Native.log(module.base.add(0x426bc), 'pp', {
//                 call(args) {
//                     Native.stalk(this.threadId, module.base);
//                 },
//             });
//         }
//         if (module.name === 'libRTXApp.so') {
//             hookException([56], {
//                 onBefore(context, num) {
//                     if (num === 56) {
//                         const path = context.x1.readCString();
//                         this.path = path;
//                         const mode = context.x2.toInt32();
//                         this.mode = mode;
//                         logger.info({ tag: '__openat' }, `${path} ${mode}`);
//                     } else if (num === 62) {
//                         const fd = readFdPath(context.x0.toInt32());
//                         logger.info(
//                             { tag: 'lseek' },
//                             `${fd} +${context.x1.toInt32()} ${context.x2.toUInt32()}`,
//                         );
//                     } else if (num === 63 || num === 67) {
//                         const fd = readFdPath(context.x0.toInt32());
//                         this.fd = fd;
//                         this.buf = context.x1;
//                     } else if (num === 78) {
//                         this.path = context.x1.readCString();
//                         this.buf = context.x2;
//                         this.bufsize = context.x3.toInt32();
//                     } else if (num === 130) {
//                         logger.info({ tag: 'tkill' }, `${context.x0.toInt32()}`);
//                     } else if (num === 134) {
//                         logger.info({ tag: 'rt_sigaction' }, `${context.x0.toInt32()}`);
//                     }
//                 },
//                 onAfter(context, num) {
//                     if (num === 56) {
//                         const path = this.path;
//                         if (path?.endsWith('/map')) {
//                             const numFd = context.x0.toInt32();
//                             if (numFd > 0) {
//                                 Libc.close(numFd);
//                             }
//                             const arg1ptr = this.rawargs.add((1 + 1) * Process.pointerSize);
//                             arg1ptr.writePointer(Memory.allocUtf8String('/dev/nya'));
//                             this.redo_call();
//                         }
//                     } else if (num === 63) {
//                         const length = context.x0.toInt32();
//                         const content = this.buf.readCString(length);
//                         const patch = content.replace(/frida/gi, 'nyasi');
//                         this.buf.writeUtf8String(patch);
//                         logger.info({ tag: 'read' }, `${this.fd} -> \n${content}`);
//                     } else if (num === 67) {
//                         const length = context.x0.toInt32();
//                         const content = hexdump(this.buf, { length: length, ansi: true });
//                         const patch = content.replace(/frida/gi, 'nyasi');
//                         this.buf.writeUtf8String(patch);
//                         logger.info({ tag: 'pread64' }, `${this.fd} -> \n${content}`);
//                     } else if (num === 78) {
//                         const result = this.buf.readCString(this.bufsize);
//                         logger.info({ tag: 'readlinkat' }, `${this.path} -> ${result}`);
//                     }
//                 },
//             });
//         }
//     },
// });

Java.performNow(() => {
    ClassLoader.perform(() => {});
});

// Strings.hookStrstr(Inject.isInOwnRange);
emitter.on('dexart', () => hookArtLoader());
emitter.on('dexdump', () => initDexDump());
emitter.on('sodump', () => initSoDump());
emitter.on('module', (libname: string) => dumpLib(libname));
emitter.on('savetext', (content: string, name: string) =>
    //@ts-ignore
    File.writeAllText(content, `${getSelfFiles()}/${name}`),
);
emitter.on('savebin', (content: unknown, name: string) =>
    //@ts-ignore
    File.writeAllBytes(content, `${getSelfFiles()}/${name}`),
);

const Fn = {
    hook: hook,
    hookArtLoader: () => emitter.emit('dexart'),
    initDexDump: () => emitter.emit('dexdump'),
    initSoDump: () => emitter.emit('sodump'),
    dumpLib: (libname: string) => emitter.emit('module', libname),
    save: (content: string, name: string) => {
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
