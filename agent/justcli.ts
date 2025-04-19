import { InstallReferrer } from '@clockwork/anticloak';
import { emitter } from '@clockwork/common';
import { dumpLib, hookArtLoader, initDexDump, initSoDump } from '@clockwork/dump';
import { hook } from '@clockwork/hooks';
import { getSelfFiles, Logcat } from '@clockwork/native';
import * as Unity from '@clockwork/unity';

//Unity.patchSsl();
//Unity.attachStrings();
Logcat.hookLogcat();

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
    },
});
