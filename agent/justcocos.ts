
import { ClassLoader, Filter, always, compat, getHookUnique, hook, ifKey } from '@clockwork/hooks';
import { ProcMaps } from '@clockwork/cmodules';
import Java from 'frida-java-bridge';
import * as Native from '@clockwork/native';
import * as Network from '@clockwork/network';
import * as Anticloak from '@clockwork/anticloak';
import * as JniTrace from '@clockwork/jnitrace';

JniTrace.attach((x) => ProcMaps.inRange(x.returnAddress), true);
Network.injectSsl();
Network.injectCurl();
Process.attachModuleObserver({
    onAdded(module) {
        const { base, name, size, path } = module;
        if (name === 'libbeg5501.so') {
            ProcMaps.addRange(module);

            const nop = (off) => {
            Memory.protect(base.add(off), 4, 'rwx')
            base.add(off).writeByteArray([0x1f, 0x20, 0x03, 0xd5])
            Memory.protect(base.add(off), 4, 'r-x')
            };
            const bne = (off) => {
            Memory.protect(base.add(off), 4, 'rwx')
            base.add(off).writeByteArray([0x41, 0x01, 0x00, 0x54])
            Memory.protect(base.add(off), 4, 'r-x')
            };

            const w = (off: any, barr: any) => {
            Memory.protect(base.add(off), barr.length, 'rwx')
            base.add(off).writeByteArray(barr)
            Memory.protect(base.add(off), barr.length, 'r-x')
            };

            nop(0x72cc)
            nop(0x704c)
            bne(0x7e60)

            w(0x2d0b0, [0x13])

            Interceptor.attach(base.add(0x9840), {
                onEnter(args) {
                    console.log('jnionload');
                    Native.stalk(Process.id, base);
                },
                onLeave(retval) {
                    //Stalker.unfollow(Process.id);
                    retval.replace(ptr(0x0))
                },
            });
            Native.log(base.add(0x6ff0), 'pps')
        }
    }
})
Java.performNow(() => {
    Anticloak.Country.mock('IN');
    Anticloak.InstallReferrer.replace({
    });
});
Java.perform(() => {

    hook('com.nvwiny.lbqtil.juasfn.KenActivity', 'getAnzhuang', {
        replace: () => 'com.android.vending'
    })
})
