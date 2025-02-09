import { ProcMaps } from '@clockwork/cmodules';
import { Text, emitter, getFindUnique, isNully, stacktrace, tryNull } from '@clockwork/common';
import { getHookUnique } from '@clockwork/hooks';
import { Color, logger } from '@clockwork/logging';
const uniqHook = getHookUnique(true);
const uniqFind = getFindUnique(false);
const clone = Module.findExportByName('libc.so', 'clone');
Interceptor.attach(clone, {
    onEnter: (args) => {
        if (!isNully(args[3])) {
            const addr = args[3].add(96).readPointer();
            const so_name = Process.findModuleByAddress(addr).name;
            const so_base = Module.getBaseAddress(so_name);
            const offset = addr.sub(so_base);
            console.log('===============>', so_name, addr, offset, offset.toString(16));
        }
    },
});

Interceptor.attach(Module.findExportByName(null, 'android_dlopen_ext'), {
    onEnter: function (args) {
        const pathptr = args[0];
        if (pathptr !== undefined && pathptr != null) {
            const path = pathptr.readCString();
            // console.log(path)
            if (path?.includes('libDexHelper')) {
                this.match = true;
                this.name = path;
            }
        }
    },
    onLeave: function (retval) {
        if (this.match) {
            console.log(this.name, '加载成功');
            const base = Module.findBaseAddress('libDexHelper.so');
            patch_func_nop(base.add(0x44dd4));
            patch_func_nop(base.add(0x4ec60));
            patch_func_nop(base.add(0x4eef8));
            patch_func_nop(base.add(0x32d08));
        }
    },
});
function patch_func_nop(addr: NativePointer) {
    Memory.patchCode(addr, 8, (code) => {
        code.writeByteArray([0xe0, 0x03, 0x00, 0xaa]);
        code.writeByteArray([0xc0, 0x03, 0x5f, 0xd6]);
        console.log(`patch code at ${addr}`);
    });
}

Interceptor.attach(Module.findExportByName(null, 'dlsym'), {
    onEnter: function (args) {
        const name = args[1].readCString();
        console.log('[dlsym]', name);
    },
});
