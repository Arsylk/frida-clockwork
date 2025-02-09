import * as Native from '@clockwork/native';
import { hookException, Libc, tryNull } from '@clockwork/common';
import { Color, logger } from '@clockwork/logging';
import { dumpLib } from '@clockwork/dump';
import { bindInRange } from '@clockwork/native';
const { red, magentaBright: pink, gray, dim, black } = Color.use();

function dome() {
    const mod = Process.getModuleByName('libmsaoaidsec.so');
    Memory.protect(mod.base, mod.size, 'r');
    const content = mod.base.readByteArray(mod.size);
    const path = `/data/data/com.cmi.jegotrip/libmos_${mod.base}.so`;
    File.writeAllBytes(path, content);
    console.log(path, 'nya');
}

let done = 0;
Interceptor.attach(Libc.pthread_create, {
    onEnter(args) {
        const args2 = args[2];
        const mod = Process.getModuleByAddress(args2);
        const offset = args2.sub(mod.base);
        console.log(`${mod.name}!pthread_create!${offset} is called`);
        if (mod.name.includes('libmsaoaidsec') && done++ === 0) {
            hookException([56], {
                onBefore(context, num) {
                    if (num === 56) {
                        const path = context.x1.readCString();
                        logger.info(
                            { tag: 'openat' },
                            `${path} ${context.x2} ${context.x3} ${context.x4} ${context.x8}`,
                        );
                        if (path.endsWith('/maps') || path.endsWith('/stat') || path.endsWith('/status'))
                            context.x1 = Memory.allocUtf8String('/dev/null');
                    }
                },
            });
        }
    },
});

function stalk(threadId: number, base: NativePointer) {
    const func_addr: { [key: string]: string } = {};
    let times = 0;

    const stack: { [key: string]: NativePointer } = {};
    const getInstCallTarget = (ctx: Arm64CpuContext, inst: Arm64Instruction) => {
        if (inst.groups.includes('call')) {
            //@ts-ignore
            const addr = inst.mnemonic === 'bl' ? ptr(inst.operands[0].value) : ctx.x8;
            const key = `${addr.sub(base)}`;
            const debug = DebugSymbol.fromAddress(addr);
            if (key in rfuncs || debug.name) {
                stack[`${inst.address}`] = addr;
                return { name: rfuncs[key] ?? debug.name, addr: addr };
            }
            return { addr: addr };
        }
        return {};
    };

    Stalker.exclude(Process.getModuleByName('libc.so'));
    Stalker.exclude(Process.getModuleByName('libart.so'));
    Stalker.exclude(Process.getModuleByName('libartbase.so'));
    Stalker.exclude(Process.getModuleByName('libnetd_client.so'));
    Stalker.exclude(Process.getModuleByName('libdl.so'));
    Stalker.exclude(Process.getModuleByName('libc++.so'));
    Stalker.exclude(Process.getModuleByName('liblog.so'));
    Stalker.exclude(Process.getModuleByName('boot.oat'));
    Stalker.exclude(Process.getModuleByName('boot-framework.oat'));
    Stalker.exclude(Process.getModuleByName('libandroidfw.so'));
    Stalker.exclude(Process.getModuleByName('libselinux.so'));
    Stalker.exclude(Process.getModuleByName('libopenjdkjvm.so'));
    Stalker.exclude(Process.getModuleByName('libbase.so'));
    Stalker.exclude(Process.getModuleByName('libandroid_runtime.so'));

    Stalker.follow(threadId, {
        events: {
            call: false,
            ret: false,
            exec: false,
            block: false,
            compile: false,
        },
        onReceive: (events: ArrayBuffer) => {},
        transform: (iterator: StalkerArm64Iterator) => {
            let instruction = iterator.next();
            do {
                if (Native.Inject.isInOwnRange(instruction.address)) {
                    //@ts-ignore
                    iterator.putCallout((ctx: Arm64CpuContext) => {
                        const inst = Instruction.parse(ctx.pc) as Arm64Instruction;

                        // call, branch, jump, etc.
                        const { name, addr } = getInstCallTarget(ctx, inst);
                        if (name || inst.groups.includes('call')) {
                            const prefix = `[${pink(++atomics)}]`;
                            logger.info(
                                { tag: 'call' },
                                `${prefix} ${inst} ${Native.addressOf(addr)} ${name ?? '?'} ${ctx.x0} ${ctx.x1}`,
                            );
                            if (atomics === 1) {
                            }
                        }

                        // ret
                        if (inst.groups.includes('return')) {
                            const prevAddr = ctx.lr;
                            const prevInst = Instruction.parse(prevAddr.sub(0x4));
                            const retVal = ctx.x0;
                            logger.info({ tag: '#ret' }, `${inst} ${prevAddr} ${retVal}`);
                        }
                    });
                }
                iterator.keep();
            } while ((instruction = iterator.next()) !== null);
        },

        onCallSummary: (summary) => {},
    });
}
let atomics = 0;
const rfuncs = {};
