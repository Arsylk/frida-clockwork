import { Color, logger } from '@clockwork/logging';
import { Inject } from './inject.js';
import { addressOf } from './utils.js';
import { tryNull } from '@clockwork/common';
const { red, green, redBright, magentaBright: pink, gray, dim, black, blue } = Color.use();

let atomics = 0;
function stalk(threadId: number, base: NativePointer) {
    const func_addr: { [key: string]: string } = {};

    const stack: { [key: string]: NativePointer } = {};
    const getInstCallTarget = (ctx: Arm64CpuContext, inst: Arm64Instruction) => {
        if (inst.groups.includes('call')) {
            //@ts-ignore
            const addr = inst.mnemonic === 'bl' ? ptr(inst.operands[0].value) : ctx.x8;
            const key = `${addr.sub(base)}`;
            const debug = DebugSymbol.fromAddress(addr);
            if (key in rfuncs) {
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
            let instruction = iterator.next() as Arm64Instruction;
            do {
                if (Inject.isInOwnRange(instruction.address)) {
                    //@ts-ignore
                    iterator.putCallout((ctx: Arm64CpuContext) => {
                        const inst = Instruction.parse(ctx.pc) as Arm64Instruction;

                        // call, branch, jump, etc.
                        const { name, addr } = getInstCallTarget(ctx, inst);
                        if (name || inst.groups.includes('call')) {
                            const prefix = `[${pink(++atomics)}]`;
                            const debug = DebugSymbol.fromAddress(addr ?? NULL);
                            const sx0 = tryNull(() => ctx.x0.readCString()) ?? ctx.x0;
                            const sx1 = tryNull(() => ctx.x1.readCString()) ?? ctx.x1;
                            logger.info(
                                { tag: 'call' },
                                `${prefix} ${inst} ${blue(`${name ?? debug?.name ?? '?'}`)} { x0: ${sx0}, x1: ${sx1} }`,
                            );
                        }
                        // ret
                        if (inst.groups.includes('return')) {
                            const prevAddr = ctx.lr;
                            const prevInst = Instruction.parse(prevAddr.sub(0x4));
                            const key = `${prevInst.address}`;
                            const value = stack[key];
                            if (value) {
                                delete stack[`${prevInst.address}`];
                                const prevName = rfuncs[`${value.sub(base)}`];
                                const prefix = `[${pink(atomics--)}]`;
                                const retVal = ctx.x0;
                                logger.info(
                                    { tag: '#ret' },
                                    `${prefix} ${inst} ${prevAddr} ${prevName} ${retVal}`,
                                );
                            } else {
                                const retVal = ctx.x0;
                                logger.info({ tag: '#ret' }, `${inst} ${prevAddr} ${retVal}`);
                            }
                        }
                    });
                }
                iterator.keep();
            } while ((instruction = iterator.next() as Arm64Instruction) !== null);
        },

        onCallSummary: (summary) => {},
    });
}

const rfuncs = {};

export { stalk };
