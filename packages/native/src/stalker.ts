import { Color, logger } from '@clockwork/logging';
import { Inject } from './inject.js';
import { addressOf } from './utils.js';
import { Text, tryNull } from '@clockwork/common';
import { ProcMaps } from '@clockwork/cmodules';
const { red, green, redBright, magentaBright: pink, gray, dim, black, blue } = Color.use();

let atomics = 0;
function stalk(threadId: number, base: NativePointer) {
  const func_addr: { [key: string]: string } = {};

  const stack: { [key: string]: NativePointer } = {};
  const getInstCallTarget = (ctx: Arm64CpuContext, inst: Arm64Instruction) => {
    if (inst.groups.includes('call')) {
      const addr =
        inst.mnemonic === 'bl'
          ? //@ts-ignore
            ptr(inst.operands[0].value)
          : ctx[(inst.operands[0] as Arm64RegOperand).value];
      const key = `${addr.sub(base).sub(0x000000)}`;
      if (key in rfuncs) {
        stack[`${inst.address}`] = addr;
        return { name: rfuncs[key], addr: addr };
      }
      return { addr: addr };
    }
    return {};
  };

  for (const lib of [
    'libc.so',
    'libart.so',
    'libartbase.so',
    'libnetd_client.so',
    'libdl.so',
    'libc++.so',
    'liblog.so',
    'boot.oat',
    'boot-framework.oat',
    'libandroidfw.so',
    'libselinux.so',
    'libopenjdkjvm.so',
    'libbase.so',
    'libandroid_runtime.so',
    'libcurl.so',
  ]) {
    // const mod = Process.findModuleByName(lib);
    // if (mod) Stalker.exclude(mod);
  }

  let last: string | null = null;
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
        if (ProcMaps.inRange(instruction.address)) {
          //@ts-ignore
          iterator.putCallout((ctx: Arm64CpuContext) => {
            const inst = Instruction.parse(ctx.pc) as Arm64Instruction;
            // logger.info({ tag: 'stalk', id: `${inst.address.sub(base).toString(16)}` }, `${inst}`);
            if (!inst.groups.includes('call')) {
              // logger.info(
              //     { tag: inst.address.sub(base).add(0x100000).toString(16) },
              //     `${inst}`,
              // );
              return;
            }

            // call, branch, jump, etc.
            const { name, addr } = getInstCallTarget(ctx, inst);
            if (name || inst.groups.includes('call')) {
              const prefix = `[${pink(++atomics)}]`;
              const debug = DebugSymbol.fromAddress(addr ?? NULL);
              const sx0 = tryNull(() => Text.maxLengh(Text.noLines(ctx.x0.readCString()), 100)) ?? ctx.x0;
              const sx1 = tryNull(() => Text.maxLengh(Text.noLines(ctx.x1.readCString()), 100)) ?? ctx.x1;
              if (last !== (name ?? debug?.name))
                logger.info(
                  { tag: 'call' },
                  `${prefix} ${inst} ${blue(`${name ?? debug?.name ?? '?'}`)} { x0: ${sx0}, x1: ${sx1} } ${addressOf(inst.address)}`,
                );
              last = name ?? debug?.name ?? null;
            }
            // ret
            // if (inst.groups.includes('return')) {
            //     const prevAddr = ctx.lr;
            //     const prevInst = Instruction.parse(prevAddr.sub(0x4));
            //     const key = `${prevInst.address}`;
            //     const value = stack[key];
            //
            //     if (value) {
            //         delete stack[`${prevInst.address}`];
            //         const prevName = rfuncs[`${value.sub(base)}`];
            //         const prefix = `[${pink(atomics--)}]`;
            //         const retVal = ctx.x0;
            //         logger.info(
            //             { tag: '#ret' },
            //             `${prefix} ${inst} ${prevAddr} ${prevName} ${retVal}`,
            //         );
            //     } else {
            //         const retVal = ctx.x0;
            //         logger.info({ tag: '#ret' }, `${inst} ${prevAddr} ${retVal}`);
            //     }
            // }
          });
        }
        iterator.keep();
      } while ((instruction = iterator.next() as Arm64Instruction) !== null);
    },

    onCallSummary: (summary) => {},
  });
}

const rfuncs =
export { stalk };
