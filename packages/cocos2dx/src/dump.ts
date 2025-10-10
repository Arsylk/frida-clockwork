import { Std, Text } from '@clockwork/common';
import { Color, subLogger } from '@clockwork/logging';
import { Inject, addressOf, dumpFile, log } from '@clockwork/native';
import { createHash } from '@frida/crypto';
const { dim } = Color.use();
const logger = subLogger('cocos2dx');

type Cocos2dxOffset = {
  name: string;
  fn_dump?: NativePointer;
  fn_key?: NativePointer;
  fn_set?: NativePointer;
};

function hookLegacy(): NativePointer[] {
  //@ts-ignore
  const array = Module.enumerateExportsSync(libname).filter(
    ({ name }) => name.includes('evalString') && name.includes('ScriptEngine'),
  );
  return array;
}

/**
 *  __int64 __fastcall se::ScriptEngine::evalString(
 *         se::ScriptEngine *this,
 *         const char *scripts,
 *         unsigned __int64 len,
 *         se::Value *a4,
 *         const char *filename)
 * */
const hookEvalString: InvocationListenerCallbacks = {
  onEnter(args) {
    const [_, scripts, len, , filename] = [args[0], args[1], args[2], args[3], args[4]];
    let length: number | null = null;
    let path: string | null = null;
    let data: string | null = null;
    if (filename && (path = filename.readCString())) {
      length = len.toUInt32();
    } else if ((data = scripts.readCString())) {
      path = `${createHash('sha256').update(data).digest('hex')}.js`;
      length = data.length;
    }
    if (!length || !path) return;
    const result = dumpFile(scripts, length, path, 'cocos2dx');
    logger.info(`${path} ${result ? dim(Text.toByteSize(length)) : 'error'}`);
  },
  onLeave() {},
};

const hookLuaLLoadbuffer: InvocationListenerCallbacks = {
  onEnter(args) {
    const [scripts, len, filename] = [args[1], args[2], args[3]];
    let length: number | null = null;
    let path: string | null = null;
    let data: string | null = null;
    if (filename && `${scripts}` !== `${filename}` && (path = filename.readCString())) {
      length = len.toUInt32();
    } else if ((data = scripts.readCString())) {
      path = `${createHash('sha256').update(data).digest('hex')}.lua`;
      length = data.length;
    }
    if (!length || !path) return;
    const result = dumpFile(scripts, length, path, 'cocos2dx');
    logger.info(`${path} ${result ? dim(Text.toByteSize(length)) : 'error'}`);
  },
  onLeave() {},
};

function dump(...targets: Cocos2dxOffset[]) {
  const notFoundId = setTimeout(
    () => logger.warn('10 seconds have passed and no cocos2dx methods were called yet'),
    10000,
  );
  Inject.afterInitArrayModule((module: Module) => {
    const evalStringAddresses: NativePointer[] = [];
    const xxteaAddresses: NativePointer[] = [];
    const setXxteaAdresses: NativePointer[] = [];
    for (const { name, fn_dump, fn_key, fn_set } of targets) {
      if (name === module.name) {
        if (fn_dump) evalStringAddresses.push(module.base.add(fn_dump));
        if (fn_key) xxteaAddresses.push(module.base.add(fn_key));
        if (fn_set) setXxteaAdresses.push(module.base.add(fn_set));
      }
    }

    if (Number.parseInt(Frida.version.split('.')[0]) <= 15) {
      evalStringAddresses.push(...hookLegacy());
    } else {
      let hookTemp = module.findExportByName('_ZN2se12ScriptEngine10evalStringEPKclPNS_5ValueES2_');
      hookTemp ??= module.findExportByName('_ZN2se12ScriptEngine10evalStringEPKcjPNS_5ValueES2_');
      hookTemp ??= module.findExportByName('_ZN2se12ScriptEngine10evalStringEPKciPNS_5ValueES2_');
      hookTemp && evalStringAddresses.push(hookTemp);
    }
    for (const address of evalStringAddresses) {
      logger.info(`evalString: ${module.name} ${addressOf(address)}`);
      Interceptor.attach(address, hookEvalString);
    }

    // luad load buffer
    const lual = module.findExportByName('luaL_loadbuffer');
    if (lual) {
      logger.info(`luaL_loadbuffer: ${module.name} ${addressOf(lual)}`);
      Interceptor.attach(lual, hookLuaLLoadbuffer);
    }

    // xxtea decrypt
    // Lua key+sig pair
    let realKeySize = 0;
    let signSize = 0;

    const xxteaCryptDecrypt = module.findExportByName('_ZNK10XXTeaCrypt7decryptERKN7cocos2d4DataEPS1_');
    if (xxteaCryptDecrypt) {
      logger.info(`xxtea_crypt_decrypt: ${module.name} ${addressOf(xxteaCryptDecrypt)}`);
      Interceptor.attach(xxteaCryptDecrypt, {
        onEnter(args) {
          const key = args[0].add(Process.pointerSize === 4 ? 0x4 : 0x8).readCString();
          const sign = args[0].add(Process.pointerSize === 4 ? 0x10 : 0x20).readCString();
          logger.info({ id: 'xxtea_crypt_decrypt' }, `key -> ${key} sign -> ${sign}`);
          realKeySize = `${key}`.length - 1;
          signSize = `${sign}`.length - 1;
        },
      });
    }

    const xxteaKeyAndSign = module.findExportByName('_ZN7cocos2d8LuaStack18setXXTEAKeyAndSignEPKciS2_i');
    if (xxteaKeyAndSign) {
      logger.info(`xxtea_key_and_sign: ${module.name} ${addressOf(xxteaKeyAndSign)}`);
      Interceptor.attach(xxteaKeyAndSign, {
        onEnter(args) {
          const keylen = Math.min(args[2].toUInt32(), 16);
          const siglen = args[4].toUInt32();
          logger.info(
            { id: 'xxtea_key_and_sign' },
            `key -> ${args[1].readCString(keylen)} sign -> ${args[3].readCString(siglen)}`,
          );
          signSize = siglen;
        },
      });
    }

    const xxteaKeyAndSign1 = module.findExportByName('_ZN7cocos2d5extra6Crypto12decryptXXTEAEPhiS2_iPi');
    if (xxteaKeyAndSign1) {
      logger.info(`xxtea_key_and_sign1: ${module.name} ${addressOf(xxteaKeyAndSign1)}`);
      Interceptor.attach(xxteaKeyAndSign1, {
        onEnter(args) {
          const key = args[1].readCString();
          const sign = args[2].readCString();
          logger.info({ id: 'xxtea_key_and_sign1' }, `key -> ${key} sign -> ${sign}`);
          signSize = `${sign}`.length - 1;
        },
      });
    }
    const xxteaKeyAndSign2 = module.findExportByName('_ZN7cocos2d8LuaStack18setXXTEAKeyAndSignEPKcS2_');
    if (xxteaKeyAndSign2) {
      logger.info(`xxtea_key_and_sign2: ${module.name} ${addressOf(xxteaKeyAndSign2)}`);
      Interceptor.attach(xxteaKeyAndSign2, {
        onEnter(args) {
          const key = args[0].readCString();
          const sign = args[1].readCString();
          logger.info({ id: 'xxtea_key_and_sign2' }, `key -> ${key} sign -> ${sign}`);
          signSize = `${sign}`.length - 1;
        },
      });
    }
    const xxteaKeyAndSign3 = module.findExportByName('_ZN7cocos2d5extra6Crypto15decryptXXTEALuaEPKciS3_i');
    if (xxteaKeyAndSign3) {
      logger.info(`xxtea_key_and_sign3: ${module.name} ${addressOf(xxteaKeyAndSign3)}`);
      Interceptor.attach(xxteaKeyAndSign3, {
        onEnter(args) {
          const key = args[0].readCString();
          const sign = args[1].readCString();
          logger.info({ id: 'xxtea_key_and_sign3' }, `key -> ${key} sign -> ${sign}`);
          signSize = `${sign}`.length - 1;
        },
      });
    }

    const xxteaResourcesDecode = module.findExportByName('_ZN15ResourcesDecode11setXXTeaKeyEPKciS1_i');
    if (xxteaResourcesDecode) {
      logger.info(`xxtea_resources_decode: ${module.name} ${addressOf(xxteaResourcesDecode)}`);
      Interceptor.attach(xxteaResourcesDecode, {
        onEnter(args) {
          const keylen = Math.min(args[2].toUInt32(), 16);
          const siglen = Math.min(args[4].toUInt32(), 16);
          logger.info(
            { id: 'xxtea_resources_decode' },
            `key -> ${args[1].readCString(keylen)} sign -> ${args[3].readCString(siglen)}`,
          );
        },
        onLeave() {},
      });
    }

    let xxtea_decrypt = module.findExportByName('_Z13xxtea_decryptPhjS_jPj');
    xxtea_decrypt && xxteaAddresses.push(xxtea_decrypt);
    xxtea_decrypt = module.findExportByName('xxtea_decrypt');
    xxtea_decrypt && xxteaAddresses.push(xxtea_decrypt);
    for (const address of xxteaAddresses) {
      logger.info(`xxtea_decrypt: ${module.name} ${addressOf(address)}`);

      // no idea why this often crashes
      try {
        Interceptor.attach(address, {
          onEnter: (args) => {
            logger.info(
              { id: 'xxtea_decrypt' },
              `key -> ${args[2].readCString(Math.min(args[3].toUInt32(), 16))}`,
            );
          },
          onLeave: () => {},
        });
      } catch (e) {
        logger.warn(`could not attach to xxtea_decrypt at ${address}`);
      }
    }

    // New methods for hooking
    const getLuaStack = module.findExportByName('_ZN7cocos2d9LuaEngine11getLuaStackEv');
    if (getLuaStack) {
      logger.info(`get_lua_stack: ${module.name} ${addressOf(getLuaStack)}`);

      let isHooked = false;
      Interceptor.attach(getLuaStack, {
        onLeave: (retval) => {
          if (!isHooked) {
            isHooked = true;
            const nextAddr = retval.readPointer().add(0xe8).readPointer();
            Interceptor.attach(nextAddr, {
              onEnter: (args) => {
                const key = args[1].readCString(Math.min(args[2].toUInt32(), 16));
                const sign = args[3].readCString(args[4].toUInt32());
                logger.info({ id: 'get_lua_stack' }, `key -> ${key} sign -> ${sign}`);
              },
            });
          }
        },
      });
    }

    const getLuaEngine = module.findExportByName('_ZN7cocos2d9LuaEngine11getInstanceEv');
    if (getLuaEngine) {
      logger.info(`get_lua_engine: ${module.name} ${addressOf(getLuaEngine)}`);

      let isHooked = false;
      Interceptor.attach(getLuaEngine, {
        onLeave: (retval) => {
          if (!isHooked) {
            isHooked = true;
            logger.info({ id: 'get_lua_engine' }, `return -> ${retval}`);
            // const nextAddr = retval.add(0x4).readPointer().readPointer().add(0x74).readPointer();
            // Interceptor.attach(nextAddr, {
            //     onEnter: function (args) {
            //         logger.info({ id: 'get_lua_engine' }, `key -> ${args[1].readCString()} sign -> ${args[2].readCString()}`);
            //     },
            // });
          }
        },
      });
    }

    // AES  encryption
    const setEncryption = module.findExportByName(
      '_ZN14EncryptManager17setEncryptEnabledEbN5cxx1717basic_string_viewIcNSt6__ndk111char_traitsIcEEEES5_i',
    );
    setEncryption &&
      Interceptor.attach(setEncryption, {
        onEnter: (args) => {
          logger.info('AES Encryption');
          logger.info('Key:');
          logger.info(
            hexdump(args[0].add(Process.pointerSize === 4 ? 0x10 : 0x20), {
              length: 32,
              ansi: true,
            }),
          );
          logger.info('IV:');
          logger.info(hexdump(args[4], { length: 16, ansi: true }));
          logger.info(`Flags -> ${args[5]}`);
        },
      });

    // TODO refactor this
    for (const offset of setXxteaAdresses) {
      let ptr: NativePointer | null = null;
      let addr: NativePointer | null = null;
      try {
        ptr = module.base.add(offset);
        addr = ptr.readPointer();
        logger.info(`set_xxtea_key: ${module.name} ${addressOf(addr)}`);
        Interceptor.attach(addr, {
          onEnter(args) {
            logger.info({ id: 'set_xxtea_key' }, new Std.String(args[1]).disposeToString());
          },
        });
      } catch (e) {
        logger.warn(`could not attach to set_xxtea_key at ${ptr} -> ${addr}`);
      }
    }

    if (evalStringAddresses.length > 0 || lual || xxteaAddresses.length > 0) {
      clearTimeout(notFoundId);
    }
  });
}

function replace(address: NativePointer, libname: string) {
  let isDone = false;
  Inject.afterInitArrayModule((module: Module) => {
    if (module.name === libname && !isDone) {
      const ptr = module.base.add(address);
      Interceptor.attach(ptr, {
        onEnter(this, args) {
          const data = `${args[1].readCString()}`;

          for (let pos = 0, ind = 0; (ind = data.indexOf('isCashGame = 2 == t', pos)) > 0; pos += ind + 1) {
            //@ts-ignore
            const newby = File.readAllBytes('/data/data/net.fierce.poker.arena/files/sample');
            args[1] = newby;
            args[3] = newby.length;
          }
        },
      });
      isDone = true;
    }
  });
}

export { dump, replace };
