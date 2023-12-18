import { createHash } from 'crypto';
import { Inject, dumpFile } from '@clockwork/native';
import { Text } from '@clockwork/common';
import { Color, subLogger } from '@clockwork/logging';
const { red, dim, blue } = Color.use();
const logger = subLogger('cocos2dx');

type Cocos2dxOffset = { name: string; fn_dump?: NativePointer; fn_key?: NativePointer };

function hookLegacy(): NativePointer[] {
    //@ts-ignore
    const array = Module.enumerateExportsSync(libname).filter(({ name }) => name.includes('evalString' && name.includes('ScriptEngine')));
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
        const [_, scripts, len, a4, filename] = [args[0], args[1], args[2], args[3], args[4]];
        let length: number | null = null;
        let path: string | null = null;
        let data: string | null = null;
        if (filename && (path = filename.readCString())) {
            length = len.toUInt32();
        } else if ((data = scripts.readCString())) {
            path = createHash('sha256').update(data).digest('hex') + '.js';
            length = data.length;
        }
        if (!length || !path) return;
        const result = dumpFile(scripts, length, path, 'cocos2dx');
        logger.info(`${path} ${result ? dim(Text.toByteSize(length)) : 'error'}`);
    },
    onLeave(retval) {},
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
            path = createHash('sha256').update(data).digest('hex') + '.lua';
            length = data.length;
        }
        if (!length || !path) return;
        const result = dumpFile(scripts, length, path, 'cocos2dx');
        logger.info(`${path} ${result ? dim(Text.toByteSize(length)) : 'error'}`);
    },
    onLeave(retval) {},
};

function dump(...targets: Cocos2dxOffset[]) {
    const notFoundId = setTimeout(() => logger.warn('10 seconds have passed and no cocos2dx methods were called yet'), 10000);
    Inject.afterInitArrayModule((module: Module) => {
        const evalStringAddresses: NativePointer[] = [];
        const xxteaAddresses: NativePointer[] = [];
        targets.forEach(({ name, fn_dump, fn_key }) => {
            if (fn_dump && name === module.name) {
                evalStringAddresses.push(module.base.add(fn_dump));
            }
            if (fn_key && name === module.name) {
                xxteaAddresses.push(module.base.add(fn_key));
            }
        });

        if (parseInt(Frida.version.split('.')[0]) <= 15) {
            evalStringAddresses.push(...hookLegacy());
        } else {
            let hookTemp = module.findExportByName('_ZN2se12ScriptEngine10evalStringEPKclPNS_5ValueES2_');
            hookTemp ??= module.findExportByName('_ZN2se12ScriptEngine10evalStringEPKcjPNS_5ValueES2_');
            hookTemp ??= module.findExportByName('_ZN2se12ScriptEngine10evalStringEPKciPNS_5ValueES2_');
            hookTemp && evalStringAddresses.push(hookTemp);
        }
        evalStringAddresses.forEach((address) => {
            logger.info(`evalString ${module.name} ${DebugSymbol.fromAddress(address)}`);
            Interceptor.attach(address, hookEvalString);
        });

        // luad load buffer
        const lual = module.findExportByName('luaL_loadbuffer');
        if (lual) {
            logger.info(`luaL_loadbuffer ${module.name} ${DebugSymbol.fromAddress(lual)}`);
            Interceptor.attach(lual, hookLuaLLoadbuffer);
        }

        // xxtea decrypt
        const xxtea_decrypt = module.findExportByName('_Z13xxtea_decryptPhjS_jPj');
        xxtea_decrypt && xxteaAddresses.push(xxtea_decrypt);
        xxteaAddresses.forEach((address) => {
            logger.info(`xxtea_decrypt ${module.name} ${DebugSymbol.fromAddress(address)}`);
            Interceptor.attach(address, {
                onEnter: function (args) {
                    logger.info('key -> ' + args[2].readCString(Math.min(args[3].toUInt32(), 16)));
                },
                onLeave: function (retval) {},
            });
        });

        if (evalStringAddresses.length > 0 || lual || xxteaAddresses.length > 0) {
            clearTimeout(notFoundId);
        }
    });
}

export { dump };
