import Java from 'frida-java-bridge';
import { type JavaArgument, findClass, isJWrapper } from '@clockwork/common';
import { logger } from '@clockwork/logging';
import { Ids } from './ids.js';
import { getLogger } from './logger.js';
import type { HookParameters } from './types.js';

function hook(clazzOrName: Java.Wrapper | string, methodName: string, params: HookParameters = {}): void {
    const { before, replace, after, logging, loggingPredicate } = params;
    const logger = getLogger(logging);

    const clazz: Java.Wrapper = isJWrapper(clazzOrName) ? clazzOrName : Java.use(clazzOrName);
    const method: Java.MethodDispatcher = clazz[methodName];

    if (`${typeof method}` !== 'function') {
        throw Error(`hook: method ${methodName} not found in ${clazz} !`);
    }

    const overloads = method.overloads;
    const classString = clazz.$className;

    const cId = Ids.genClassId(classString);
    const mId = Ids.genMethodId(classString, methodName);
    logger.printHookClass(classString, Ids.classId(cId));

    for (let i = 0; i < overloads.length; i++) {
        const overload = overloads[i];
        if (params?.predicate?.(overload, i) === false) continue;

        const logId = Ids.uniqueId(cId, mId, i);
        const { argumentTypes, returnType } = overload;
        const argTypesString: string[] = argumentTypes.map((t) => t.className ?? t.name);
        const returnTypeString = returnType.className ?? returnType.name;
        const methodDef: Java.Method = method.overload(...argTypesString);
        logger.printHookMethod(methodName, argTypesString, returnTypeString, logId);

        methodDef.implementation = function (...params: JavaArgument[]) {
            const doLog = loggingPredicate?.call(this, methodDef, ...params) ?? true;
            doLog &&
                logger.printCall(
                    classString,
                    methodName,
                    params,
                    argTypesString,
                    returnTypeString,
                    logId,
                    replace !== undefined,
                );

            before?.call(this, methodDef, ...params);
            const retval = replace?.call(this, methodDef, ...params) ?? methodDef.call(this, ...params);
            after?.call(this, methodDef, retval, ...params);

            if (returnTypeString !== 'void') doLog && logger.printReturn(retval, returnTypeString, logId);

            return retval;
        };
    }
}

function findHook(clazzName: string, methodName: string, params: HookParameters) {
    const clazz = findClass(clazzName);
    if (!clazz) {
        logger.debug({ tag: 'findHook' }, `class ${clazzName} not found !`);
        return;
    }
    hook(clazz, methodName, params);
}

function getHookUnique(logging = true) {
    const found = new Set<string>();

    return (clazzName: string, methodName: string, params: HookParameters = {}) => {
        const clazz = findClass(clazzName);
        if (!clazz) {
            logging && logger.info({ tag: 'hookUnique' }, `class ${clazzName} not found !`);
            return;
        }

        const ptr = `${clazz.$l.handle}::${methodName}`;
        if (!found.has(ptr)) {
            found.add(ptr);
            hook(clazz, methodName, params);
        }
    };
}

export { findHook, getHookUnique, hook };
