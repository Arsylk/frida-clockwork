import { getLogger } from './logger.js';
import { isJWrapper, findClass } from '@clockwork/common';
import { logger } from '@clockwork/logging';
import { HookParameters } from './types.js';

function hook(clazzOrName: Java.Wrapper | string, methodName: string, params: HookParameters = {}): void {
    const { before, replace, after, logging, loggingPredicate } = params;
    const logger = getLogger(logging);

    const clazz: Java.Wrapper = isJWrapper(clazzOrName) ? clazzOrName : Java.use(clazzOrName);
    const method: Java.MethodDispatcher & { _o: any[] } = clazz[methodName];

    if (`${typeof method}` !== 'function') {
        throw Error(`hook: method ${methodName} not found in ${clazz} !`);
    }

    const overloads = method._o;
    const classString = clazz.$className;
    logger.printHookClass(classString);

    for (let i = 0; i < overloads.length; i++) {
        const overload = overloads[i];
        if (params?.predicate?.(overload, i) === false) continue;

        const { argumentTypes }: { argumentTypes: any[] } = overload;
        const argTypesString: string[] = argumentTypes.map((t) => t.className);
        const returnTypeString = overload.returnType.className;
        logger.printHookMethod(methodName, argTypesString, returnTypeString);

        const methodDef: Java.Method = method.overload(...argTypesString);
        methodDef.implementation = function (...params: any[]) {
            const doLog = loggingPredicate ? loggingPredicate.call(this, methodDef, ...params) : true;
            doLog && logger.printCall(classString, methodName, params, returnTypeString, replace !== undefined);

            before?.call(this, methodDef, ...params);
            const returnValue: any | undefined = replace ? replace.call(this, methodDef, ...params) : methodDef.call(this, ...params);
            after?.call(this, methodDef, returnValue, ...params);

            if (returnTypeString !== 'void') doLog && logger.printReturn(returnValue);

            return returnValue;
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

function getHookUnique() {
    const found = new Set<string>();

    return (clazzName: string, methodName: string, params: HookParameters = {}) => {
        const clazz = findClass(clazzName);
        if (!clazz) {
            logger.info({ tag: 'hookUnique' }, `class ${clazzName} not found !`);
            return;
        }

        const ptr = `${clazz.$l.handle}::${methodName}`;
        if (!found.has(ptr)) {
            found.add(ptr);
            hook(clazz, methodName, params);
        }
    };
}

export { hook, findHook, getHookUnique };
