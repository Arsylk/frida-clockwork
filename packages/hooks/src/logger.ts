import { Classes, ClassesString, Text, isIterable, stacktraceList, vs } from '@clockwork/common';
import type { OmitFirstArg } from '@clockwork/common/src/types.js';
import { Color, logger } from '@clockwork/logging';
import type { LoggerOptions } from './types.js';
const { black, gray, red, green, cyan, dim, italic, bold, yellow, hidden } = Color.use();

type ILogger = {
    printHookClass(className: string, logId: string): void;

    printHookMethod(methodName: string, argTypes: string[], returnType: string, logId: string): void;

    printCall(
        className: string,
        methodName: string,
        argValues: any[],
        argTypes: string[],
        returnType: string,
        logId: string,
        isReplaced: boolean,
    ): void;

    printReturn(returnValue: any, returnType: string, logId: string): void;
};

const DEFAULT_LOGGER_OPTIONS: LoggerOptions = {
    spacing: '   ',
    arguments: true,
    return: true,
    multiline: true,
    short: false,
    call: true,
    hook: true,
    enable: true,
};

const HOOK_LOGGER = {
    mapMethod(config: LoggerOptions, name: string): string {
        return Color.method(name);
    },

    mapClass(config: LoggerOptions, className: string): string {
        let type = Text.toPrettyType(className);
        let array = '';
        const index = type.indexOf('[');
        if (index !== -1) {
            array = dim(yellow(type.substring(index)));
            type = type.substring(0, index);
        }
        const splits: string[] = type.split('.');
        if (config.short) return Color.className(splits[splits.length - 1]) + array;
        return splits.map(Color.className).join('.') + array;
    },

    mapValue(arg: any, type?: string): string {
        const pretty = type ? Text.toPrettyType(type) : type;
        return vs(arg, pretty);
    },

    mapArgs(config: LoggerOptions, args: any[], types?: string[]): string {
        if (!isIterable(args) || !args.length || args.length === 0) return '';
        if (!config.arguments) return gray('...');
        const joinBy = config.multiline ? ', \n' : ', ';
        const joined = args
            .map((arg: any, i: number) => {
                let value = arg;
                let type = types?.[i] ?? null;
                const result = config.transform?.(value, type, i) ?? null;
                if (result && isIterable(result)) {
                    const [newarg, newtype] = result;
                    if (newarg !== undefined) value = newarg;
                    if (newtype !== undefined) type = newtype;
                }
                const visual = this.mapValue(value, type ?? undefined);
                return `${config.multiline ? config.spacing : ''}${visual}`;
            })
            .join(joinBy);

        return config.multiline ? `\n${joined}\n` : joined;
    },

    printHookClass(config: LoggerOptions, className: string, logId: string) {
        if (!config.hook) return;

        let sb = '';
        sb += bold('Hooking');
        sb += ' ';
        sb += this.mapClass(config, className);

        this.logInfo(sb, logId);
    },

    printHookMethod(
        config: LoggerOptions,
        methodName: string,
        argTypes: string[],
        returnType: string,
        logId: string,
    ) {
        if (!config.hook) return;

        let sb = '';
        sb += black(dim('  >'));
        sb += this.mapMethod(config, methodName);
        sb += Color.bracket('(');
        sb += argTypes.map((argType) => this.mapClass(config, argType)).join(', ');
        sb += Color.bracket(')');
        sb += ': ';
        sb += this.mapClass(config, returnType);

        this.logInfo(sb, logId);
    },

    printCall(
        config: LoggerOptions,
        className: string,
        methodName: string,
        argValues: any[],
        argTypes: string[],
        returnType: string,
        logId: string,
        isReplaced = false,
    ) {
        if (!config.call) return;

        let sb = '';
        // sb += dim(isReplaced ? italic('replace') : 'call');
        // sb += ' ';
        if (methodName !== '$init') {
            sb += this.mapClass(config, className);
            sb += '::';
            sb += this.mapMethod(config, methodName);
            sb += Color.bracket('(');
            sb += this.mapArgs(config, argValues, argTypes);
            sb += Color.bracket(')');
            sb += ': ';
            sb += this.mapClass(config, returnType);
        } else {
            sb += gray('new');
            sb += ' ';
            sb += this.mapClass(config, className);
            sb += Color.bracket('(');
            sb += this.mapArgs(config, argValues, argTypes);
            sb += Color.bracket(')');
        }

        this.logInfo(sb, logId);
    },

    printReturn(config: LoggerOptions, returnValue: any, returnType: string, logId: string) {
        if (!config.return) return;

        const value = config.transform?.(returnValue, returnType, -1) ?? returnValue;

        let sb = '';
        sb += dim('return');
        sb += ' ';
        sb += `${this.mapValue(value, returnType)}`;

        this.logInfo(sb, logId);
    },

    mapLogId(logId: any): string {
        // janky support for kitty background, needs to be set per theme
        return ` \x1b[38;2;45;42;46m${hidden(logId)}\x1b[0m`;
    },

    logInfo(text: string, logId: string | null) {
        // fix line endings
        let sb = text.replaceAll(/\r\n?$/gm, '\n');

        // append logId to all lines
        if (logId) {
            sb = sb.replaceAll(/$/gm, `${this.mapLogId(logId)}`);
        }

        logger.info(sb);
    },
};

const HOOK_LOGGER_JSON = {
    mapMethod(name: string): string {
        return name;
    },

    mapClass(className: string): string {
        let type = Text.toPrettyType(className);
        let array = '';
        const index = type.indexOf('[');
        if (index !== -1) {
            array = type.substring(index);
            type = type.substring(0, index);
        }
        const splits: string[] = type.split('.');
        return splits.join('.') + array;
    },

    mapValue(arg: any): string | null {
        if (
            typeof arg === 'string' ||
            typeof arg === 'boolean' ||
            typeof arg === 'number' ||
            arg?.$className === ClassesString.String
        ) {
            return `${arg}`;
        }
        if (arg === null || arg === undefined) {
            return null;
        }

        if (typeof arg === 'object' && arg?.$className === undefined)
            try {
                //@ts-ignore
                return Classes.Arrays.toString(arg);
            } catch (_) {}
        try {
            //@ts-ignore
            return Classes.String.valueOf(arg);
        } catch (e) {
            return `${arg}@${typeof arg}`;
        }
    },

    printHookClass(className: string, logId: string) {
        const msg = JSON.stringify({
            t: 'jvmclass',
            cn: this.mapClass(className),
            id: logId,
        });
        logger.info(msg);
    },

    printHookMethod(methodName: string, argTypes: string[], returnType: string, logId: string) {
        const msg = JSON.stringify({
            t: 'jvmmethod',
            mn: this.mapMethod(methodName),
            a: argTypes.map((argType) => this.mapClass(argType)),
            r: this.mapClass(returnType),
            id: logId,
        });
        logger.info(msg);
    },

    printCall(
        className: string,
        methodName: string,
        argValues: any[],
        argTypes: string[],
        returnType: string,
        logId: string,
        isReplaced = false,
    ) {
        const msg = JSON.stringify({
            t: 'jvmcall',
            cn: this.mapClass(className),
            mn: this.mapMethod(methodName),
            id: logId,
            av: argValues.map((arg) => this.mapValue(arg)),
            st: stacktraceList(),
        });
        logger.info(msg);
    },

    printReturn(returnValue: any, returnType: string, logId: string) {
        const msg = JSON.stringify({
            t: 'jvmreturn',
            id: logId,
            rv: this.mapValue(returnValue),
        });
        logger.info(msg);
    },
};

function getPrettyLogger(options?: Partial<LoggerOptions>): {
    [key in keyof typeof HOOK_LOGGER]: OmitFirstArg<(typeof HOOK_LOGGER)[key]>;
} {
    const opt = options ? { ...DEFAULT_LOGGER_OPTIONS, ...options } : DEFAULT_LOGGER_OPTIONS;
    return Object.assign(
        {},
        ...Object.entries(HOOK_LOGGER).map(([key, func]: [any, any]) => ({
            [key]: (...args: any[]) => func.call(HOOK_LOGGER, opt, ...args),
        })),
    );
}

function getJsonLogger() {
    return HOOK_LOGGER_JSON;
}

function getLogger(options?: Partial<LoggerOptions>): ILogger {
    return getPrettyLogger(options);
    // return getJsonLogger()
}

export { getLogger };
