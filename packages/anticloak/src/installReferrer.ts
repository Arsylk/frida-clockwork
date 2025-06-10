import type Java from 'frida-java-bridge';
import { Classes, ClassesString, enumerateMembers, findClass } from '@clockwork/common';
import { ClassLoader, hook } from '@clockwork/hooks';
import type { MethodHookPredicate } from '@clockwork/hooks/dist/types';
import { Color, subLogger } from '@clockwork/logging';
const logger = subLogger('installreferrer');

interface ReferrerDetails {
    google_play_instant?: boolean;
    install_begin_timestamp_seconds?: number;
    install_begin_timestamp_server_seconds?: number;
    install_referrer?: string;
    install_version?: string;
    referrer_click_timestamp_seconds?: number;
    referrer_click_timestamp_server_seconds?: number;
}

function createInstallReferrer(classWrapper: Java.Wrapper, details: ReferrerDetails): Java.Wrapper {
    const now = Date.now() / 1000;
    const off = (int: number) => Math.round(Math.random() * int);
    const bundle = Classes.Bundle.$new();
    bundle.putBoolean('google_play_instant', details?.google_play_instant ?? true);
    bundle.putLong(
        'install_begin_timestamp_seconds',
        details?.install_begin_timestamp_seconds ?? now - off(30),
    );
    bundle.putLong(
        'install_begin_timestamp_server_seconds',
        details?.install_begin_timestamp_server_seconds ?? now - off(30),
    );
    bundle.putString('install_referrer', details?.install_referrer ?? 'utm_medium=Non-Organic');
    bundle.putString('install_version', details?.install_version ?? '1.0.0');
    bundle.putLong(
        'referrer_click_timestamp_seconds',
        details?.referrer_click_timestamp_seconds ?? now - off(65),
    );
    bundle.putLong(
        'referrer_click_timestamp_server_seconds',
        details?.referrer_click_timestamp_server_seconds ?? now - off(65),
    );
    return classWrapper.$new(bundle);
}

function replace(details: ReferrerDetails = {}) {
    let isHooked = false;
    ClassLoader.perform((_) => {
        if (isHooked) return;

        const client = findClass(ClassesString.InstallReferrerClient);
        if (!client) return;
        isHooked = true;

        performReplace(details, client);
    });
}

function performReplace(details: ReferrerDetails, client: Java.Wrapper) {
    let isFinished = false;
    const beforeInit = function (this: Java.Wrapper) {
        const paretnClass = findClass(this.$className);
        if (!paretnClass) {
            logger.warn(`missing parent class: ${this.$className}`);
            return;
        }
        const [startMethod, getMethod] = matchReferrerClientMethods(paretnClass);
        logger.info({ tag: 'ref' }, `startConnection:  ${startMethod} getInstallReferrer: ${getMethod}`);

        hook(paretnClass, startMethod, {
            predicate: startConnectionPredicate,
            replace(method, listener) {
                const listenerClass = findClass(listener.$className);
                if (!listenerClass) {
                    logger.warn(`missing listener class: ${listener.$className}`);
                    return method.call(this, listener);
                }

                const onFinishedMethod = matchStateListenerMethod(listenerClass);
                logger.info({ tag: 'ref' }, `onInstallReferrerSetupFinished:  ${onFinishedMethod}`);

                let msg = Color.method(startMethod);
                msg += Color.bracket('(');
                msg += Color.className(listener?.$className);
                msg += Color.bracket(')');
                msg += ' -> ';
                msg += Color.method(onFinishedMethod);
                msg += `${Color.bracket('(')}${Color.number('0')}${Color.bracket(')')}`;
                logger.info(msg);

                hook(listenerClass, onFinishedMethod, {
                    replace(method, ...args) {
                        if (isFinished) return;
                        isFinished = true;
                    },
                });

                listener?.[onFinishedMethod]?.(0);
            },
        });

        hook(paretnClass, getMethod, {
            predicate: getInstallReferrerPredicate,
            replace(method) {
                const referrerDetails = findClass(ClassesString.ReferrerDetails);
                if (!referrerDetails) {
                    logger.warn(`missing referrer class: ${ClassesString.ReferrerDetails}`);
                    return method.call(this);
                }

                enumerateMembers(
                    referrerDetails,
                    {
                        onMatchMethod(clazz, member) {
                            hook(clazz, member);
                        },
                    },
                    1,
                );

                return createInstallReferrer(referrerDetails, details);
            },
        });
    };

    hook(client, '$init', { before: beforeInit });
}

function matchReferrerClientMethods(clazz: Java.Wrapper): [string, string] {
    let startMethod: string | null = null;
    let getMethod: string | null = null;
    enumerateMembers(
        clazz,
        {
            onMatchMethod(clazz, member) {
                const def: Java.MethodDispatcher = clazz[member];
                if (!def) return;
                for (const [i, overload] of def.overloads.entries()) {
                    logger.info({ tag: 'ref start and get' }, `${overload}`);
                    if (startConnectionPredicate(overload, i)) {
                        logger.info({ tag: 'ref start connection' }, 'found');
                        startMethod ??= member;
                        continue;
                    }

                    if (getInstallReferrerPredicate(overload, i)) {
                        logger.info({ tag: 'ref get isntall referrer' }, 'found');
                        getMethod ??= member;
                    }
                }
            },
        },
        1,
    );

    return [startMethod ?? 'startConnection', getMethod ?? 'getInstallReferrer'];
}

function matchStateListenerMethod(clazz: Java.Wrapper): string {
    let found: string | null = null;
    enumerateMembers(
        clazz,
        {
            onMatchMethod(clazz, member) {
                const def: Java.MethodDispatcher = clazz[member];
                if (!def) return;
                for (const [i, overload] of def.overloads.entries()) {
                    logger.info({ tag: 'ref setupfinished' }, `${overload}`);
                    if (onInstallReferrerSetupFinishedPredicate(overload, i)) {
                        logger.info({ tag: 'ref setupfinished' }, 'found');
                        found ??= member;
                        return;
                    }
                }
            },
        },
        1,
    );

    return found ?? 'onInstallReferrerSetupFinished';
}

const startConnectionPredicate: MethodHookPredicate = ({ returnType, argumentTypes }) => {
    const listener = findClass(ClassesString.InstallReferrerStateListener);
    const argClass = argumentTypes[0]?.className && findClass(argumentTypes[0].className);
    console.log(argClass);
    return (
        listener?.class &&
        argClass &&
        returnType.className === 'void' &&
        argumentTypes.length === 1 &&
        listener.class.isAssignableFrom(argClass.class)
    );
};
const getInstallReferrerPredicate: MethodHookPredicate = ({ returnType, argumentTypes }) => {
    return returnType.className === ClassesString.ReferrerDetails && argumentTypes.length === 0;
};
const onInstallReferrerSetupFinishedPredicate: MethodHookPredicate = ({ returnType, argumentTypes }) => {
    return (
        returnType.className === 'void' && argumentTypes.length === 1 && argumentTypes[0].className === 'int'
    );
};

export { createInstallReferrer, replace };
