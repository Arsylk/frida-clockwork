import { findClass, Classes, ClassesString } from '@clockwork/common';
import { ClassLoader, hook } from '@clockwork/hooks';
import { subLogger, Color } from '@clockwork/logging';
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
    const now = Date.now();
    const bundle = Classes.Bundle.$new();
    bundle.putBoolean('google_play_instant', details?.google_play_instant ?? true);
    bundle.putLong('install_begin_timestamp_seconds', details?.install_begin_timestamp_seconds ?? now - 30 * 1000);
    bundle.putLong('install_begin_timestamp_server_seconds', details?.install_begin_timestamp_server_seconds ?? now - 30 * 1000);
    bundle.putString('install_referrer', details?.install_referrer ?? 'utm_medium=non-organic');
    bundle.putString('install_version', details?.install_version ?? '1.0.0');
    bundle.putLong('referrer_click_timestamp_seconds', details?.referrer_click_timestamp_seconds ?? now - 65 * 1000);
    bundle.putLong('referrer_click_timestamp_server_seconds', details?.referrer_click_timestamp_server_seconds ?? now - 65 * 1000);
    return classWrapper.$new(bundle);
}

function replace(details: ReferrerDetails = {}) {
    const beforeInit = function (this: Java.Wrapper) {
        const paretnClass = findClass(this.$className);
        if (!paretnClass) {
            logger.warn(`missing parent class: ${this.$className}`);
            return;
        }

        hook(paretnClass, 'startConnection', {
            replace(_, listener) {
                let msg = Color.method('startConnection');
                msg += Color.bracket('(')
                msg += Color.className(listener.$className)
                msg += Color.bracket(')')
                msg += ' -> '
                msg += Color.method('onInstallReferrerSetupFinished')
                msg += `${Color.bracket('(')}0${Color.bracket(')')}`
                logger.info(msg);
                listener.onInstallReferrerSetupFinished(0);
            },
        });

        hook(paretnClass, 'getInstallReferrer', {
            replace(method) {
                const referrerDetails = findClass(ClassesString.ReferrerDetails);
                if (!referrerDetails) {
                    logger.warn(`missing referrer class: ${ClassesString.ReferrerDetails}`);
                    return method.call(this);
                }
                hook(referrerDetails, 'getInstallReferrer')
                return createInstallReferrer(referrerDetails, details);
            },
        });
    };

    let isHooked = false;
    ClassLoader.perform((_) => {
        if (isHooked) return;
        const client = findClass(ClassesString.InstallReferrerClient);
        if (client) {
            isHooked = true;
            hook(client, '$init', { before: beforeInit });
        }
    });
}

export { replace };
