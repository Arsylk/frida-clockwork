import { ClassLoader, findHook, getHookUnique } from '@clockwork/hooks';
import * as Anticloak from '@clockwork/anticloak';
import * as Network from '@clockwork/network';
import * as Native from '@clockwork/native';
import * as JniTrace from '@clockwork/jnitrace';
import * as Cocos2dx from '@clockwork/cocos2dx';
import * as Unity from '@clockwork/unity';
import { hook } from '@clockwork/hooks';
import { Text, Classes, Libc, enumerateMembers, findClass, stacktrace } from '@clockwork/common';
import { log, logger, Color } from '@clockwork/logging';
import { always, ifKey, ifReturn } from '@clockwork/hooks/dist/addons';
import { dumpFile, gPtr } from '@clockwork/native';
import { createHash } from 'crypto';
const uniqHook = getHookUnique();
const { blue, blueBright, redBright, magentaBright: pink } = Color.use();

function hookActivity() {
    hook(Classes.Activity, '$init', {
        after() {
            console.warn(`$init: ${this}`);
        },
    });
    hook(Classes.Activity, 'onCreate', {
        after() {
            console.warn(` onCreate: ${this}`);
        },
        logging: { arguments: false },
    });
    hook(Classes.Activity, 'onResume', {
        after() {
            console.warn(`  onResume: ${this}`);
        },
        logging: { arguments: false },
    });
}

function hookWebview() {
    hook(Classes.WebView, 'evaluateJavascript');
    hook(Classes.WebView, 'loadDataWithBaseURL');
    hook(Classes.WebView, 'loadUrl');
}

function hookCrypto() {
    //  hook(Classes.SecretKeySpec, '$init', {
    //     logging: { multiline: false },
    // });
    // hook(JTypes.Cipher, 'getInstance');
    hook(Classes.Cipher, 'doFinal', {
        after(m, r, ...p) {
            if (this.opmode.value === 1) {
                const str = Classes.String.$new(p[0]);
                log(`[${blueBright('encrypt')}] ${str}`);
            }
            if (this.opmode.value === 2) {
                try {
                    const str = Classes.String.$new(r);
                    log(`[${redBright('decrypt')}] ${str}`);
                } catch (e) {
                    log(`[${redBright('decrypt')}] ${r}`);
                }
            }
        },
        logging: { arguments: false, return: false },
    });
}

function hookJson(fn?: (key: string, method: string) => any) {
    const lp = () => {
        const trace = stacktrace();
        if (trace.includes('at com.google.firebase.installations.local.PersistedInstallation')) {
            return false;
        }
        if (trace.includes('at com.unity3d.services.core.configuration.PrivacyConfigurationLoader')) {
            return false;
        }
        return true;
    };

    const getOpt = ['get', 'opt'];

    hook(Classes.JSONObject, '$init', {
        loggingPredicate: lp,
        predicate: (_, index) => index !== 0 && index !== 4,
    });

    for (const pre of getOpt) {
        const mKey = `${pre}JSONObject`;
        hook(Classes.JSONObject, mKey, {
            loggingPredicate: lp,
            replace: ifKey(function (key) {
                switch (key) {
                }
                return fn?.(key, mKey);
            }),
        });
    }
    for (const pre of getOpt) {
        const mKey = `${pre}Int`;
        hook(Classes.JSONObject, mKey, {
            loggingPredicate: lp,
            replace: ifKey(function (key) {
                switch (key) {
                }
                return fn?.(key, mKey);
            }),
        });
    }
    for (const pre of getOpt) {
        const mKey = `${pre}Boolean`;
        hook(Classes.JSONObject, mKey, {
            loggingPredicate: lp,
            replace: ifKey(function (key) {
                switch (key) {
                }
                return fn?.(key, mKey);
            }),
        });
    }

    for (const pre of getOpt) {
        const mKey = `${pre}String`;
        hook(Classes.JSONObject, mKey, {
            loggingPredicate: lp,
            replace: ifKey(function (key) {
                switch (key) {
                }
                return fn?.(key, mKey);
            }),
        });
    }

    hook(Classes.JSONObject, 'get', {
        loggingPredicate: lp,
        replace: ifKey(function (key) {
            switch (key) {
            }
            return fn?.(key, 'get');
        }),
    });
    // hook(Classes.JSONObject, 'put')
}

function hookPrefs() {
    const lp = () => {
        const trace = stacktrace();
        if (trace.includes('at com.facebook.internal.')) return false;
        if (trace.includes('at com.appsflyer.internal.')) return false;
        if (trace.includes('at com.onesignal.OneSignalPrefs.')) return false;
        if (trace.includes('at com.google.android.gms.internal.ads.')) return false;
        return true;
    };

    hook('android.app.SharedPreferencesImpl', 'getString', {
        loggingPredicate: lp,
        logging: { multiline: false },
        replace: ifKey((key) => {
            switch (key.trim()) {
                case 'referrer':
                    return 'Non-organic';
            }
        }),
    });
    hook('android.app.SharedPreferencesImpl', 'getInt', {
        loggingPredicate: lp,
        logging: { multiline: false },
        replace: ifKey((key) => {
            switch (key) {
            }
        }),
    });
    hook('android.app.SharedPreferencesImpl', 'getBoolean', {
        loggingPredicate: lp,
        logging: { multiline: false },
        replace: ifKey((key) => {
            switch (key) {
            }
        }),
    });
    // hook('java.util.Properties', 'getProperty');
}

function hookCountry() {
    const timezoneId = 'America/Sao_Paulo';
    const mcc = '724',
        mnc = '10',
        code = '55',
        mccmnc = `${mcc}${mnc}`;
    const locale = ['BR', 'pt'],
        country = 'br',
        operator = 'Vivo';
    const number = `${code}${Text.stringNumber(10)}`,
        subscriber = `${mccmnc}${Text.stringNumber(10)}`;
    hook(Classes.TelephonyManager, 'getLine1Number', { replace: always(number) });
    hook(Classes.TelephonyManager, 'getSimOperator', { replace: always(mccmnc) });
    hook(Classes.TelephonyManager, 'getSimOperatorName', { replace: always(operator) });
    hook(Classes.TelephonyManager, 'getNetworkOperator', { replace: always(mccmnc) });
    hook(Classes.TelephonyManager, 'getNetworkOperatorName', { replace: always(operator) });
    hook(Classes.TelephonyManager, 'getSimCountryIso', { replace: always(country) });
    hook(Classes.TelephonyManager, 'getNetworkCountryIso', { replace: always(country) });
    hook(Classes.TelephonyManager, 'getSubscriberId', { replace: always(subscriber) });
    hook(Classes.TimeZone, 'getID', { replace: always(timezoneId) });
    hook(Classes.Locale, 'getDefault', {
        replace: () => Classes.Locale.$new(locale[1], locale[0]),
        logging: { call: false, return: false },
    });
    // hook(Classes.Locale, 'getCountry', { replace: always('BR') });
    // hook(Classes.Locale, 'getLanguage', { replace: always('pt') });
    // hook(Classes.Locale, 'getDisplayCountry', { replace: always('Brazil') });
    // hook(Classes.Locale, 'toString', { replace: always('pt_BR') });
}

function hookDevice() {
    /* device Settings*/
    const Build = {
        MODEL: 'Secret SC-1224',
        DEVICE: 'Device Value',
        BOARD: 'Device Board',
        // PRODUCT: 'Device Product',
        // HARDWARE: 'Device Hardware',
        FINGERPRINT: 'foo/bar/Device:11/11/2022:user/sig-keys',
        MANUFACTURER: 'Company Co',
        BOOTLOADER: 'Boot-JJ129-ac',
        BRAND: 'China Telecom',
        HOST: 'HOST Co',
        DISPLAY: 'Foo procuctions and bar 1-0-111',
        TAGS: 'Production Build',
        SERIAL: 'Seriously ?',
        TYPE: 'Production build',
        USER: 'LINUX General',
        UNKNOWN: 'KGTT General',
    };
    const buildProperties = Java.use('android.os.Build');
    Reflect.ownKeys(Build).forEach((key: any) => {
        const field = buildProperties[key];
        if (field) field.value = Build[key];
    });
    //buildProperties.ANDROID_ID.value='b6932a00c88d8b50';
}

function hookSettings() {
    const settings = { development_settings_enabled: 0, adb_enabled: 0 };
    hook('android.provider.Settings$Secure', 'getInt', {
        logging: { call: true, return: true },
        replace(method, ...params) {
            const key = params[1];
            if (settings.hasOwnProperty(key)) return settings[key];
            return method.call(this, ...params);
        },
    });
}

function hookInstallReferrer() {
    const uniqHook = getHookUnique();
    ClassLoader.perform((cl) => {
        uniqHook('com.android.installreferrer.api.InstallReferrerClient', '$init', {
            before(method, ...args) {
                uniqHook(this.$className, 'startConnection', {
                    replace(method, listner) {
                        // TODO call original yes/no ?
                        if (listner?.onInstallReferrerSetupFinished) {
                            listner.onInstallReferrerSetupFinished(0);
                        }
                    },
                });
                uniqHook(this.$className, 'getInstallReferrer', {
                    replace(method, ...args) {
                        const ReferrerDetails = findClass(method.returnType.className ?? 'com.android.installreferrer.api.ReferrerDetails');
                        if (ReferrerDetails) {
                            const bundle = Classes.Bundle.$new();
                            bundle.putString('install_referrer', 'Nyaa!~');
                            return ReferrerDetails.$new(bundle);
                        }
                        return method.call(this, ...args);
                    },
                });
            },
        });
    });
}

Java.performNow(() => {
    hookActivity();
    hookWebview();
    hookJson(function (key, method) {
        switch (key) {
            case 'jigsaw_noAd_level':
                return 0;
            case 'post_parameters':
            case 'web_env_url':
            case 'pool_key':
            case 'base_uri':
            case 'url':
            case 'data':
            case 'murl':
                return 'https://google.pl/search?q=hi';
        }
    });
    hookPrefs();
    hookCrypto();
    hookSettings();
    hook(Classes.URL, 'openConnection', {
        loggingPredicate: () => {
            const trace = stacktrace();
            if (trace.includes('at com.facebook.internal.')) return false;
            if (trace.includes('at com.appsflyer.internal.')) return false;
            if (trace.includes('at com.onesignal.OneSignalPrefs.')) return false;
            if (trace.includes('at com.google.android.gms.internal.ads.')) return false;
            return true;
        },
    });
    hook(Classes.Runtime, 'exec');
    hookCountry();
    hookDevice();
    hookInstallReferrer();

    let x: any = null;
    ClassLoader.perform((cl) => {
        uniqHook('com.qihoo.util.a', 'm3a', { replace: always(true) });
    });
});

Network.attachGetAddrInfo();
Network.attachGetHostByName();
Network.attachNativeSocket();
Network.attachInteAton();
Native.attachRegisterNatives();
Native.attachSystemPropertyGet(function (key) {
    // console.log(DebugSymbol.fromAddress(this.returnAddress));
    switch (key) {
        case 'ro.debuggable':
            return '0';
        case 'ro.product.model':
            return 'Raven';
        case 'ro.product.brand':
            return 'Xiaomi';
        case 'ro.build.flavor':
            return 'raven-release';
    }
    // if (Native.Inject.modules.findPath(this.returnAddress)?.includes('/data') === true) return 'nya';
});

Anticloak.Jigau.memoryPatch();
// Cocos2dx.dump();
// Unity.setVersion('2022.2.6f1')
// Unity.attachStrings();

let x = true;
const predicate = (r) => x && Native.Inject.isWithinOwnRange(r);

JniTrace.attach(({ returnAddress }) => {
    return predicate(returnAddress);
});

['strcmp', 'strncmp', 'strstr', 'strncasecmp'].forEach((ex) => {
    const strcmp = Module.getExportByName(null, ex);
    Native.Inject.attachInModule(predicate, strcmp, {
        onEnter(args) {
            logger.info(
                { tag: ex },
                `"${args[0].readCString()}", "${args[1].readCString()}" ${Native.Inject.modules.findPath(this.returnAddress)}`,
            );
        },
    });
});
[
    'stat',
    'access',
    'vprintf',
    '__android_log_print',
    'sprintf',
    'open',
    'access',
    'pthread_kill',
    'kill',
    'exit',
    '_exit',
    'killpg',
    'signal',
    'abort',
].forEach((ex) => {
    const exp = Module.getExportByName(null, ex);
    Native.Inject.attachInModule(predicate, exp, {
        onEnter(args) {
            const arg = ex === '__android_log_print' ? args[2] : args[0];
            switch (ex) {
                case '__android_log_print': {
                    // logger.info({ tag: ex }, `"${args[2].readCString()}"`);
                    return;
                }
                case 'sprintf': {
                    logger.info({ tag: ex }, `"${args[0].readCString()}" "${args[1].readCString()}"`);
                    return;
                }
                default: {
                    logger.info({ tag: ex }, `"${arg.readCString()}"`);
                    return;
                }
            }
        },
    });
});

// let repl = false;
// Interceptor.replace(
//     Libc.fork,
//     new NativeCallback(
//         function (this: any, args: any[]) {
//             // repl = true;
//             logger.info({ tag: 'fork' }, 'call fork call');
//             return Libc.fork();
//         } as any,
//         'int',
//         [],
//     ),
// );

// Interceptor.replace(
//     Libc.pthread_create,
//     new NativeCallback(
//         function (this: CallbackContext, arg0: NativePointer, arg1: NativePointer, arg2: NativePointer, arg3: NativePointer) {
//             if (false) {
//                 logger.info({ tag: 'pthread_create#fake' }, 'replaced fork call');
//                 return 0;
//             }
//             logger.info(
//                 { tag: 'pthread_create' },
//                 `${arguments[0]} ${arguments[1]} ${arguments[2]} ${arguments[3]} ${Native.Inject.modules.findPath(this.returnAddress)}`,
//             );
//             return Libc.pthread_create(arguments[0], arguments[1], arguments[2], arguments[3]);
//         },
//         'int',
//         ['pointer', 'pointer', 'pointer', 'pointer'],
//     ),
// );
