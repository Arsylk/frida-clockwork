import * as Anticloak from '@clockwork/anticloak';
import { ProcMaps } from '@clockwork/cmodules';
import * as Cocos2dx from '@clockwork/cocos2dx';
import {
    Classes,
    ClassesString,
    Consts,
    Linker,
    Struct,
    Text,
    emitter,
    enumerateMembers,
    findClass,
    getFindUnique,
    hookException,
    isNully,
    stacktrace,
    tryNull,
} from '@clockwork/common';
import { toHex, uuid } from '@clockwork/common/dist/text';
import * as Dump from '@clockwork/dump';
import { ClassLoader, Filter, always, compat, getHookUnique, hook, ifKey } from '@clockwork/hooks';
import type { FridaMethodThisCompat } from '@clockwork/hooks/dist/types';
import * as JniTrace from '@clockwork/jnitrace';
import { Color, logger } from '@clockwork/logging';
import * as Native from '@clockwork/native';
import { predicate as _predicate } from '@clockwork/native';
import { getSelfProcessName } from '@clockwork/native/dist/utils';
import * as Network from '@clockwork/network';
import * as Unity from '@clockwork/unity';
const { red, green, redBright, magentaBright: pink, gray, dim, black } = Color.use();
const uniqHook = getHookUnique(false);
const uniqFind = getFindUnique(false);
const uniqEnum = (clazzName: string, depth?: number) => {
    uniqFind(clazzName, (clazz) => {
        hook(clazz, '$init');
        enumerateMembers(
            clazz,
            {
                onMatchMethod(clazz, member, depth) {
                    hook(clazz, member);
                },
            },
            depth,
        );
    });
};

const predicate = (ptr: NativePointer) => _predicate(ptr);

function hookActivity() {
    let createdLast: any = null;
    let resumedLast: any = null;
    hook(Classes.Activity, '$init', {
        after() {
            logger.info({ tag: 'activity' }, `${gray('$init')}: ${this.$className}`);
        },
    });
    hook(Classes.Activity, 'onCreate', {
        after() {
            logger.info({ tag: 'activity' }, `${gray('onCreate')}: ${this.$className}`);
            createdLast = this;
        },
        logging: { arguments: false },
    });
    hook(Classes.Activity, 'onResume', {
        after() {
            logger.info({ tag: 'activity' }, `${gray('onResume')}: ${this.$className}`);
            resumedLast = this;
        },
        logging: { arguments: false },
    });
    hook(Classes.Activity, 'startActivity');
    hook(Classes.Activity, 'startActivities');
}

function hookWebview(trace?: boolean) {
    const logging = { short: true };
    hook(Classes.WebView, 'evaluateJavascript', {
        logging: {
            ...logging,
            transform: (value, type, id) => (id === 0 ? Text.maxLengh(value, 300) : value),
        },
    });
    hook(Classes.WebView, 'loadDataWithBaseURL', {
        logging: {
            ...logging,
            transform: (value, type, id) => (id === 1 ? Text.maxLengh(value, 300) : value),
        },
    });
    hook(Classes.WebView, 'loadUrl', {
        logging: logging,
        after() {
            if (trace) {
                const strace = stacktrace();
                if (
                    !strace.includes('com.google.android.gms.ads.internal.webview.') &&
                    !strace.includes('com.google.android.gms.internal.')
                ) {
                    logger.info(pink(strace));
                }
            }
        },
    });
}

function hookNetwork() {
    hook(Classes.URL, 'openConnection', {
        loggingPredicate: Filter.url,
    });
    let RealCall: Java.Wrapper | null = null;
    ClassLoader.perform(() => {
        !RealCall &&
            (RealCall = findClass('okhttp3.internal.connection.RealCall')) &&
            'callStart' in RealCall &&
            hook(RealCall, 'callStart', {
                after() {
                    const original = this.originalRequest?.value;
                    if (original) {
                        const url = original._url?.value;
                        const method = original._method?.value;
                        logger.info(
                            //@ts-ignore
                            `${dim(method)} ${Color.url(
                                //@ts-ignore
                                Classes.String.valueOf(url),
                            )}`,
                        );
                    }
                },
            });
    });

    hook(Classes.InetSocketAddress, '$init', {
        logging: { multiline: false, short: true },
    });

    function byteBufferToBase64(buffer: Java.Wrapper, limit: number = buffer.remaining()): string {
        buffer.mark();
        const rawarr: number[] = [];
        for (let i = 0; i < limit; i += 1) rawarr.push(0);
        const bytes = Java.array('byte', rawarr);
        buffer.get(bytes);
        const b64 = Classes.String.$new(Classes.Base64.getEncoder().encode(bytes));
        buffer.reset();
        return b64;
    }

    hook(Classes.DatagramChannelImpl, 'send', {
        before(method, buffer) {
            const b64 = byteBufferToBase64(buffer);
            logger.info(
                { tag: 'send' },
                `${this.localAddress()} -> ${this.remoteAddress()} | ${gray(`${b64}`)}`,
            );
        },
    });

    hook(Classes.DatagramChannelImpl, 'read', {
        logging: { multiline: false },
        after(method, returnValue, buffer) {
            buffer.position(0);
            const b64 = byteBufferToBase64(buffer, returnValue);
            logger.info(
                { tag: 'read' },
                `${this.remoteAddress()} -> ${this.localAddress()} | ${gray(`${b64}`)}`,
            );
        },
    });
}

function hookFile() {
    for (const [mth, id] of [
        ['canRead', 'r'],
        ['canWrite', 'w'],
        ['canExecute', 'x'],
        ['exists', '?'],
    ]) {
        hook(Classes.File, mth, {
            logging: { call: false, return: false },
            replace(method) {
                const path = `${this}`;
                if (path.endsWith('/su') || path.includes('/data/local/tmp')) {
                    return false;
                }
                return method.call(this);
            },
            after(method, returnValue, ...args) {
                const ret = Color.number(returnValue ? 'true' : 'false');
                logger.info({ tag: 'file', id: id }, `${gray(`${this}`)} ? ${ret}`);
            },
        });
    }
}

function hookRuntimeExec() {
    const mReplace = (sArg: string) => {
        sArg = sArg.replace(/su$/g, 'nya');
        sArg = sArg.replace(/^rm -r/g, 'file ');
        sArg = sArg.replace(/^getprop/g, 'ls');
        sArg = sArg.replace(/^uname/g, 'echo');
        return Classes.String.$new(`${sArg}`);
    };

    false &&
        hook(Classes.Runtime, 'exec', {
            replace(method, ...args) {
                // string array
                if (method.argumentTypes[0].name === '[Ljava/lang/String;') {
                    const cloned = Array(args[0].length);
                    for (let i = 0; i < args[0].length; i += 1) {
                        cloned[i] = mReplace(`${args[0][i]}`);
                    }
                    args[0] = Java.array(ClassesString.String, cloned);
                }
                // single string
                else {
                    args[0] = mReplace(`${args[0]}`);
                }
                logger.info({ tag: 'process' }, `${args[0]}`);
                // if (`${args[0]}`.includes('nya') === false) return Classes.Runtime.exec.call(this, 'echo nya');
                return method.call(this, ...args);
            },
        });
    hook(Classes.ProcessBuilder, 'start', {
        before(method, ...args) {
            const newlist: string[] = [];
            for (let i = 0; i < this._command.value.size(); i += 1) {
                const newvalue = mReplace(`${this._command.value.get(i)}`);
                this._command.value.set(i, newvalue);
                newlist.push(newvalue);
            }
            logger.info({ tag: 'process' }, `${newlist}`);
        },
    });
}

function hookCrypto() {
    hook(Classes.SecretKeySpec, '$init', {
        logging: {
            multiline: false,
            short: true,
            transform: (value, type, id) =>
                (id === 0 || undefined) &&
                tryNull(() => [
                    (() => {
                        let sb = '';
                        for (const b of value) {
                            sb += toHex(b);
                        }
                        return [sb];
                    })(),
                    `${ClassesString.Object}[]`,
                ]),
        },
    });
    hook(Classes.Cipher, 'getInstance', {
        logging: { multiline: false, short: true },
    });
    hook(Classes.Cipher, 'doFinal', {
        before(method, ...args) {},
        after(method, returnValue, ...args) {
            if (this.opmode.value === 1) {
                let str = tryNull(() => Classes.String.$new(args[0], Classes.StandardCharsets.UTF_8.value));
                str ??= tryNull(() => Classes.String.$new(args[0]));
                str ??= tryNull(() =>
                    (Classes.Arrays.toString as Java.MethodDispatcher)
                        .overload('[B')
                        .call(Classes.Arrays, args[0]),
                );
                str ??= `${args[0]}`;
                logger.info({ tag: 'encrypt' }, `${str}`);
            }
            if (this.opmode.value === 2) {
                let transformed = tryNull(() =>
                    Classes.String.$new(returnValue, Classes.StandardCharsets.UTF_8.value),
                );
                transformed ??= tryNull(() => Classes.String.$new(returnValue));
                transformed ??= tryNull(() =>
                    (Classes.Arrays.toString as Java.MethodDispatcher)
                        .overload('[B')
                        .call(Classes.Arrays, returnValue),
                );
                //@ts-ignore
                transformed ??= `${Classes.String.valueOf(returnValue)}`;
                logger.info({ tag: 'decrypt' }, `${transformed}`);
                logger.info({ tag: 'decrypt' }, pink(stacktrace()));
            }
        },
        logging: { arguments: false, return: false },
    });
}

function hookJson(fn?: (key: string, method: string, fallback: () => Java.Wrapper) => any) {
    const getOpt = ['get', 'opt'];
    const types = ['Boolean', 'Double', 'Int', 'JSONArray', 'JSONObject', 'Long', 'String'];

    hook(Classes.JSONObject, '$init', {
        loggingPredicate: Filter.json,
        logging: { short: true },
        predicate: (_, index) => index !== 0,
    });

    hook(Classes.JSONObject, 'has', {
        loggingPredicate: Filter.json,
        logging: { multiline: false, short: true },
        replace(method, key) {
            const bound = method.bind(this, key);
            const found = fn?.(key, 'has', bound) !== undefined;
            return found || bound();
        },
    });

    for (const item of getOpt) {
        hook(Classes.JSONObject, item, {
            loggingPredicate: Filter.json,
            logging: { multiline: false, short: true },
            replace(method, ...args) {
                const bound = method.bind(this, ...args);
                const value = fn?.(args[0], item, bound);
                return value !== undefined ? value : bound();
            },
        });
    }

    for (const type of types) {
        for (const item of getOpt) {
            const name = `${item}${type}`;
            hook(Classes.JSONObject, name, {
                loggingPredicate: Filter.json,
                logging: { multiline: false, short: true },
                replace(method, ...args) {
                    const bound = method.bind(this, ...args);
                    const value = fn?.(args[0], item, bound);
                    return value !== undefined ? value : bound();
                },
            });
        }
    }
    // hook(Classes.JSONObject, 'put')
}

function hookPrefs(fn?: (this: FridaMethodThisCompat, key: string, method: string) => any) {
    const keyFns = ['getBoolean', 'getFloat', /**'getInt',*/ 'getLong', 'getString', 'getStringSet'];

    hook(Classes.SharedPreferencesImpl, 'contains', {
        loggingPredicate: Filter.prefs,
        logging: { multiline: false, short: true },
        replace: compat(function () {
            const found = fn?.call(this, this.originalArgs[0], 'contains') !== undefined;
            return found || this.fallback();
        }),
    });
    // hook(Classes.SharedPreferencesImpl, 'getAll', {
    //     loggingPredicate: Filter.prefs,
    //     logging: { multiline: false, short: true },
    // });

    for (const item of keyFns) {
        hook(Classes.SharedPreferencesImpl, item, {
            loggingPredicate: Filter.prefs,
            logging: { multiline: false, short: true },
            replace: compat(function () {
                const result = fn?.call(this, this.originalArgs[0], item);
                return result !== undefined ? result : this.fallback();
            }),
        });
    }
    // hook('java.util.Properties', 'getProperty');
}

function hookPreferences(fn?: (key: string, method: string) => any) {
    let Preferences: Java.Wrapper | null = null;
    let Preferences$Key: Java.Wrapper | null = null;
    ClassLoader.perform(() => {
        !Preferences &&
            (Preferences = findClass(ClassesString.Preferences)) &&
            hook(Preferences, '$init', {
                predicate(method) {
                    return method.argumentTypes.length > 0;
                },
                after(method, returnValue, ...args) {
                    const contains = function (this: Java.Wrapper, method: Java.Method, key: string) {
                        const found = fn?.(key, 'contains') !== undefined;
                        return found || method.call(this, key);
                    };
                    const get = function (this: Java.Wrapper, method: Java.Method, key: Java.Wrapper) {
                        const keyStr = key.getName();
                        const result = fn?.(keyStr, method.name);
                        if (result !== undefined) return result;
                        return method.call(this, key);
                    };

                    'contains' in this &&
                        hook(this.$className, 'contains', {
                            replace: fn ? contains : undefined,
                            logging: { short: true, multiline: false },
                        });
                    'get' in this &&
                        hook(this.$className, 'get', {
                            replace: fn ? get : undefined,
                            logging: { short: true, multiline: false },
                        });
                    'asMap' in this &&
                        hook(this.$className, 'asMap', {
                            logging: { short: true, multiline: false },
                        });
                },
            });
        !Preferences$Key &&
            (Preferences$Key = findClass(ClassesString.Preferences$Key)) &&
            hook(Preferences$Key, '$init', {
                logging: { multiline: false, short: true },
            });
    });
}

function hookFirestore() {
    let FirebaseFirestore: Java.Wrapper | null = null;
    let QueryDocumentSnapshot: Java.Wrapper | null = null;
    let QuerySnapshot: Java.Wrapper | null = null;
    let DocumentSnapshot: Java.Wrapper | null = null;
    const fn = () => {
        if (
            !FirebaseFirestore &&
            (FirebaseFirestore = findClass('com.google.firebase.firestore.FirebaseFirestore'))
        ) {
            hook(FirebaseFirestore, '$init', {
                predicate: (overload) => overload.argumentTypes.length > 0,
                logging: { short: true },
            });

            'collection' in FirebaseFirestore &&
                hook(FirebaseFirestore, 'collection', {
                    logging: { short: true, multiline: false },
                });
        }
        if (
            !QueryDocumentSnapshot &&
            (QueryDocumentSnapshot = findClass('com.google.firebase.firestore.QueryDocumentSnapshot'))
        ) {
            'getId' in QueryDocumentSnapshot &&
                hook(QueryDocumentSnapshot, 'getId', {
                    logging: { short: true, multiline: false },
                });
            'getData' in QueryDocumentSnapshot &&
                hook(QueryDocumentSnapshot, 'getData', {
                    logging: { short: true, multiline: false },
                });
        }
        if (!QuerySnapshot && (QuerySnapshot = findClass('com.google.firebase.firestore.QuerySnapshot'))) {
            hook(QuerySnapshot, '$init', {
                loggingPredicate: (method) => method.argumentTypes.length > 0,
                logging: { short: true },
            });
        }
        if (
            !DocumentSnapshot &&
            (DocumentSnapshot = findClass('com.google.firebase.firestore.DocumentSnapshot'))
        ) {
            hook(DocumentSnapshot, '$init', {
                logging: { short: true },
                loggingPredicate(method, ...args) {
                    return args.length > 0;
                },
            });
            'get' in DocumentSnapshot && hook(DocumentSnapshot, 'get', { logging: { short: true } });
        }
    };
    ClassLoader.perform(fn);
}

function bypassIntentFlags() {
    if (Classes.Build$VERSION.SDK_INT.value < 34) return;
    hook(Classes.PendingIntent, 'getBroadcastAsUser', {
        replace(method, ...args) {
            const flags = args[3];
            const flagImmutableSet = (flags & Classes.PendingIntent.FLAG_IMMUTABLE.value) !== 0;
            const flagMutableSet = (flags & Classes.PendingIntent.FLAG_MUTABLE.value) !== 0;
            if (!flagImmutableSet && !flagMutableSet) {
                const newFlags = flags | Classes.PendingIntent.FLAG_MUTABLE.value;
                args[3] = newFlags;
            }
            return method.call(this, ...args);
        },
        logging: { call: false, return: false },
    });
    hook(Classes.PendingIntent, 'checkPendingIntent', {
        replace(method, ...args) {
            return;
        },
        logging: { call: false, return: false },
    });
    hook('android.os.UserHandle', 'isCore', {
        replace: always(true),
        logging: { call: false, return: false },
    });
}

function bypassReceiverFlags() {
    if (Classes.Build$VERSION.SDK_INT.value < 34) return;
    hook(Classes.ContextImpl, 'registerReceiverInternal', {
        replace(method, ...args) {
            const EXPORTED = Classes.Context.RECEIVER_EXPORTED.value;
            const NOT_EXPORTED = Classes.Context.RECEIVER_NOT_EXPORTED.value;
            if ((args[6] & NOT_EXPORTED) === 0) {
                args[6] |= EXPORTED;
            }

            return method.call(this, ...args);
        },
        logging: {
            call: false,
            return: false,
        },
    });

    hook('android.app.AlarmManager', 'setExact', {
        replace: function (method) {
            method.call(this, false);
        },
        logging: { call: false, return: false },
    });
}

function swapIntent(/*target: string, dest: string*/) {
    let i = 0;
    hook(Classes.Intent, '$init', {
        predicate: (_, index) => index === 1,
        replace(method, context, clazz) {
            const tmpclazz = findClass('com.tamanedukasianak.laguanakpaud.RateappActivity')?.class;
            if (tmpclazz && i < 2) {
                i += 1;
                clazz = tmpclazz;
            }
            return method.call(this, context, clazz);
        },
    });
}

Java.performNow(() => {
    const C4_URL = 'https://google.pl/search?q=hi';
    const AD_ID = 'fwqna41l-mrux-l4pi-mi6q-imrr3t83da4n';
    const INSTALL_REFERRER = `utm_source=facebook_ads&utm_medium=Non-organic&media_source=true_network&http_referrer=BingSearch&utm_campaign=Non-organic&campaign=Non-organic&af_ad=${AD_ID}`;
    hookActivity();
    hookWebview(true);
    hookNetwork();
    hookFile();
    hookJson((key, _method, fallback) => {
        switch (key) {
            //case 'r_debugger':
            //    return true;
            case 'referrer':
            case 'applink_url':
            case 'af_message':
            case 'af_status':
            case 'tracker_name':
            case 'network':
            case 'campaign':
            case 'google_utm_source':
                return INSTALL_REFERRER;
            case 'gaid':
            case 'android_imei':
            case 'android_meid':
            case 'android_device_id':
                return '4102978102398';
        }
    });
    hookPrefs((key, method) => {
        switch (key) {
            case 'oskdoskdue':
                return 0;
            case 'isAudit':
            case 'IS_AUDIT':
                return false;
            case 'invld_id':
            case 'key_umeng_sp_oaid':
            case 'UTDID2':
            case 'adid':
            case 'com.flurry.sdk.advertising_id':
            case 'tenjin_advertising_id':
            case 'uuid':
            case 'AF_CAMPAIGN':
                return 'Non-organic';
            case 'country':
            case 'userCountry':
            case 'key_real_country':
            case 'KEY_LOCALE':
            case 'key_country':
            case 'Plat_Lang':
                return 'VN';
            case 'install_referrer':
                return INSTALL_REFERRER;
            case '_rs_app_start_route':
                return 'Login';
        }
    });
    hook(Classes.SharedPreferencesImpl$EditorImpl, 'putString');
    hookPreferences(() => {});
    hookFirestore();
    hookCrypto();
    hookRuntimeExec();

    bypassIntentFlags();
    bypassReceiverFlags();

    // hook('android.content.ContextWrapper', 'getSharedPreferences', {
    //     logging: { multiline: false, short: true, return: false },
    // });

    hook(Classes.Process, 'killProcess', {
        after: () => {
            logger.info({ tag: 'process' }, redBright(stacktrace()));
        },
        logging: { multiline: false, return: false },
    });
    hook(Classes.ActivityManager, 'getRunningAppProcesses', {
        logging: { short: true, multiline: false },
    });
    hook(Classes.ActivityManager$RunningAppProcessInfo, '$init', {
        logging: { short: true, multiline: false },
    });

    // hook(Classes.Activity, 'finish', { replace: () => {}, logging: { multiline: false, return: false } });
    // hook(Classes.Activity, 'finishAffinity', {
    //     replace: () => {},
    //     logging: { multiline: false, return: false },
    // });

    Anticloak.Debug.hookVMDebug();
    // Anticloak.Debug.hookDigestEquals();
    Anticloak.Debug.hookVerify();
    Anticloak.generic();
    Anticloak.hookDevice();
    Anticloak.hookSettings();
    Anticloak.hookAdId(AD_ID);
    Anticloak.hookPackageManager();
    Anticloak.Country.mock('VN');
    Anticloak.InstallReferrer.replace({ install_referrer: INSTALL_REFERRER });

    hook(Classes.SystemProperties, 'get', {
        loggingPredicate: Filter.systemproperties,
        logging: { multiline: false, short: true },
        replace: ifKey((key) => {
            const value = Anticloak.BuildProp.propMapper(key);
            return value;
        }),
    });
    hook(Classes.System, 'getProperty', {
        loggingPredicate: Filter.systemprop,
        logging: { multiline: false, short: true },
        replace(method, ...args) {
            const fallback = () => method.call(this, ...args);
            const value = Anticloak.BuildProp.systemMapper(args[0], fallback);
            return value ?? fallback();
        },
    });

    hook(Classes.DisplayManager, 'createVirtualDisplay');

    hook(Classes.SimpleDateFormat, 'parse', {
        logging: { short: true, multiline: false },
    });
    hook(Classes.URLEncoder, 'encode', {
        logging: { short: true, multiline: false },
        loggingPredicate: Filter.urlencoder,
    });

    hook(Classes.DexPathList, '$init', {
        logging: { short: true, multiline: false },
    });

    const conf = { logging: { short: true, multiline: false } };
    ClassLoader.perform(() => {});
});

Native.initLibart();
Network.injectSsl();
Network.attachGetAddrInfo();
Network.attachGetHostByName();
Network.attachNativeSocket();
Network.attachInteAton();
Native.attachSystemPropertyGet(
    (ret) => true,
    (key) => {
        const value = Anticloak.BuildProp.propMapper(key);
        return value;
    },
);

//Cocos2dx.dump({ name: 'libcocos2djs.so', fn_dump: ptr(0x00b72f78), fn_key: ptr(0x01a53d60) });
//Cocos2dx.hookLocalStorage((key) => {
//    logger.info({ tag: 'cocossetlocal' }, key);
//    return undefined;
//});
//Unity.setVersion('2019.3.13f1');
//Unity.patchSsl();
//Unity.attachScenes();
//Unity.attachStrings();

//let enabled = false;
//setTimeout(() => (enabled = true), 8000);

Native.Pthread.hookPthread_create();
Native.Files.hookFopen(predicate, true, (path) => {
    if (
        path?.endsWith('/proc/net/tcp') ||
        path?.endsWith('/maps') ||
        path?.endsWith('/smaps') ||
        path?.includes('/proc/self/environ')
    ) {
        return '/dev/null';
    }
    if (path?.endsWith('/su') || path?.endsWith('/mountinfo')) {
        return path.replace(/\/(su|mountinfo)$/, '/nya');
    }
    if (
        path?.includes('magisk') ||
        path?.includes('supolicy') ||
        path?.toLowerCase()?.includes('superuser')
    ) {
        return path.replace(/(magisk|supolicy|superuser)/gi, 'nya');
    }
});
//Native.Strings.hookStrtoLong(predicate);

//Native.hookGlGetString();
//Native.System.hookSystem();
//Native.System.hookGetauxval();
//Native.TheEnd.hook(predicate);

//Interceptor.attach(Libc.vsnprintf, {
//    onEnter(args) {
//        this.dst = args[0];
//    },
//    onLeave(retval) {findsym
//        if (predicate(this.returnAddress)) {
//            const text = this.dst.readCString();
//            logger.info({ tag: 'vsnprintf' }, `${text} ${Native.addressOf(this.returnAddress)}`);
//        }
//    },
//});
//Interceptor.attach(Libc.sprintf, {
//    onEnter(args) {
//        this.dst = args[0];
//    },
//    onLeave(retval) {
//        const text = this.dst.readCString();
//        logger.info({ tag: 'sprintf' }, `${text}`);
//    },
//});

Interceptor.attach(Libc.posix_spawn, {
    onEnter({ 0: pid, 1: path, 2: action }) {
        const pathStr = path.readCString();
        logger.info({ tag: 'posix_spawn' }, `${pathStr} ${action}`);
    },
    onLeave(retval) {
        logger.info({ tag: 'posix_spawn' }, `${retval}`);
    },
});

Interceptor.replace(
    Libc.nanosleep,
    new NativeCallback(
        () => {
            //if (predicate(this.returnAddress)) {
            //    logger.info({ tag: 'nanosleep' }, `${Native.addressOf(this.returnAddress)}`);
            //}
            return 0;
        },
        'int',
        ['pointer', 'pointer'],
    ),
);

Interceptor.replace(
    Libc.fork,
    new NativeCallback(
        function () {
            const retval = Libc.fork();
            //const retval = 2;
            logger.info({ tag: 'fork' }, `${retval} ${Native.addressOf(this.returnAddress)}`);
            return retval;
        },
        'int',
        [],
    ),
);

Interceptor.replace(
    Libc.popen,
    new NativeCallback(
        (arg0, arg1) => {
            const cmd = arg0.readCString();
            logger.info({ tag: 'popen' }, `${cmd}`);
            if (cmd?.startsWith('uname')) {
                arg0.writeUtf8String('echo -a');
            }
            if (cmd?.startsWith('getprop')) {
                arg0.writeUtf8String('echo');
            }

            return Libc.popen(arg0, arg1);
        },
        'pointer',
        ['pointer', 'pointer'],
    ),
);

function stalk(pid: number, module: Module) {
    const func_addr: { [key: string]: string } = {};
    let times = 0;

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

    Stalker.follow(pid, {
        events: {
            call: false,
            ret: true,
            exec: false,
            block: false,
            compile: false,
        },
        onReceive: (events: ArrayBuffer) => {},
        transform: (iterator: StalkerArm64Iterator) => {
            let instruction = iterator.next();
            do {
                if (instruction?.groups.includes('call')) {
                    //@ts-ignore

                    const value = tryNull(() => ptr(instruction.operands[0].value));
                    logger.info({ tag: 'call' }, `${times}:${instruction} | ${value}`);
                    times = times + 1;
                }
                iterator.keep();
            } while ((instruction = iterator.next()) !== null);
        },

        onCallSummary: (summary) => {},
    });
}

Native.Strings.hookStrstr(() => true);
Native.Files.hookFgets(() => true);

Native.Inject.onPrelinkOnce(function (module) {
    const isNotFrida = (r: NativePointer) => !ProcMaps.isFridaAddress(r) && `${r}`.startsWith('0xab');
    const { base, name, size, path } = module;
    if (name === 'libcocos.so') {
        //hookException([160], {
        //    onBefore({ x0, x1, x2, x3 }, num) {
        //        switch (num) {
        //            case 56:
        //                this.path = x1.readCString();
        //                break;
        //            case 57:
        //                //this.path = `/proc/self/fd/${x1.toUInt32()}`;
        //                break;
        //            case 160:
        //                this.ptr = x0;
        //                break;
        //        }
        //    },
        //    onAfter(ctx, num) {
        //        if (num === 160) {
        //            const addr = this.ptr.add(0x41 * 2);
        //            const text = addr.readCString().toLowerCase();
        //            for (const key of ['ksu', 'kernelsu', 'lineage', 'dirty']) {
        //                const i = text.indexOf(key);
        //                if (i !== -1) {
        //                    addr.add(i).writeByteArray(new Array(key.length).map((_) => 0x0));
        //                }
        //            }
        //        }
        //        if (num === 56) {
        //            logger.info({ tag: 'openat' }, `${this.path} ${ctx.x0}`);
        //        }
        //    },
        //});
        stalk(this.threadId, module);
        Native.Logcat.hookLogcat(function (...args) {
            return !ProcMaps.isFridaAddress(this.returnAddress);
        });
        Anticloak.Debug.hookPtrace();

        //Native.Strings.hookStrcpy(predicate);
        Native.Strings.hookStrcmp(isNotFrida);
        Native.Strings.hookStrlen(isNotFrida);
        Native.Strings.hookStrstr(isNotFrida);
        //Native.Strings.hookStrchr(predicate);
        //Native.Strings.hookStrcat(predicate);

        Native.log(Module.getExportByName(null, 'android_set_abort_message'), 's');
        //Native.log(Libc.mmap, 'piiiip', {});
        Native.log(Libc.memcpy, '__i', {
            predicate: (ptr) => predicate(ptr),
            call: function (args) {
                this.a0 = args[0];
                this.a1 = args[1];
                this.size = args[2].toInt32();
            },
            ret: function (retval) {
                if (predicate(this.returnAddress)) {
                    //Memory.protect(this.a0, this.size, 'rwx');
                    //Memory.protect(this.a1, this.size, 'rwx');
                    //ELF = ptr(`${retval}`);
                    //ELF_size = this.size;

                    //const data = this.a0.readByteArray(this.size);
                    logger.info({ tag: 'memcpy' }, hexdump(this.a1, { length: this.size }));
                    //File.writeAllBytes(
                    //    '/data/data/com.kct.fundo.btnotification/files/memcpyelf.so',
                    //    data,
                    //);
                }
                return;
            },
        });
        //const buffer1 = Memory.alloc(512);
        //const buffer2 = Memory.alloc(512);
        //const buffer3 = Memory.alloc(512);
        //const buffer4 = Memory.alloc(512);
        Native.Files.hookAccess(predicate);
        //Native.Files.hookStat(predicate);
        //Native.Files.hookRemove(predicate);
        Native.Files.hookDirent(() => true);
        Native.Files.hookOpendir(
            () => true,
            (path) => {
                if (
                    path === '/dev' ||
                    (path?.startsWith('/proc') &&
                        (path?.includes('/task') ||
                            path.endsWith('/fd') ||
                            path.endsWith('/status') ||
                            path.endsWith('/fs/jbd2')))
                )
                    return '/dev/null';
            },
        );
    }
});

function syscallRead(path: string): string | null {
    const syscall = new NativeFunction(Libc.syscall, 'int', ['int', 'pointer', 'pointer', 'int', 'int']);
    const fd = syscall(56, NULL, Memory.allocUtf8String(path), 0, 0);
    const file = Libc.fdopen(fd, Memory.allocUtf8String('r')).value;
    logger.info({ tag: 'sysread' }, `${fd} $ ${file}`);
    if (fd === -1) return null;

    let text = '';
    const size = 0x4000;
    const buffer = Memory.alloc(size);
    let nread: NativePointer;
    while (!isNully((nread = Libc.fgets(buffer, size, file)))) {
        const line = buffer.readCString();
        if (!line.includes('/tmp')) text += line;
    }
    Libc.fclose(file);
    Libc.close(fd);

    return text;
}

//setTimeout(() => {
//    const dir = '/data/data/com.reveny.nativecheck/files';
//    Libc.system(Memory.allocUtf8String(`mkdir -p ${dir}`));
//
//    // @ts-ignore
//    File.writeAllText(`${dir}/fake_maps`, File.readAllText('/proc/self/maps'));
//});

Object.defineProperty(global, 'keysJs', {
    value: (str: string) => {
        findClass('d.try')?.type(`
            var tryNull = (x) => {
                var r = null;
                try {
                    r = x();
                } catch (e) {}
                return r;
            };
            var __iterAs = (a) => {
                var keys = null;
                try {
                    keys = Object.keys(a);
                } catch(e) {
                }
                return keys !== null ? keys : null;
            };
            var sss = ${str};
            __iterAs(sss)?.forEach(x => {
                tryNull(() => {console.log(x)});
            });`);
    },
});
Object.defineProperty(global, 'evalJs', {
    value: (str: string) => {
        findClass('d.try')?.type(`
            var __this;
            __this = this;
            var __iterAs = null;
            __iterAs = (a) => {
                var keys = null;
                try {
                    keys = Object.keys(a);
                } catch(e) {
                }
                return keys !== null ? keys : null;
            };
            var ej = null;
            ej = (sss, depth) => {
                sss = sss?.toString();
                var pp = ' '.repeat(depth * 2);
                var refget = (x, y) => {
                    var z = null;
                    try {
                        z = Reflect.get(x, y);
                    } catch (e) {}
                    return z;
                };
                var be = sss?.split('.')?.reduce?.((p, c) => (p === null) ? refget(__this, c) : refget(p, c), null);
                var lm = JSON.stringify({ arg0: sss, type: typeof be, value: new String(be) });
                console.log(lm);
                __iterAs(be)?.forEach((key) => {
                    var fk = [sss, key].join('.');
                    if ((key === 'window' || key === 'parent' || key === 'top') && fk.startsWith('window')) return;
                    if (depth > 4) return;
                    ej(fk, depth+1);
                });
            };
            ej('${str}', 0);`);
    },
});
Object.defineProperty(global, 'setJs', {
    value: (str: string, key: string, val: any) => {
        findClass('d.try')?.type(
            `var ejv; ejv = (sss, kkk, vvv) => { var pr = sss?.toString(); var be = pr.split('.').reduce((p, c) => Reflect.get(p !== null ? p : this, c), null); console.log(pr, be, Reflect.get(be, kkk)); console.log(be[kkk] = val); }; ejv('${str}', '${key}', ${val});`,
        );
    },
});
