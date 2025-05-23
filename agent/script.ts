import * as Anticloak from '@clockwork/anticloak';
import * as Cocos2dx from '@clockwork/cocos2dx';
import * as Unity from '@clockwork/unity';
import { ProcMaps } from '@clockwork/cmodules';
import {
    Classes,
    ClassesString,
    Consts,
    Linker,
    Struct,
    Text,
    emitter,
    enumerateMembers,
    findChoose,
    findClass,
    getFindUnique,
    hookException,
    isNully,
    stacktrace,
    tryNull,
} from '@clockwork/common';
import { dumpLib, initSoDump } from '@clockwork/dump';
import { ClassLoader, Filter, always, compat, getHookUnique, hook, ifKey } from '@clockwork/hooks';
import * as JniTrace from '@clockwork/jnitrace';
import { Color, logger } from '@clockwork/logging';
import * as Native from '@clockwork/native';
import { predicate as _predicate, bindInRange } from '@clockwork/native';
import * as Network from '@clockwork/network';
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

logger.info({ tag: 'processid' }, `${Process.id}`);
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
            (rpc.exports as any).resumedLast = resumedLast = this;
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
        replace(method, ...args) {
            logger.info({ tag: 'connection' }, `${Color.url(this.toString())}`);
            logger.info({ tag: 'connection' }, `${pink(stacktrace())}`);
            return method.call(this, ...args);
        },
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
                        logger.info({ tag: 'call' }, pink(stacktrace()));
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
            logger.info({ tag: 'send' }, pink(stacktrace()));
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
            logger.info({ tag: 'read' }, pink(stacktrace()));
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
    const mReplace = (arg: string) => {
        let sArg = arg.replace(/su$/g, 'echo');
        sArg = sArg.replace(/^rm -r/g, 'file ');
        sArg = sArg.replace(/^getprop/g, 'echo');
        sArg = sArg.replace(/^mount/g, 'echo');
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
                            sb += Text.toHex(b);
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
                // logger.info({ tag: 'decrypt' }, pink(stacktrace()));
            }
        },
        logging: { arguments: false, return: false },
    });
}

function hookJson(fn?: (key: string, method: string, fallback: () => Java.Wrapper) => any) {
    const logging = { multiline: false, short: true, call: false, return: false };
    const getOpt = ['get', 'opt'];
    const types = ['Boolean', 'Double', 'Int', 'JSONArray', 'JSONObject', 'Long', 'String'];

    hook(Classes.JSONObject, '$init', {
        loggingPredicate: Filter.json,
        logging: { short: true },
        predicate: (_, index) => index !== 0,
    });

    hook(Classes.JSONObject, 'has', {
        loggingPredicate: Filter.json,
        logging: logging,
        replace(method, key) {
            const bound = method.bind(this, key);
            const found = fn?.(key, 'has', bound) !== undefined;
            return found || bound();
        },
    });

    for (const item of getOpt) {
        hook(Classes.JSONObject, item, {
            loggingPredicate: Filter.json,
            logging: logging,
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
                logging: logging,
                replace(method, ...args) {
                    const bound = method.bind(this, ...args);
                    const value = fn?.(args[0], name, bound);
                    return value !== undefined ? value : bound();
                },
            });
        }
    }
    // hook(Classes.JSONObject, 'put')
}

function hookPrefs(fn?: (key: string, method: string) => any) {
    const keyFns = ['getBoolean', 'getFloat', 'getInt', 'getLong', 'getString', 'getStringSet'];

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
    hook('android.app.IActivityManager$Stub$Proxy', 'registerReceiverWithFeature', {
        predicate: (overload, i) => `${overload.argumentTypes[overload.argumentTypes.length - 1]}` === 'I',
        replace(method, ...args) {
            const EXPORTED = Classes.Context.RECEIVER_EXPORTED.value;
            const NOT_EXPORTED = Classes.Context.RECEIVER_NOT_EXPORTED.value;
            if (`${method.argumentTypes[method.argumentTypes.length - 1]}` === 'I') {
                args[method.argumentTypes.length - 1] |= EXPORTED;
                args[method.argumentTypes.length - 1] &= ~NOT_EXPORTED;
            }

            const ret = method.call(this, ...args);
            // logger.info({ tag: 'why' }, `${ret}`);
            return ret;
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

    hook('android.os.UserHandle', 'isCore', {
        replace: always(true),
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
    // const ipp = Java.use('android.app.ActivityThread').installProvider;
    // let i = 0;
    // ipp.implementation = function (...args) {
    //     console.log(i);
    //     return i++ !== 0 ? ipp.call(this, ...args) : null;
    // };
    const LOCALE = 'IN';
    const TS = Date.now();
    const C4_URL = 'https://google.pl/search?q=hi';
    const AD_ID = 'fwqna41l-mrux-l4pi-mi6q-imrr3t83da4n';
    const INSTALL_REFERRER = `utm_source=facebook_ads&utm_medium=Non-organic&media_source=true_network&http_referrer=BingSearch&utm_campaign=Non-organic&campaign=Non-organic&af_ad=${AD_ID}`;
    hookActivity();
    hookWebview(true);
    hookNetwork();
    hookFile();
    hookJson((key, _method, fallback) => {
        switch (key) {
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
            case 'pia_token':
                return '85208303447208243';
            case 'adafkey':
                return AD_ID;
        }
    });
    hookPrefs((key, method) => {
        switch (key) {
            case 'counsel':
                return TS;
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
            case 'AF_CAMPAIGN':
                return 'Non-organic';
            case 'uuid':
                return 'f88669b0-a7f3-438d-b544-dc3aea46967a';
            case 'country':
            case 'userCountry':
            case 'key_real_country':
            case 'KEY_LOCALE':
            case 'key_country':
            case 'Plat_Lang':
                return LOCALE;
            case 'INSTALL_STORE':
            case 'CACHED_CHANNEL':
            case 'install_referrer':
                return INSTALL_REFERRER;
            case 'userId':
            case 'googleId':
            case 'com.facebook.appevents.AnalyticsUserIDStore.userID':
            case 'adid_str':
            case 'gaidM':
            case 'user_token':
                return AD_ID;
            case 'is_logged_in':
                if (one) return (one = false);
                return method.includes('oolean') ? true : 1;
            case 'CirclesColor':
                return C4_URL;
            case 'CallRecSuccess':
                return true;
        }
    });
    let one = true;
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

    // Anticloak.Debug.hookDigestEquals();
    Anticloak.Debug.hookVerify();
    Anticloak.generic();
    Anticloak.hookDevice();
    Anticloak.hookSettings();
    Anticloak.hookNetwork();
    Anticloak.hookAdId(AD_ID);
    Anticloak.hookPackageManager();
    Anticloak.Country.mock(LOCALE);
    // Anticloak.InstallReferrer.replace({
    //     install_referrer: INSTALL_REFERRER,
    // });

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
    // hook(Classes.SimpleDateFormat, 'format', {
    //     logging: { short: true, multiline: false },
    // });

    hook(Classes.URLEncoder, 'encode', {
        logging: { short: true, multiline: false },
        loggingPredicate: Filter.urlencoder,
    });
    // hook(Classes.Method, 'invoke', {
    //     logging: {
    //         transform(value, type, id) {
    //             if (id === 1) {
    //                 logger.info({ tag: 'reflect', id: `${toPrettyType(type)}` }, `${value}`);
    //                 return value?.[0];
    //             }
    //             return undefined;
    //         },
    //     },
    // });

    hook(Classes.File, 'delete', {
        replace: always(true),
        after(method, returnValue, ...args) {
            logger.info({ tag: 'file', id: '!' }, `${this}`);
        },
        logging: { call: false, return: false },
    });
    hook(Classes.DexPathList, '$init', {
        logging: { short: true, multiline: false },
    });

    const conf = { logging: { short: true, multiline: false } };
    ClassLoader.perform(() => {
        uniqHook('com.nuifwae.webdex.LaunchManager$1', 'onComplete', {
            replace(method, ...args) {
                return method.call(this, true);
            },
        });

        uniqFind(
            'zTgS7MlYtQFpAYRdmnNBGpIaXKYW12THHyFFH6Tib6oJkhTWknfg.YKxMHgCuKs9wVVZdl54qbgQayKYQCwRrz0I8YAVh3qskD9ZvCrnLuXx7kcxtfZ54W1TDWYfspcVgyvPzGOqcgOAsVMsq',
            (clz) => {
                enumerateMembers(
                    clz,
                    {
                        onMatchMethod(clazz, member, depth) {
                            hook(clazz, member);
                        },
                    },
                    1,
                );
            },
        );
    });
});

emitter.on('so', (a0) => dumpLib(a0));

// initSoDump();
Native.initLibart();
Network.injectSsl();
Network.injectCurl();

Network.flutterInjectSsl();
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

// Cocos2dx.replace(ptr(0x007ecaf4), 'libcocos2djs.so');
// Cocos2dx.dump({ name: 'libcocos2djs.so', fn_dump: ptr(0x006edf7c), fn_key: ptr(0x006248e0) });
// Cocos2dx.hookLocalStorage(function (key) {
//     logger.info({ tag: 'cocossetlocal' }, `${key} -> ${this.fallback()}`);
//
//     if (key === 'BinFenShuiGuo_DB') return '{}';
//     if (key === 'getItem') return 'true';
//     if (key === 'organic' || key === 'is->retaddr')
//         return 'utm_source=facebook_ads&utm_medium=Non-organic&media_source=true_network&http_referrer=BingSearch&utm_campaign=Non-organic&campaign=Non-organic&af_ad=${AD_ID}';
//     if (key === 'ANDROID_ID') return 'fwqna41l-mrux-l4pi-mi6q-imrr3t83da4n';
//
//     return undefined;
// });
// Unity.setVersion('2021.3.45f1c1');
Unity.patchSsl();
Unity.attachScenes();
Unity.attachStrings();

//let enabled = false;
// setTimeout(() => (enabled = true), false);
Native.Pthread.hookPthread_create({
    before(returnAddress, startRoutine) {
        if (Native.addressOf(returnAddress).includes('0x1ee6bc')) {
            logger.info(
                { tag: 'badthread' },
                `${DebugSymbol.fromAddress(startRoutine)} ${Native.addressOf(startRoutine)}`,
            );
            const dss = Process.getModuleByAddress(returnAddress).getExportByName('doSetShellState');
            new NativeFunction(dss, 'pointer', ['int'])(0x90);
            return 1;
        }
    },
});
// Native.Files.hookFopen(predicate, true, (path) => {
//     if (
//         path?.endsWith('/proc/net/tcp') ||
//         path?.endsWith('/comm') ||
//         path?.endsWith('/smaps') ||
//         path?.includes('/proc/self/environ')
//     ) {
//         return '/dev/null';
//     }
//     if (path?.endsWith('/su') || path?.endsWith('/mountinfo')) {
//         return path.replace(/\/(su|mountinfo)$/, '/nya');
//     }
//     if (
//         path?.includes('magisk') ||
//         path?.includes('supolicy') ||
//         path?.toLowerCase()?.includes('superuser')
//     ) {
//         return path.replace(/(magisk|supolicy|superuser)/gi, 'nya');
//     }
// });
//
//Native.Strings.hookStrtoLong(predicate);
Native.hookGlGetString();
Network.attachGetAddrInfo(false);
Native.System.hookGetauxval();
Native.System.hookSystem();
Native.System.hookPopen();
Native.TheEnd.hook(predicate);

// Interceptor.attach(Libc.vsnprintf, {
//     onEnter(args) {
//         this.dst = args[0];
//     },
//     onLeave(retval) {
//         if (Native.Inject.isInOwnRange(this.returnAddress)) {URL_PREFIX
//             const text = this.dst.readCString();
//             logger.info({ tag: 'vsnprintf' }, `${text} ${Native.addressOf(this.returnAddress)}`);
//         }
//     },
// });
//     onEnter(args) {
//         this.dst = args[0];
//     },
//     onLeave(retval) {
//         if (Native.Inject.isInOwnRange(this.returnAddress)) {
//             const text = this.dst.readCString();
//             logger.info({ tag: 'sprintf' }, `${text}`);
//         }
//     },
// });

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
            //    logger.info({ tag: 'nanosleep' }, ead`${Native.addressOf(this.returnAddress)}`);
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
            // const retval = 0;
            logger.info({ tag: 'fork' }, `${retval} ${Native.addressOf(this.returnAddress)}`);
            ProcMaps.printStacktrace(this.context, 'fork');
            return retval;
        },
        'int',
        [],
    ),
);

Native.Strings.hookStrstr(predicate);
// Native.Files.hookFgets(predicate);
Native.Logcat.hookLogcat();
let canStalk: true | false | null = null;
Native.replace(Libc.dlsym, 'pointer', ['pointer', 'pointer'], function (s0, i1) {
    const str = i1.readCString();
    if (str === 'pthread_create') return Libc.pthread_create;
    if (str === 'dlopen') return Libc.dlopen;
    const ret = Libc.dlsym(s0, i1);
    if (!Native.Inject.isWithinOwnRange(this.returnAddress)) return ret;
    const addr = Native.addressOf(this.returnAddress);
    const debug = DebugSymbol.fromAddress(ret);
    logger.info({ tag: 'dlsym' }, `${str} -> ${debug} ${addr}`);

    if (!isNully(ret) && str === 'JNI_OnLoad') {
        Native.log(ret, 'pp', {
            tag: str,
            call(args) {
                logger.info({ tag: 'stalk' }, `hi: ${canStalk}`);
                if (canStalk === true) {
                    canStalk = false;
                    Native.stalk(this.threadId, Process.getModuleByAddress(this.returnAddress).base);
                }
            },
            ret(retval) {
                if (canStalk === false) {
                    Stalker.unfollow(this.threadId);
                    canStalk = true;
                }
            },
        });
    }
    return ret;
});

Native.Time.hookTime(Native.Inject.isInOwnRange);
Anticloak.Debug.hookPtrace();
Java.deoptimizeEverything();
JniTrace.attach((ptr) => Native.Inject.isInOwnRange(ptr.returnAddress), true);
// biome-ignore lint/complexity/useArrowFunction: <explanation>
Native.Inject.onPrelinkOnce(function (module) {
    const { base, name, size, path } = module;

    logger.info({ tag: 'phdr' }, `${Text.stringify({ name: name, base: base, size: size })}`);
    if (name === 'base.odex') {
        Linker.patchSoList((name) => name.includes('memfd'));
    }
    if (name === 'libmain2.so ') {
        // Native.memWatch(base.add(0xd39b8), 0x8, (x) => console.log(x.address.readCString()));
        // let x = 0;
        // Native.log(base.add(0x78b34), '', {
        //     call(args) {
        //         Native.stalk(this.threadId, base);
        //     },
        // });
        // Native.memWatch(base.add(0xc5086), 0x8, (all) => {
        //     logger.info({ tag: 'memwatch' }, `${all.address.readPointer()} <- ${all.address} <- ${all.from}`);
        // });

        // Native.log(base.add(0xb4e0c), 'ppp', {
        //     call({ 0: a0, 1: a1, 2: a2 }) {
        //         const chars = JniTrace.asFunction(a0, JniTrace.JNI.GetStringUTFChars);
        //
        //         logger.info(
        //             { tag: 'chars' },
        //             `${chars} ${chars.readCString()} ${ProcMaps.printStacktrace(this.context)}`,
        //         );
        //     },
        // });
        //
        Native.log(Libc.dl_iterate_phdr, 'psp', { predicate: Native.Inject.isInOwnRange });

        // Hide.hiddenSoExecSegmentInMaps(path);

        // Native.log(base.add(0xb094), 'hii');
        // Native.lo0x3128d8g(base.add(0xb248), 'pspi', {
        //     call(args) {
        //         const _base = args[0].readPointer().sub(base);
        //         const count = args[0].add(0x8).readPointer();
        //         const check = args[0].add(0x28).readPointer();
        //         logger.info({ tag: 'stuct' }, `${_base} ${count} ${check}`);
        //     },
        // });

        // const addrs = [0x8b3e8];
        // for (const off of addrs) {
        //     const addr = base.add(off);
        //     Memory.patchCode(addr, 8, () => {
        //         const writer = new Arm64Writer(addr);
        //         writer.putNop();
        //         writer.flush();
        //     });
        // }
        //
        // Native.log(base.add(0x8b3e8), '', { logcat: true });
        // Native.log(base.add(0xddf68), 'ss');
        // Native.log(base.add(0x8b70ac), '');
        // Native.log(base.add(0x11fc10), '');
        // Native.log(base.add(0xa40f4), '');
        // Native.log(base.add(0xa2b40), '', {
        //     logcat: true,
        // });
        // Natilibjiagu.sove.log(base.add(0x10b4c), 'pp');
        // Native.log(base.add(0x1e6650), 'si');

        Native.log(Libc.dladdr, 'pp', {
            predicate: bindInRange(module),
        });
        // Native.log(Libc.mprotect, 'rp', {
        //     base: base,
        //     predicate: bindInRange(module),
        // });
        // Native.log(Libc.fopen64, 'si', {
        //     predicate: bindInRange(module),
        // });
        // Native.Files.hookOpendir(bindInRange(module), (dir) => {
        //     if (dir.startsWith('/proc/') && dir.endsWith('/fd')) return '/dev/null';
        // });
        // Native.Files.hookDirent(bindInRange(module));
        // Native.Files.hookFopen(bindInRange(module));

        // Native.Files.hookAccess(bindInRange(module));
        // Native.Files.hookRemove(bindInRange(module), () => true);
        // Native.Files.hookReadlink(bindInRange(module));
        //
        // Native.Strings.hookStrlen(bindInRange(module));
        // Native.Strings.hookStrcmp(bindInRange(module));

        // // Native.Strings.hookStrtok(bindInRange(module));
        // Native.Strings.hookStrcpy(bindInRange(module));
        // Native.Strings.hookStrchr(bindInRange(module));
        // Native.Strings.hookStrcat(bindInRange(module));
        // Native.log(Module.getExportByName(null, 'android_set_abort_message'), 's');
        // Native.log(Libc.mmap, 'ppp', { predicate: Native.Inject.isInOwnRange });
        hookException([56], {
            onBefore(context, num) {
                if (num === 56) {
                    const path = context.x1.readCString();

                    if (name.includes('frida') || path.includes('/proc')) {
                        // Memory.protect(context.x1, 10, 'rw');
                        // context.x1.writeUtf8String('/dev/null');
                        context.x1 = Memory.allocUtf8String('/dev/nya');
                        logger.info(
                            { tag: 'openat' },
                            `${path} -> ${context.x1.readCString()} ${context.x2} ${context.x3} ${context.x4}`,
                        );
                    } else {
                        logger.info({ tag: 'openat' }, `${path} ${context.x2} ${context.x3} ${context.x4}`);
                    }
                } else if (num === 172) {
                    logger.info({ tag: 'getpid' });
                } else if (num === 174) {
                    logger.info({ tag: 'getuid' });
                }
                if (num === 67) {
                    // const fd = Native.readFdPath(context.x0.toInt32());
                    const buf = context.x2;
                    logger.info({ tag: 'pread64' }, `${buf}`);
                }
            },
        });
        // //
        // Native.log(
        //     Process.getModuleByName('libart.so')
        //         .enumerateSymbols()
        //         .filter((x) => x.name.includes('art_sigsegv_fault'))[0].address,
        //     '',
        //     {
        //         call(args) {
        //             ProcMaps.printStacktrace(this.context);
        //         },
        //     },
        // );
        // const lib_signal = new NativeFunction(
        //     Process.getModuleByName('libsigchain.so')
        //         .enumerateExports()
        //         .filter((x) => x.name.includes('signal'))[0].address,
        //     'int',
        //     ['int', 'pointer'],
        // );
        // Native.replace(lib_signal, 'int', ['int', 'pointer'], function (signo, handler) {
        //     logger.info({ tag: 'signal' }, `signo: ${signo} ${Native.addressOf(this.returnAddress)}`);
        //     ProcMaps.printStacktrace(this.context);
        //     return 0;
        // });
        // Native.log(
        //     Process.getModuleByName('libsigchain.so')
        //         .enumerateExports()
        //         .filter((x) => x.name.includes('signal'))[0].address,
        //     '',
        //     {
        //         call(args) {},
        //     },
        // );

        // Native.log(Libc.memcmp, '__i', {
        //     predicate: bindInRange(module),
        //     call: function (args) {
        //         this.a0 = args[0];
        //         this.a1 = args[1];
        //         this.size = args[2].toInt32();
        //     },
        //     ret: function (retval) {
        //         const line1 = hexdump(this.a1, { length: this.size, header: false });
        //         const line0 = hexdump(this.a0, { length: this.size, header: false });
        //         logger.info({ tag: 'memcmp' }, `\n${line1}\n${line0}`);
        //         logger.info({ tag: 'memcmp' }, '='.repeat(100));
        //     },
        // });
        const c: (t: string) => string = (t) => t;
        const c_strlen = (x: string) =>
            new CModule(x, {
                frida_log: new NativeCallback(
                    (str) => {
                        const msg = str.readCString();
                        logger.info({ tag: 'strlen' }, `${msg}`);
                    },
                    'void',
                    ['pointer'],
                ),
            }) as any;
        Interceptor.attach(
            Libc.strlen,
            c_strlen(
                c(`
                  #include <gum/guminterceptor.h>
                  #include <stdio.h>
                  typedef unsigned long long u64;
                  void* BASE = (void *) ${base};
                  void* SIZE = (void *) ${size};

                  typedef struct _IcState IcState;
                  struct _IcState {
                    char *arg0;
                    void *retaddr;
                    int log;
                  };

                  extern void frida_log(void *str);
                  static void mklog(const char *format, ...) {
                      gchar *message;
                      va_list args;
                      va_start(args, format);
                      message = g_strdup_vprintf(format, args);
                      va_end(args);
                      frida_log(message);
                      g_free(message);
                  }

                  void onEnter(GumInvocationContext * ic) {
                    IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
                    is->arg0 = gum_invocation_context_get_nth_argument(ic, 0);
                    is->retaddr = (void *) gum_invocation_context_get_return_address(ic);
                    if ((u64) BASE <= (u64)is->retaddr && (u64)BASE + (u64)SIZE > (u64)is->retaddr) {
                        is->log = 1;
                    } else {
                        is->log = 0;
                    }
                  };
                  void onLeave(GumInvocationContext * ic) {
                    IcState *is = GUM_IC_GET_INVOCATION_DATA(ic, IcState);
                    u64 retval = (u64) gum_invocation_context_get_return_value(ic);
                    if (is->log == 1) {
                        mklog("%s = %d %p", is->arg0, retval, (u64)is->retaddr-(u64)BASE);
                    }
                  };
                `),
            ),
        );

        const c_memmove = (x: string) =>
            new CModule(x, {
                frida_log: new NativeCallback(
                    (str) => {
                        const msg = str.readCString();
                        logger.info({ tag: 'memmove' }, `${msg}`);
                    },
                    'void',
                    ['pointer'],
                ),
                sprintf: Libc.sprintf,
                isprint: Libc.isprint,
            }) as any;
        Interceptor.attach(
            Libc.memmove,
            c_memmove(`
                  #include <gum/guminterceptor.h>
                  #include <stdio.h>
                  typedef unsigned long long u64;
                  void* BASE = (void *) ${base};
                  void* SIZE = (void *) ${size};

                  extern int sprintf(char *str, const char *format, ...);
                  extern int isprint(int ch);
                  extern void frida_log(void *str);
                  static void mklog(const char *format, ...) {
                      gchar *message;
                      va_list args;
                      va_start(args, format);
                      message = g_strdup_vprintf(format, args);
                      va_end(args);
                      frida_log(message);
                      g_free(message);
                  }

                  int count;
                  void onInit() {
                      count = 0;
                  }

                  void hex_dump(const void *ptr, size_t x) {
                      const unsigned char *p = ptr;
                      size_t i, j;
                      char line[100];

                      // mklog("Offset    | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII");
                      mklog("-----------+-------------------------------------------------+-----------------");
                      for (i = 0; i < x; i += 16) {
                          char *pos = line;
                          pos += sprintf(pos, "0x%08zx | ", i);

                          for (j = 0; j < 16; j++) {
                              if (i + j < x)
                                  pos += sprintf(pos, "%02x ", p[i + j]);
                              else
                                  pos += sprintf(pos, "   ");
                          }

                          pos += sprintf(pos, "| ");
                          for (j = 0; j < 16; j++) {
                              if (i + j < x) {
                                  unsigned char c = p[i + j];
                                  pos += sprintf(pos, "%c", isprint(c) ? c : '.');
                              } else {
                                  pos += sprintf(pos, " ");
                              }
                          }

                          mklog("%s", line);
                      }
                  }

                  void onEnter(GumInvocationContext * ic) {
                    void* a0 = gum_invocation_context_get_nth_argument(ic, 0);
                    char* a1 = gum_invocation_context_get_nth_argument(ic, 1);
                    size_t a2 = GPOINTER_TO_SIZE(gum_invocation_context_get_nth_argument(ic, 2));
                    void* retaddr = (void *) gum_invocation_context_get_return_address(ic);
                    if ((u64) BASE <= (u64)retaddr && (u64)BASE + (u64)SIZE > (u64)retaddr) {
                          mklog("%p %p %d", a0, a1, a2);
                          hex_dump(a1, a2 > 1000 ? 1000 : a2);
                    } else {
                        // mklog("%p %p %p", BASE, SIZE, retaddr);
                    }
                  }
                `),
        );
    }
});
