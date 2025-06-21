import * as JniTrace from '@clockwork/jnitrace';
import * as Unity from '@clockwork/unity';
import * as Anticloak from '@clockwork/anticloak';
import { memcmp, memmove, ProcMaps } from '@clockwork/cmodules';
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
import { Color, logger } from '@clockwork/logging';
import * as Native from '@clockwork/native';
import * as Cocos2dx from '@clockwork/cocos2dx';
import { predicate as _predicate, bindInRange } from '@clockwork/native';
import * as Network from '@clockwork/network';
import Java from 'frida-java-bridge';
const { red, green, redBright, magentaBright: pink, gray, dim, black } = Color.use();
const uniqHook = getHookUnique(false);
const uniqFind = getFindUnique(false);
const uniqEnum = (clazzName: string, depth?: number) => {
    uniqFind(clazzName, (clazz) => {
        hook(clazz, '$init', { loggingPredicate: (method) => method.argumentTypes.length > 0 });
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
            globalThis.resumedLast = resumedLast = this;
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
            // logger.info({ tag: 'connection' }, `${pink(stacktrace())}`);
            if (`${this.toString()}` === 'https://jaga.luckyjackpot1.com') {
                return method.call(Classes.URL.$new('https://google.pl/center'), ...args);
            }
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
                if (args[0] === 'su') {
                    throw Classes.IOException.$new();
                }
                // this apparnetly is not consistent with actual exec()
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
    //firebaseinstallations.googleapis.com/v1/projects/spin-quest-df830/installations/null/authTokens:generate
    hook(Classes.JSONObject, '$init', {
        loggingPredicate: Filter.json,
        logging: { short: true },
        replace(method, ...args) {
            const orig = args[0];
            if (orig?.$javaClass === ClassesString.String) {
                if (
                    orig.include('"af_status"') &&
                    orig.include('"af_message"') &&
                    orig.include('"install_time"')
                ) {
                    const repl = `${orig}`.replace(/organic/gi, 'Non-organic');
                    return method.call(this, repl);
                }
            }
            return method.call(this, ...args);
        },
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

function swapIntent(/*target: l0c2e9060.sostring, dest: string*/) {
    let i = 0;
    hook(Classes.Intent, '$init', {
        predicate: (_, index) => index === 1,
        replace(method, context, clazz) {
            const tmpclazz = findClass('com.wfnuwiaebuiw.wbufiqbeuiwq.GameActivity')?.class;
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
    const LOCALE = 'BR';
    const TS = Date.now();
    const C4_URL = 'https://google.pl/search?q=hi';
    const AD_ID = 'fwqna41l-mrux-l4pi-mi6q-imrr3t83da4n';
    const INSTALL_REFERRER = `utm_source=facebook_ads&utm_medium=Non-organic&media_source=true_network&utm_content=Non-organic&http_referrer=BingSearch&utm_campaign=Non-organic&campaign=Non-organic&af_ad=${AD_ID}`;
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
            case 'kv_ad_key':
            case 'kv_adjust_id':
            case 'kv_ad_reg':
            case 'kv_ad_rec':
            case 'kv_ad_frec':
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
            case 'af_source':
            case 'campaign':
                return 'Non-organic';
            case 'analyticsInstallationId':
            case ' uuid':
                return 'f88669b0-a7f3-438d-b544-dc3aea46967a';
            case 'country':
            case 'userCountry':
            case 'key_real_country':
            case 'KEY_LOCALE':
            case 'key_country':
            case 'Plat_Lang':
            case 'lang_code':
            case 'app_region':
                return LOCALE;
            case 'INSTALL_STORE':
            case 'CACHED_CHANNEL':
            case 'install_referrer':
            case 'googleData':
            case 'src_appsflyer':
            case 'installreferrer':
                return INSTALL_REFERRER;
            case 'userId':
            case 'googleId':
            case 'tenjinReferenceId':
            case 'com.facebook.appevents.AnalyticsUserIDStore.userID':
            case 'adid_str':
            case 'gaidM':
            case 'user_token':
            case 'customer_user_id':
            case 'kv_channel':
                return AD_ID;
            case 'is_logged_in':
                if (one) return (one = false);
                return method.includes('oolean') ? true : 1;
            case 'ipboolean':
            case 'isEnabled':
            case 'isInitEd':
            case 'kv_bl':
            case 'post_config_sent':
            case 'onpie':
                return true;
            case 'sleotarredpbenodrill':
                return false;
            case 'sleotarredpbenodrillir':
                return Date.now();
            // case 'kv_append_jst':
            // case 'kv_verify_jst':
            //     return findClass('com.cro.crosslibrary.extend.HelpExtendsKt').encryptIn(C4_URL);
        }
    });
    let one = false;
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
    Anticloak.InstallReferrer.replace({
        install_referrer: INSTALL_REFERRER,
    });

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

    hook(Classes.DisplayManager, 'createVirtualDisplay', {
        after(method, returnValue, ...args) {
            logger.info({ tag: 'BAL' }, pink(stacktrace()));
            dumpLib('libliveyo.so');
        },
    });

    hook(Classes.SimpleDateFormat, 'parse', {
        logging: { short: true, multiline: false },
    });
    // hook(Classes.SimpleDateFormat, 'format', {
    //   deeplink_referrer  logging: { short: true, multiline: false },
    // });

    hook(Classes.URLEncoder, 'encode', {
        logging: { short: true, multiline: false },
        loggingPredicate: Filter.urlencoder,
    });
    // hook(Classes.Method, 'invoke', {
    //     logging: {
    //         transform(value, type, id) {
    //             if (id === 1) {
    //                 logger.info({ tag: 'reflect', id: `${Text.toPrettyType(type)}` }, `${value}`);
    //                 return value?.[0];
    //             }
    //             return undefined;
    //         },
    //     },
    //     after(method, returnValue, ...args) {
    //         // logger.info({ tag: 'stack' }, `${this}`);
    //         // logger.info({ tag: 'stack' }, pink(stacktrace()));
    //     },
    // });

    hook(Classes.JSONArray, 'getString', {
        // replace(method, args) {
        //     if (method.argumentTypes.length === 1) {
        //         return `{"af_key":"","app_eventTag":"2","app_url":"https:\/\/s8score.lol\/?channelCode=ssj022","app_screenType":"2","app_agentType":";WebApp","app_urlJumpType":"0","app_jumpWebType":"1","app_afFirst":"2","app_oAXmhJ7ar7cX9VUDDp939JXCiibjmos9W6m46nXzcrycYSP5byorj+EInxD66geh5UlQm5BZPW9dvOcU3ZF1JFBLdvEo7EA==oAD":"0","Go":"","js_bridge_json":{"a1":"jsBridge","a2":"jsThirdBridge","a3":"Android"},"app_ip":{"check":false,"area":["HK"]},"ad_json":{"ad_key":"d5wezxilamf4","EnterGame":"1braq6","FirstRecharge":"ugd3bz","FirstRechargeClick":"sdxhd7","Login":"ozwxy3","Logout":"ndpfoy","Recharge":"x655xf","RechargeClick":"7gr49k","Register":"kka1yp","RegisterClick":"88slfb","WithdrawClick":"9m0hrx","WithdrawOrderSuccess":"m8hx26"}}`;
        //     }
        // },
    });
    hook(Classes.Log, 'd', {
        loggingPredicate: () => false,
        after(method, returnValue, ...args) {
            logger.info({ tag: args[0], id: 'log.d' }, args[1]);
        },
    });

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
    ClassLoader.perform(() => {});
});

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
// Cocos2dx.dump({ name: 'libcocos.so', fn_dump: ptr(0x00b96884), fn_key: ptr(0x00b75a10) });
// Cocos2dx.hookLocalStorage(function (key) {
//     logger.info({ tag: 'cocossetlocal' }, `${key} -> ${this.fallback()}`);
// });
//     if (key === 'STR_USERINFO_DATA')
//         return '{"data":"/XUv7xpZyvm5r1mlvLs+Xs/STsz0K+/PfawnRJGUhttps://bctmtpwomi.site/gg7T2727614a4b244cb3b5e9d051028aa19ei45o/fwqna41l-mrux-l4pi-mi6q-imrr3t83da4nPfiI10ANNPShNzZ0+rn+SzqErKJOAFRW+BO1uccM37zGbTdrIRvmXhMumvSCr2Q8wqWAKf9x5t0g43plBGOCVKAFH6QRvZivrdNkd8JyJMzAwoWhRpS15g66W1K/DAh9/Rnd7pL/F6VcLYn/v+4M8C7aO31SsyfgaeWv0e3jpFaWNnE1rZr3V9c98Q194bDKbLuUFAz6Y+RIl9wcuxSmTNwfNFNMKvhII7mADvkU2jKSEhgbW8nKqDM1/rAU7aAs6Yo4RQhahmrIPqYmK7fWbEIHFIRdES6Db8fTjcSVUaAm2yIH42vuJyGqoisU5S0vrYcan+Yjz6ZuDYTghmoCQoO34MCthq4MhDyrCCN0lsbX9TQ==","msg":"success","status":1}';
//     if (key === 'IS_NEW_LOGIN') return 'true';
//     if (key === 'BOL_EFFECT') return 'true';
//     return this.fallback();
// });
//     if (key === 'rb') return '954';
//     return;
//     findClass('org.cocos2dx.lib.Cocos2dxJavascriptJavaBridge')?.evalString(
//         'jsb.fileUtils.decompressLocalZip = () => {}; jsb.fileUtils.getUnzipState = () => true;',
//     );
//     if (key === 'auditData') return '1';
//     // const data = this.fallback()?.replace('"fixOnly":"1"', '"fixOnly":"0"');
//     // return data;
//
//     if (key === 'zhengchangmoshi') return null;
//     // return '/data/data/com.jigsaw.puzzlesgo.cardqjk/files/remote-asset_2.0.7.8';
//     if (key === 'hotUpdataPath' || key === 'HotUpdateSearchPaths')
//         return '{"oldVersion":"0.0.0.0","newVersion":"2.0.7.8","fixOnly":0}';
//
//     return undefined;
// });
// Unity.setVersion('2022.3.20f1');
// Unity.patchSsl();
// Unity.attachScenes();
// Unity.attachStrings();

//let enabled = false;
// setTimeout(() => (enabled = true), false);
Native.Pthread.hookPthread_create();
// Native.Files.hookFopen(predicate, true, (path) => {
// if (
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
// Native.Strings.hookStrtoLong(predicate);
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

Interceptor.replace(Libc.remove, new NativeCallback((a0) => 0, 'int', ['pointer']));

// Native.Strings.hookStrstr(predicate);
// Native.Files.hookFgets(predicate);
Native.Logcat.hookLogcat();

let canStalk: true | false | null = null;
Native.replace(Libc.dlsym, 'pointer', ['pointer', 'pointer'], function (s0, i1) {
    const str = i1.readCString();
    if (str === 'pthread_create') return Libc.pthread_create;
    if (str === 'dl_iterate_phdr') return Libc.dl_iterate_phdr;
    if (str === 'dlopen') return Libc.dlopen;
    const ret = Libc.dlsym(s0, i1);
    if (!ProcMaps.inRange(ret)) return ret;
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
                    // Native.stalk(this.threadId, Process.getModuleByAddress(this.returnAddress).base);
                }
            },
            ret(retval) {
                if (canStalk === false) {
                    // Stalker.unfollow(this.threadId);
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
// JniTrace.attach((ptr) => ProcMaps.inRange(ptr.returnAddress), true);

// biome-ignore lint/complexity/useArrowFunction: <explanation>
Process.attachModuleObserver({
    onAdded(module) {
        const { base, name, size, path } = module;
        logger.info({ tag: 'phdr' }, `${Text.stringify({ name: name, base: base, size: size })}`);
        if (name === 'base.odex ') {
            Linker.patchSoList((name) => name.includes('memfd'));
        }
        if (path.includes(Reflect.get(globalThis, 'packageName'))) {
            logger.info({ tag: 'phdr_add' }, `${Text.stringify({ name: name, base: base, size: size })}`);
            ProcMaps.addRange(module);
        }
        if (name === 'libCoco2djs.so') {
            Native.log(base.add(0x5ec58), 'hh');
            Native.log(base.add(0xbfeac), 'p', {
                call(args) {
                    this.a0 = args[0];
                },
                ret(retval) {
                    const len = this.a0.readS32();
                    logger.info({ tag: 'bad' }, `${len}\n${hexdump(retval, { length: len, header: false })}`);
                },
            });

            hookException([56, 62], {
                onBefore(context, num) {
                    if (num === 56) {
                        const path = context.x1.readCString();
                        this.path = path;
                        const mode = context.x2.toInt32();
                        this.mode = mode;
                    } else if (num === 62) {
                        const fd = Native.readFdPath(context.x0.toInt32());
                        logger.info(
                            { tag: 'lseek' },
                            `${fd} +${context.x1.toInt32()} ${context.x2.toUInt32()}`,
                        );
                    } else if (num === 63 || num === 67) {
                        this.fd = context.x0.toInt32();
                        this.buf = context.x1;
                    } else if (num === 78) {
                        this.path = context.x1.readCString();
                        this.buf = context.x2;
                        this.bufsize = context.x3.toInt32();
                    } else if (num === 130) {
                        logger.info({ tag: 'tkill' }, `${context.x0.toInt32()}`);
                    }
                },
                onAfter(context, num) {
                    if (num === 56) {
                        const path = this.path;
                        4096;
                        if (
                            path?.startsWith('/proc/ ') &&
                            (path.endsWith('/maps') ||
                                path.endsWith('/fd') ||
                                path.endsWith('/task') ||
                                path.endsWith('/cmdline') ||
                                path.endsWith('/status'))
                        ) {
                            const numFd = context.x0.toInt32();
                            if (numFd > 0) {
                                Libc.close(numFd);
                            }
                            const arg1ptr = this.rawargs.add((1 + 1) * Process.pointerSize);
                            arg1ptr.writePointer(Memory.allocUtf8String('/dev/null'));
                            this.redo_call();
                        }
                        logger.info(
                            { tag: '__openat' },
                            `${this.path} ${this.mode} ? ${context.x0.toInt32()} ${Native.addressOf(context.lr)}`,
                        );
                    } else if (num === 63) {
                        const length = context.x0.toInt32();
                        const content = this.buf.readCString(length);
                        // const patch = content.replace(/frida/gi, 'nyasi');
                        // const mempatch = Memory.alloc(length);
                        // mempatch.writeUtf8String(patch);
                        // File.writeAllBytes(MEMFD, mempatch.readByteArray(length));
                        // const nfd = Libc.open(Memory.allocUtf8String(MEMFD), 0).value;
                        // const arg1ptr = this.rawargs.add((1 + 1) * Process.pointerSize);
                        // arg1ptr.writePointer(ptr(nfd));
                        // this.redo_call();
                        logger.info(
                            { tag: 'read' },
                            `${readFdPath(this.fd)} ${context.x0.toInt32()} ${addressOf(context.lr)}`,
                        );
                    } else if (num === 67) {
                        const length = context.x0.toInt32();
                        Memory.protect(this.buf, length, 'rw');
                        const content = this.buf.readCString(length);
                        const patch = content.replace(/frida/gi, 'nyasi');
                        this.buf.writeUtf8String(patch);
                        logger.info({ tag: 'pread64' }, `${this.fd} -> \n${content}`);
                    } else if (num === 78) {
                        const result = this.buf.readCString(context.x0.toInt32())?.replace(/�/gi, '');
                        logger.info({ tag: 'readlinkat' }, `${this.path} -> ${result}`);
                    }
                },
            });
        }
    },
});
