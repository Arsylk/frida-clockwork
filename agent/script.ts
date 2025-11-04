import * as Dump from '@clockwork/dump';
import { Coverage } from '../node_modules/@worksbutnottested/stalker-coverage/dist/coverage.js';
import * as JniTrace from '@clockwork/jnitrace';
import * as Anticloak from '@clockwork/anticloak';
import * as Unity from '@clockwork/unity';
import { LinkerSym, memcmp, memmove, ProcMaps } from '@clockwork/cmodules';
import {
  Classes,
  ClassesString,
  Consts,
  Linker,
  Std,
  Struct,
  Text,
  emitter,
  enumerateMembers,
  findChoose,
  findClass,
  getApplicationContext,
  getFindUnique,
  hookException,
  isNully,
  jarrayToBuffer,
  stacktrace,
  tryNull,
  vs,
} from '@clockwork/common';
import { dumpLib, dexBytesVerify, hookInMemoryDexDump, initSoDump } from '@clockwork/dump';
import { ClassLoader, Filter, always, compat, findHook, getHookUnique, hook, ifKey } from '@clockwork/hooks';
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

dumpLib;
logger.info({ tag: 'processid' }, `${Process.id}`);
const predicate = (ptr: NativePointer) => _predicate(ptr);

function hookActivity() {
  hook(Classes.Activity, '$init', {
    after() {
      logger.info({ tag: 'activity' }, `${gray('$init')}: ${this.$className}`);
    },
  });
  hook(Classes.Activity, 'onCreate', {
    after() {
      logger.info({ tag: 'activity' }, `${gray('onCreate')}: ${this.$className}`);
    },
    logging: { arguments: false },
  });
  hook(Classes.Activity, 'onResume', {
    after() {
      logger.info({ tag: 'activity' }, `${gray('onResume')}: ${this.$className}`);
      const clz = findClass(this.$className);
      globalThis.resumed = Java.retain(clz ? Java.cast(this, clz) : this);
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
      logger.info({ tag: 'send' }, `${this.localAddress()} -> ${this.remoteAddress()} | ${gray(`${b64}`)}`);
      logger.info({ tag: 'send' }, pink(stacktrace()));
    },
  });

  hook(Classes.DatagramChannelImpl, 'read', {
    logging: { multiline: false },
    after(method, returnValue, buffer) {
      buffer.position(0);
      const b64 = byteBufferToBase64(buffer, returnValue);
      logger.info({ tag: 'read' }, `${this.remoteAddress()} -> ${this.localAddress()} | ${gray(`${b64}`)}`);
      logger.info({ tag: 'read' }, pink(stacktrace()));
    },
  });

  hook(Classes.DatagramSocket, 'send', {
    logging: {
      multiline: false,
      transform: (value, type, id) =>
        id === 0 ? tryNull(() => [[Text.ba2hex(value.buf.value)], `${ClassesString.Object}[]`]) : value,
    },
  });

  hook(Classes.DatagramSocket, 'receive', {
    logging: {
      multiline: false,
      transform: (value, type, id) =>
        id === 0 ? tryNull(() => [[Text.ba2hex(value.buf.value)], `${ClassesString.Object}[]`]) : value,
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
        if (!`${this}`.endsWith('/no_backup'))
          logger.info({ tag: 'file', id: id }, `${gray(`${this}`)} ? ${ret}`);
      },
    });
  }
}

function hookRuntimeExec() {
  const mReplace = (arg: string) => {
    let sArg = arg;
    // sArg = sArg.replace(/su$/g, 'nya');
    // sArg = sArg.replace(/^rm /g, 'file ');
    // sArg = sArg.replace(/^getprop/g, 'echo nya');
    // sArg = sArg.replace(/^mount/g, 'echo nya');
    // sArg = sArg.replace(/^sh/g, 'echo nya');
    // sArg = sArg.replace(/^uname/g, 'echo');
    return Classes.String.$new(`${sArg}`);
  };

  // hook(Classes.Runtime, 'exec', {
  //   replace(method, ...args) {
  //     // string array
  //     if (method.argumentTypes[0].name === '[Ljava/lang/String;') {
  //       const cloned = Array(args[0].length);
  //       for (let i = 0; i < args[0].length; i += 1) {
  //         cloned[i] = mReplace(`${args[0][i]}`);
  //       }
  //       args[0] = Java.array(ClassesString.String, cloned);
  //     }
  //     // single string
  //     else {
  //       if (args[0] === 'su') {
  //         throw Classes.IOException.$new();
  //       }
  //       // this apparnetly is not consistent with actual exec()
  //       args[0] = mReplace(`${args[0]}`);
  //     }
  //     logger.info({ tag: 'process' }, `${args[0]}`);
  //     // if (`${args[0]}`.includes('nya') === false) return Classes.Runtime.exec.call(this, 'echo nya');
  //     return method.call(this, ...args);
  //   },
  // });
  hook(Classes.ProcessBuilder, 'start', {
    before(method, ...args) {
      const newlist: string[] = [];
      const command = this.command();
      for (const cmdpart of command.toArray()) {
        if (`${cmdpart}` === 'su') {
          console.log('nyanya');
          throw Classes.IOException.$new();
        }
        newlist.push(mReplace(cmdpart));
      }
      logger.info({ tag: 'process' }, `${newlist} ${pink(stacktrace())}`);
      this.command(...args);
    },
  });
}

function hookCrypto() {
  hook(Classes.SecretKeySpec, '$init', {
    logging: {
      multiline: false,
      short: true,
      transform: (value, type, id) =>
        (id === 0 || undefined) && tryNull(() => [[Text.ba2hex(value)], `${ClassesString.Object}[]`]),
    },
  });
  hook(Classes.Cipher, 'getInstance', {
    logging: { multiline: false, short: true },
  });
  hook(Classes.Cipher, 'doFinal', {
    after(method, returnValue, ...args) {
      if (this.opmode.value === 1) {
        let str = tryNull(() => Classes.String.$new(args[0], Classes.StandardCharsets.UTF_8.value));
        str ??= tryNull(() => Classes.String.$new(args[0]));
        str ??= tryNull(() =>
          (Classes.Arrays.toString as Java.MethodDispatcher).overload('[B').call(Classes.Arrays, args[0]),
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
          (Classes.Arrays.toString as Java.MethodDispatcher).overload('[B').call(Classes.Arrays, returnValue),
        );
        //@ts-ignore
        transformed ??= `${Classes.String.valueOf(returnValue)}`;
        logger.info({ tag: 'decrypt' }, `${transformed}`);

        // this can save bytes to file easily
        // const uint8s = new Uint8Array(returnValue);
        // try {
        //   File.writeAllBytes(`${Native.getSelfFiles()}/dec`, uint8s.buffer);
        // } catch (e) {
        //   console.log(e);
        // }

        logger.info({ tag: 'decrypt' }, pink(stacktrace()));
      }
    },
    logging: { arguments: false, return: false },
  });
}

function hookJson(fn?: (key: string, method: string, fallback: () => Java.Wrapper) => any) {
  const logging = { multiline: false, short: true };
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

Java.performNow(() => {
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
      case 'af_user_media_source_key':
        return 'Non-organic';
      case 'analyticsInstallationId':
      case 'uuid':
      case 'device_uuid':
      case 'adPlanId':
        return 'f88669b0-a7f3-438d-b544-dc3aea46967a';
      case 'country':
      case 'userCountry':
      case 'key_real_country':
      case 'KEY_LOCALE':
      case 'key_country':
      case 'key_language':
      case 'Plat_Lang':
      case 'lang_code':
      case 'language':
      case 'app_region':
      case 'Country':
        return LOCALE;
      case 'INSTALL_STORE':
      case 'CACHED_CHANNEL':
      case 'install_referrer':
      case 'googleData':
      case 'src_appsflyer':
      case 'installreferrer':
      case 'refer':
      case 'raw_referrers':
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
      case 'gaid':
      case 'gaidM':
      case 'gmp_app_id':
      case 'UP_ID':
      case 'AD_CHANNEL':
      case 'AD_GROUP_ID':
        return AD_ID;
      case 'is_logged_in':
        if (one) return (one = false);
        return method.includes('oolean') ? true : 1;
      case 'ipboolean':
        return true;
      // case 'ad_disable':
      case 'isInitEd':
      case 'post_config_sent':
        return false;
      case 'containsReferrerKey':
      case 'tenjinGoogleInstallContainsRbaivieteferrerKey':
        return false;
      case 'tLxueOQBY':
        return C4_URL;
    }
  });
  let one = false;
  hook(Classes.SharedPreferencesImpl$EditorImpl, 'putString', {});
  hookPreferences(() => {});
  hookFirestore();
  hook(Classes.Intent, 'getExtras', {
    before(method, ...args) {
      if (this.getAction() === 'android.hardware.usb.action.USB_STATE') {
        this.removeExtra('connected');
        this.putExtra('connected', false);
      }
    },
  });

  hook(Classes.Intent, 'getStringExtra', {
    replace(method, key) {
      if (false) {
        return C4_URL;
      }
      return method.call(this, key);
    },
  });

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
  //   install_referrer: INSTALL_REFERRER,
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

  hook(Classes.DisplayManager, 'createVirtualDisplay', {
    after(method, returnValue, ...args) {
      logger.info({ tag: 'BAL' }, pink(stacktrace()));
    },
  });

  hook(Classes.SimpleDateFormat, 'parse', {
    logging: { short: true, multiline: false },
  });
  // hook(Classes.SimpleDateFormat, 'format', {
  //   deeplink_referrer  logging: { short: true, multiline: false },
  // });

  // hook(Classes.URLEncoder, 'encode', {
  //   logging: { short: true, multiline: false },
  //   loggingPredicate: Filter.urlencoder,
  // });
  // hook(Classes.Method, 'invoke', {
  //   logging: {
  //     transform(value, type, id) {
  //       if (id === 1) {
  //         return value?.[0];
  //       }
  //       return undefined;
  //     },
  //   },
  //   after(method, returnValue, ...args) {
  //     logger.info(
  //       { tag: 'reflect' },
  //       `${this.getDeclaringClass().getName()}::${this.getName()}(${vs(args[1], `${ClassesString.Object}[]`)}): ${returnValue}`,
  //     );
  //     // logger.info({ tag: 'stack' }, pink(stacktrace()));
  //   },
  // });
  // hook(Classes.Class, 'getDeclaredMethod', { logging: { multiline: false }, predicate: (_, i) => i === 0 });

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
  // hook(Classes.File, '$init', {
  //   loggingPredicate(method) {
  //     return method.argumentTypes.length > 0;
  //   },
  //   logging: { short: true, multiline: false },
  // });
  hook(Classes.DexPathList, '$init', {
    logging: { short: true, multiline: false },
  });
  hook(Classes.Thread, 'getStackTrace', {
    // replace: always([]),
    loggingPredicate: Filter.stacktrace,
    logging: { short: true, multiline: false },
  });

  hook('android.util.Base64', 'decode', {
    loggingPredicate: Filter.base64,
    logging: { short: true, multiline: false, call: false, return: false },
    after(method, returnValue, ...args) {
      let sb = BigInt(0);
      const st = stacktrace();
      for (let i = 0; i < st.length; i += 1) {
        sb += BigInt(st.codePointAt(i) ?? 0);
      }
      File.writeAllBytes(`${Native.getSelfFiles()}/dec_${sb}`, jarrayToBuffer(returnValue));
    },
  });

  const pp = 'com.applovin.sdk.AppLovinInitProvider';
});

ClassLoader.perform(() => {});

Native.initLibart();
Process.attachModuleObserver({
  onAdded(module) {
    const { base, name, size, path } = module;
    if (
      !path.includes(Reflect.get(globalThis, 'packageName')) ||
      name === 'libmonochrome_64.so' ||
      name === 'libunity.so' ||
      name === 'libil2cpp.so' ||
      name === 'libhwui.so' ||
      name === 'libnms.so' ||
      name === 'libandroid.so' ||
      name === 'libil2cpp.so' ||
      name === 'libmmkv.so' ||
      name === 'libflutter.so' ||
      name === 'libsigner.so' ||
      name === 'libcocos2djs.so' ||
      name === 'ibdB2CB406F37A3.so' ||
      name === 'libdBFB00A6DC21B.so' ||
      name === 'libd47052F4E9E58.so' ||
      name === 'libd3401D2A31E51.so' ||
      name === 'libd79E1FB729E42.so' ||
      name === 'libd586F624C883B.so' ||
      name === 'libd882B40CF4232.so' ||
      name === 'libdE9CCDAF38955.so'
    )
      return;
    logger.info({ tag: 'phdr_add' }, `${Text.stringify({ name: name, base: base, size: size, path: path })}`);
    ProcMaps.addRange(module);
  },
});
Native.log(Libc.mprotect, 'pi2', {
  predicate: ProcMaps.inRange,
  nolog: true,
  transform: { 2: Consts.prot },
  call(args) {
    this.base = args[0];
    this.size = args[1].toInt32();
    this.prot = args[2].toInt32();
  },
  ret(retval) {
    const range = { base: this.base, size: this.size };
    if (this.prot & 4) ProcMaps.addRange(range);
  },
});

Network.injectNative();
Network.injectSsl();

// Network.flutterInjectSsl();

Network.attachGetAddrInfo(true);
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
Native.log(Libc.open, 'si', { predicate: ProcMaps.inRange });
Native.log(Libc.openat, 'isi', { predicate: ProcMaps.inRange });
// Native.log(Libc.syscall, 'i', { predicate: ProcMaps.inRange });
// let runmeat = 0;
// Native.log(LinkerSym.__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv, 's', {
//   nolog: true,
//   call(args) {
//     const path = args[0].readCString();
//     this.path = path;
//   },
//   ret(retval) {
//     const path = this.path;
//     if (path?.includes('libovert.so')) {
//       if (runmeat === 0) runmeat = 1;
//     }
//   },
// });
// Native.log(LinkerSym.__dl__ZN6soinfo17call_constructorsEv, 'p', {
//   tag: 'call_constructors',
//   transform: {
//     0: (ptr) => tryNull(() => new SoInfo(ptr).getRealpath()) ?? `${ptr}`,
//     NaN: function (ptr) {
//       return (
//         tryNull(() =>
//;
// Text.stringify(JSON.parse(JSON.stringify(Process.getModuleByAddress(this.soinfo.getBase())))),
//         ) ?? `${ptr}`
//       );
//     },
//   },
//   call(args) {
//     this.soinfo = new SoInfo(args[0]);
//   },
//   ret(retval) {
//     if (runmeat === 1) {
//       runmeat = 2;
//     }
//   },
// });

// Cocos2dx.replace(ptr(0x007ecaf4), 'libcocos2djs.so');
// Cocos2dx.dump({ name: 'libcocos2djs.so', fn_dump: ptr(0x0079cb08), fn_key: ptr(0x00696830) });
Cocos2dx.hookLocalStorage(function (key) {
  logger.info({ tag: 'cocossetlocal' }, `${key} -> ${this.fallback()}`);
  if (key === 'asmuh') return 'GMT+05:30';
});
// Unity.setVersion('6000.0.31f1');
// Unity.patchSsl();
// Unity.attachScenes();
// Unity.attachStrings();

// let enabled = fale;
// setTimeout(() => (enabled = true), 8330);
// JniTrace.barebone(
//   (x) => ProcMaps.inRange(x.returnAddress),
//   () => {},
// );
JniTrace.attach((thisRef) => ProcMaps.inRange(thisRef.returnAddress), true);
// Native.hookGlGetString();
Network.attachGetAddrInfo(true);
Native.System.hookGetauxval();
Native.System.hookSystem();
Native.System.hookPopen();
Native.TheEnd.hook();
// Interceptor.attach(Libc.vsnprintf, {
//     onEnter(args) {
//         this.dst = args[0];
//     },
//     onLeave(retval) {
//         if (Native.Inject.isInOwnRange(this.returnAddress)) {URL_PREFIX
//             const text = this.dst.readCString();
//             logger.info({ tag: 'vsnprintf' }, `${text} ${Native.addressOf(this.returnAddress)}`);
//        }
//     },
// });
//     onEnter(args) {
//         this.dst = args[0];
//     },
//     onLeave(retval) {
//         if (Native.Inject.isInOwnRange(this.returnAddress)) {
//             const text = this.dst.readCString();
//             logger.inf/o({ tag: 'sprintf' }, `${text}`);

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
    function () {
      if (ProcMaps.inRange(this.returnAddress)) {
        // logger.info({ tag: 'nanosleep' }, `${Native.addressOf(this.returnAddress)}`);
      }
      return 0;
    },
    'int',
    ['pointer', 'pointer'],
  ),
);
Interceptor.replace(
  Libc.usleep,
  new NativeCallback(
    function (arg0) {
      if (ProcMaps.inRange(this.returnAddress)) {
        // logger.info({ tag: 'usleep' }, `${arg0} ${Native.addressOf(this.returnAddress)}`);
      }
      return 0;
    },
    'int',
    ['ulong'],
  ),
);

// Interceptor.replace(
//   Libc.fork,
//   new NativeCallback(
//     function () {
//       const retval = Libc.fork();
//       // const retval = 1;
//       logger.info({ tag: 'fork' }, `${retval} ${Native.addressOf(this.returnAddress)}`);
//       ProcMaps.printStacktrace(this.context, 'fork');
//       return retval;
//     },
//     'int',
//     [],
//   ),
// );
Native.Files.hookRemove(() => true);

// Native.log(Libc.memchr, 'pci', { predicate: ProcMaps.inRange });
// Interceptor.attach(Libc.memcmp, memcmp);
// Interceptor.attach(Libc.memmove, memmove);
// Native.log(Libc.strlen, 's', { predicate: ProcMaps.inRange });
Native.log(Libc.pthread_create, 'pp2p', {
  predicate: ProcMaps.inRange,
  transform: {
    2: Native.addressOf,
    NaN: (ptr) => (isNully(ptr) ? `${NULL}` : hexdump(ptr, { length: 0xf, ansi: true, header: false })),
  },
});
// Native.log(Native.getEnumerated(Process.getModuleByName('libc.so'), '__start_thread'), 'p', {});
// Native.log(Native.getEnumerated(Process.getModuleByName('libc.so'), '_ZL15__pthread_startPv'), 'p', {});
Native.Strings.hookStrstr(predicate);
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
          Native.Stalker.stalk(this.threadId, Process.getModuleByAddress(this.returnAddress).base);
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

Native.Time.hookTime(ProcMaps.inRange);
Anticloak.Debug.hookPtrace();
Java.deoptimizeEverything();
// Dump.hookArtDexFile();
Native.log(DebugSymbol.fromName('AAssetManager_open').address, 'psi');

// biome-ignore lint/complexity/useArrowFunction: <explanation>
Process.attachModuleObserver({
  onAdded(module) {
    const { base, name, size, path } = module;
    logger.info({ tag: 'phdr' }, `${Text.stringify({ name: name, base: base, size: size })}`);

    const dexes = new Map();
    if (name === 'base.odex') {
      Linker.patchSoList((name) => name.includes('memfd'));
    }
  },
});

function syscallme() {
  hookException([226], {
    onBefore(context, num) {
      if (num === 56) {
        const path = context.x1.readCString();
        this.path = path;
        const mode = context.x2.toInt32();
        this.mode = mode;
      } else if (num === 62) {
        this.fd = context.x0.toInt32();
        this.offset = context.x1.toInt32();
        this.whence = context.x2.toUInt32();
      } else if (num === 63 || num === 67) {
        this.fd = context.x0.toInt32();
        this.buf = context.x1;
      } else if (num === 78) {
        this.path = context.x1.readCString();
        this.buf = context.x2;
        this.bufsize = context.x3.toInt32();
      } else if (num === 80) {
        this.fd = context.x1.toInt32();
      } else if (num === 130) {
        logger.info({ tag: 'tkill' }, `${context.x0.toInt32()}`);
      } else if (num === 160) {
        this.buf = context.x0;
        logger.info({ tag: 'uname' }, `${context.x0}`);
      } else if (num === 222 || num === 226) {
        this.base = context.x0;
        this.size = context.x1.toInt32();
        this.prot = context.x2.toUInt32();
      }
    },
    onAfter(context, num) {
      if (num === 56) {
        const path = this.path;
        // if (
        //   path?.startsWith('/proc/ ') &&
        //   (path.endsWith('/maps') ||
        //     path.endsWith('/fd ') ||
        //     path.endsWith('/task ') ||
        //     path.endsWith('/cmdline ') ||
        //     path.endsWith('/status '))
        // ) {
        //   const numFd = context.x0.toInt32();
        //   if (numFd > 0) {
        //     Libc.close(numFd);
        //   }
        //   const arg1ptr = this.rawargs.add((1 + 1) * Process.pointerSize);
        //   arg1ptr.writePointer(Memory.allocUtf8String('/dev/null'));
        //   this.redo_call();
        // }
        logger.info(
          { tag: '__openat' },
          `${this.path} ${this.mode} ? ${context.x0.toInt32()}`, // ${addressOf(context.lr)}`,
        );
      } else if (num === 62) {
        const fdpath = Native.readFdPath(this.fd);
        logger.info(
          { tag: '_lseek' },
          `${fdpath} ${this.offset} ${Consts.whence[this.whence]} ? ${context.x0.toInt32()}`,
        );
      } else if (num === 63) {
        const length = context.x0.toInt32();
        // Memory.protect(this.buf, length, 'rw');
        const content = this.buf.readCString(length);
        // const patch = content.replace(/frida/gi, 'nyasi');
        // this.buf.writeUtf8String(patch);
        // const mempatch = Memory.alloc(length);
        // mempatch.writeUtf8String(patch);
        // File.writeAllBytes(MEMFD, mempatch.readByteArray(length));
        // const nfd = Libc.open(Memory.allocUtf8String(MEMFD), 0).value;
        // const arg1ptr = this.rawargs.add((1 + 1) * Process.pointerSize);
        // arg1ptr.writePointer(ptr(nfd));
        // this.redo_call();
        logger.info({ tag: '_read' }, `${Native.readFdPath(this.fd)} -> \n${content}`);
      } else if (num === 67) {
        const length = context.x0.toInt32();
        // Memory.protect(this.buf, length, 'rw');
        const content = this.buf.readCString(length);
        // const patch = content.replace(/frida/gi, 'nyasi');
        // this.buf.writeUtf8String(patch);
        logger.info({ tag: '_pread64' }, `${Native.readFdPath(this.fd)} -> \n${content}`);
      } else if (num === 78) {
        const result = this.buf.readCString(context.x0.toInt32())?.replace(/�/gi, '');
        logger.info({ tag: '_readlinkat' }, `${this.path} -> ${result}`);
      } else if (num === 80) {
        const path = Native.readFdPath(this.fd);
        logger.info({ tag: '_fstat' }, `${path} -> ${''}`);
      } else if (num === 160) {
        const addr = this.buf.add(0x41 * 2);
        const text = addr.readCString().toLowerCase();

        for (const key of ['ksu', 'kernelsu', 'lineage', 'dirty']) {
          const i = text.indexOf(key);
          if (i !== -1) {
            addr.add(i).writeByteArray(new Array(key.length).fill(0x0));
          }
        }
      } else if (num === 222) {
        logger.info({ tag: '_mmap' }, `${this.base} ${this.size} ${Consts.prot(this.prot)}`);
      } else if (num === 226) {
        logger.info({ tag: '_mprotect' }, `${this.base} ${this.size} ${Consts.prot(this.prot)}`);
      }
    },
  });
}
