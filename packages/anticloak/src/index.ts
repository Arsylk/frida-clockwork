import { Classes, Text, enumerateMembers, getFindUnique, getRandomInt, stacktrace } from '@clockwork/common';
import { ClassLoader, Filter, always, hook, ifKey } from '@clockwork/hooks';
import type { HookParameters } from '@clockwork/hooks/dist/types.js';
import { buildMapper } from './buildprop.js';
export * as HideMaps from './hidemaps.js';

export * as BuildProp from './buildprop.js';
export * as Country from './country.js';
export * as Debug from './debug.js';
export * as InstallReferrer from './installReferrer.js';
export * as Jigau from './jigau.js';
export * from './packages.js';

function hookDevice(fn?: (key: string) => number | undefined) {
  enumerateMembers(Classes.Build, {
    onMatchField(clazz, member) {
      const field = clazz[member];
      const mapped = fn?.(member) ?? buildMapper(member);
      if (field && mapped) {
        let casted: any = mapped;
        if (field.fieldReturnType.className === 'boolean') {
          casted = Boolean(mapped);
        }
        field.value = casted;
      }
    },
  });
}

function hookSettings(fn?: (key: string) => number | undefined) {
  const mapper = (key: string): number | undefined => {
    switch (key) {
      case 'development_settings_enabled':
      case 'adb_enabled':
      case 'adb_wifi_enabled':
      case 'install_non_market_apps':
      case 'stay_on_while_plugged_in':
        return 0;
      case 'play_protect_enabled':
        return 1;
    }
  };

  for (const clazz of [Classes.Settings$Secure, Classes.Settings$Global]) {
    hook(clazz, 'getInt', {
      loggingPredicate: Filter.settings,
      logging: { multiline: false, short: true },
      replace: ifKey((key) => fn?.(key) ?? mapper(key), 1),
    });
  }
}

function hookAdId(id = Text.uuid()) {
  const uniqFind = getFindUnique(false);
  ClassLoader.perform(() => {
    uniqFind('com.google.android.gms.ads.identifier.AdvertisingIdClient$Info', (clazz) => {
      'getId' in clazz && hook(clazz, 'getId', { replace: always(id) });
    });
  });
}

function hookInstallerPackage() {
  hook(Classes.ApplicationPackageManager, 'getInstallerPackageName', {
    replace: always('com.android.vending'),
    logging: {
      short: true,
      multiline: false,
    },
  });
}

function hookLocationHardware() {
  hook(Classes.LocationManager, 'getGnssHardwareModelName', {
    replace: always('Model Name Nya'),
  });
}

function hookSensor() {
  const params: HookParameters = {
    replace(method, ...args) {
      const value = `${method.call(this, ...args)}`;
      return value.replace(
        /x86|sdk|open|source|emulator|google|aosp|ranchu|goldfish|cuttlefish|generic|unknown/gi,
        'nya',
      );
    },
    logging: {
      short: true,
      multiline: false,
    },
  };
  hook(Classes.Sensor, 'getVendor', { ...params, loggingPredicate: () => false });
  hook(Classes.Sensor, 'getName', { ...params, loggingPredicate: () => false });
}

function hookVerify() {
  hook(Classes.Signature, 'verify', {
    replace: () => true,
  });
}

function hookHasFeature() {
  const HARDWARE_FEATURES = ['android.hardware.camera.flash', 'android.hardware.nfc'];
  hook(Classes.ApplicationPackageManager, 'hasSystemFeature', {
    logging: { short: true, multiline: false },
    predicate(_, i) {
      return i !== 0;
    },
    loggingPredicate(_, ...args) {
      if (`${args[0]}` === 'android.hardware.touchscreen.multitouch.jazzhand') return false;
      return true;
    },
    replace(method, ...args) {
      const feature = `${args[0]}`;
      for (const key of HARDWARE_FEATURES) {
        if (feature.startsWith(key)) {
          return true;
        }
      }
      return method.call(this, ...args);
    },
  });
}

function hookBatteryManager() {
  hook(Classes.BatteryManager, 'isCharging', {
    replace: always(false),
    logging: { short: true, multiline: false },
  });

  hook(Classes.BatteryManager, 'getIntProperty', {
    replace: ifKey((key) => {
      switch (`${key}`) {
        case '4': // battery level
          return 73;
        case '6': // battery current now
          return -getRandomInt(5, 15);
      }
    }),
    logging: { short: true, multiline: false },
  });
}

function hookWindowFlags() {
  hook(Classes.Window, 'setFlags', {
    replace(method, ...args) {
      const FLAG_SECURE = 0x2000;
      args[0] &= ~FLAG_SECURE;
      return method.call(this, ...args);
    },
    logging: { call: false, return: false },
  });
}

function hookNetwork() {
  hook(Classes.NetworkInterface, 'getNetworkInterfaces', {
    replace(method, ...args) {
      const vec = Classes.Vector.$new(1);
      vec.add(Classes.NetworkInterface.$new('nya_interface', 0, [Classes.InetAddress.getLocalHost()]));
      return vec.elements();
    },
  });
  hook(Classes.NetworkInfo, 'getState', {
    replace: () => {
      //@ts-ignore
      return Classes.NetworkInfo$State.valueOf('CONNECTED');
    },
  });
  hook(Classes.NetworkInfo, 'isAvailable', { replace: always(true) });
  hook(Classes.NetworkInfo, 'isConnected', { replace: always(true) });
  hook(Classes.NetworkInfo, 'isConnectedOrConnecting', { replace: always(true) });
  hook(Classes.TelephonyManager, 'getSimState', {
    replace: always(5),
    logging: { multiline: false, short: true },
  });
  hook(Classes.TelephonyManager, 'getDataState', {
    replace: always(2),
    logging: { multiline: false, short: true },
  });
  hook(Classes.TelephonyManager, 'isDataEnabled', {
    replace: always(true),
    logging: { multiline: false, short: true },
  });
}

function hookSystemOs() {
  hook(Classes.Os, 'uname', {
    after(method, returnValue, ...args) {
      returnValue.release.value = '5.10';
      returnValue.machine.value = '';
    },
  });
}

function generic() {
  hookInstallerPackage();
  hookLocationHardware();
  hookSensor();
  hookVerify();
  hookHasFeature();
  hookBatteryManager();
  hookWindowFlags();
  hookSystemOs();
}

export { generic, hookAdId, hookDevice, hookNetwork, hookInstallerPackage, hookBatteryManager, hookSettings };
