import { hook } from '@clockwork/hooks';
import Java from 'frida-java-bridge';

const ROOT_PACKAGES = [
  'com.topjohnwu.magisk',
  'me.weishu.kernelsu',
  'com.termux',
  'com.termux.styling',
  'com.rifsxd.ksunext',
  '  bin.mt.plus',
];

function hookPackageManager() {
  const hookParams = {
    logging: { multiline: false, short: true },
    replace(method, ...args) {
      if (ROOT_PACKAGES.includes(`${args[0]}`)) {
        args[0] = 'come.just.test.fake.app';
      }
      return method.call(this, ...args);
    },
    //after(_method, returnValue) {
    //    const mPackage = this.mContext.value.getPackageName();
    //    if (mPackage === returnValue?.packageName?.value) {
    //    }
    //},
  };
  hook(Classes.ApplicationPackageManager, 'getPackageInfo', hookParams);
  hook(Classes.ApplicationPackageManager, 'getApplicationInfo', {
    ...hookParams,
    logging: { ...hookParams.logging, return: false, call: false },
  });

  const listHookParams = (cast: Java.Wrapper) => {
    return {
      logging: { multiline: false, short: true },
      replace(method, ...args) {
        return Classes.ArrayList.$new();
        const retval = method.call(this, ...args);
        for (const _item of retval.toArray()) {
          const item = Java.cast(_item, cast);
          if (ROOT_PACKAGES.includes(`${item.packageName.value}`)) {
            retval.remove(item);
          }
        }
        return retval;
      },
    };
  };
  hook(
    Classes.ApplicationPackageManager,
    'getInstalledApplications',
    listHookParams(Classes.ApplicationInfo),
  );
  hook(Classes.ApplicationPackageManager, 'getInstalledPackages', listHookParams(Classes.PackageInfo));
  hook(Classes.ApplicationPackageManager, 'queryIntentActivities', {
    logging: { short: true, multiline: false },
  });
  hook(Classes.UsageStatsManager, 'queryEvents', { logging: { short: true, multiline: false } });
  hook(Classes.UsageEvents, 'getNextEvent', {
    replace(method, eventOut) {
      method.call(this, eventOut);

      let pkg = eventOut.getPackageName();
      while (ROOT_PACKAGES.includes(pkg)) {
        if (this.hasNextEvent()) {
          method.call(this, eventOut);
          pkg = eventOut.getPackageName();
        } else {
          eventOut.copyFrom(Classes.UsageEvents$Event.$new());
          break;
        }
      }
    },
    logging: { call: false, return: false },
  });
}

export { hookPackageManager };
