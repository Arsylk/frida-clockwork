import { Debug, generic, HideMaps as Hide, hookSettings, InstallReferrer } from '@clockwork/anticloak';
import { mock } from '@clockwork/anticloak/dist/country';
import { memcmp, memmove, ProcMaps } from '@clockwork/cmodules';
import { ClassesString, Consts, Linker, Struct, Text, getFindUnique, hookException } from '@clockwork/common';
import { Unity } from '@clockwork/common/dist/define/struct';
import { dumpLib } from '@clockwork/dump';
import { ClassLoader, getHookUnique, hook } from '@clockwork/hooks';
import { attach, barebone } from '@clockwork/jnitrace';
import { Color, logger } from '@clockwork/logging';
import * as Native from '@clockwork/native';
import { flutterInjectSsl } from '@clockwork/network';
import { attachScenes, attachStrings, unitypatchSsl } from '@clockwork/unity';
import Java from 'frida-java-bridge';
const { gray, white } = Color.use();
const uniqHook = getHookUnique(false);
const uniqFind = getFindUnique(false);

function ba2hex(b: ArrayBuffer): string {
  const uint8arr = new Uint8Array(b);
  if (!uint8arr) {
    return '';
  }
  let hexStr = '';
  for (let i = 0; i < uint8arr.length; i++) {
    let hex = (uint8arr[i] & 0xff).toString(16);
    hex = hex.length === 1 ? `0${hex}` : hex;
    hexStr += hex;
  }
  return hexStr;
}
// flutterInjectSsl();

Java.performNow(() => {
  generic();
  hookSettings();
  InstallReferrer.replace({
    install_referrer:
      'InstallReferrerManager=Non-organic&OnReferrerReceived=Non-organic&utm_source=facebook_ads&utm_medium=Non-organic&media_source=true_network&utm_content=Non-organic&http_referrer=BingSearch&utm_campaign=Non-organic&campaign=Non-organic&af_ad=${AD_ID}',
  });
  hook(Classes.WebView, 'loadUrl');
  hook(Classes.Activity, 'startActivity');
  hook(Classes.Intent, '$init', {
    predicate(o) {
      return o.argumentTypes.length > 0;
    },
  });
});

const libc = Process.getModuleByName('libc.so');
Native.log(libc.getExportByName('mprotect'), 'pi2', {
  predicate: ProcMaps.inRange,
  transform: { 2: Consts.prot },
  call(args) {
    this.base = args[0];
    this.size = args[1].toInt32();
  },
  ret(retval) {
    const range = { base: this.base, size: this.size };
    if (this.arg2.toInt32() & 4) ProcMaps.addRange(range);
  },
});
Process.attachModuleObserver({
  onAdded(module) {
    const { path, base, size, name } = module;
    if (path.includes(Reflect.get(globalThis, 'packageName'))) {
      ProcMaps.addRange(module);
    }
  },
});
// mock('BR');
// attachScenes();
// attachStrings();
unitypatchSsl();
attach((thisRef) => ProcMaps.inRange(thisRef.returnAddress), true);
Java.performNow(() => {
  hook(Classes.JSONObject, '$init', {
    predicate: (o) => o.argumentTypes.length > 0 && o.argumentTypes[0].className === ClassesString.String,
    after(method, returnValue, ...args) {
      const data = this.optJSONObject('data');
      logger.info({ tag: 'repljson' }, data);
      if (data) {
        const version = data.optString('version');
        const sign = data.optString('sign');
        const log = data.optBoolean('log');
        logger.info({ tag: 'dataat' }, `version: ${version}, sign: ${sign}, log: ${log}`);
        const util = findClass('com/menangad036/com/ManagerUtils');
        const n_sign = util.encrypt(util.decrypt(sign).replace('false', 'true'));
        data.put('sign', n_sign);
        data.put('log', true);
        data.put('version', '2.0');
        this.put('data', data);
      }
      logger.info({ tag: 'repljson' }, data);
    },
  });
});
