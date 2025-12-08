function propMapper(key: string): string | undefined | null {
  if (key.includes('qemu') || key.includes('goldfish') || key.includes('ranchu')) return null;

  switch (key) {
    case 'ro.arch':
      return 'arm64';
    case 'ro.secure':
      return '1';
    case 'ro.debuggable':
      return '0';
    case 'ro.build.characteristics':
      return 'default';
    case 'ro.build.id':
      return 'TQ3C.230901.001';
    case 'ro.build.type':
      return 'release';
    case 'ro.build.tags':
    case 'ro.bootimage.build.tags':
      return 'release-keys';
    case 'ro.build.flavor':
      return 'raven-release';
    case 'ro.product.model':
    case 'ro.product.real_model':
    case 'ro.product.name':
      return 'Raven';
    case 'ro.product.manufacturer':
    case 'ro.product.brand':
    case 'ro.product.vendor.manufacturer':
    case 'ro.soc.manufacturer':
      return 'Xiaomi';
    case 'ro.hardware':
    case 'ro.product.board':
    case 'ro.board.platform':
    case 'ro.product.device':
    case 'ro.soc.model':
      return 'hi6250';
    case 'ro.hardware.egl':
      // return 'emulation';
      return 'qcom';
    case 'ro.build.product':
      return 'nya64a';
    case 'ro.bootloader':
    case 'ro.bootmode':
      return 'secure';
    case 'gsm.version.baseband':
      return '4.0.2.c8-00047-0722+1520_40cbe21,4.0.2.c8-00047-0722_1520_40cbe21';
    case 'ro.build.fingerprint':
      return 'Xiaomi/raven/raven:14/SQ1D.220205.003/8069835:user/release-keys';
    case 'ro.build.description':
    case 'ro.build.display.id':
      return 'xiaomi-raven 14 SQ1D.220205.003 8069835 release-keys';
    case 'ro.boot.verifiedbootstate':
      return 'verified';
    case 'sys.oem_unlock_allowed':
      return '0';
    case 'persist.sys.timezone':
      return 'America/Sao_Paulo';
    case 'ro.hardware.power':
    case 'init.svc.adbd':
    case 'sys.usb.controller':
    case 'sys.usb.state':
      return '';
    case 'ro.boot.vbmeta.digest':
    case 'ro.bootimage.build.fingerprint':
      return '1111111111111111111111111111111111111111111111111111111111111111';
  }
  return undefined;
}

function buildMapper(key: string): string | undefined {
  switch (key) {
    case 'MODEL':
      return 'Go 6 Pro';
    case 'BRAND':
    case 'MANUFACTURER':
    case 'SOC_MANUFACTURER':
      return 'Xiaomi';
    //case 'DEVICE':
    //case 'PRODUCT': // this can be problematic for EGLConfig
    //    return 'nya_arm64';
    case 'HARDWARE':
      return 'qcom';
    case 'BOARD':
      return 'hi6250';
    case 'FINGERPRINT':
      return 'Xiaomi/raven/raven:14/SQ1D.220205.003/8069835:user/release-keys';
    case 'DISPLAY':
      return 'SQ1D.220205.003';
    case 'BOOTLOADER':
      return 'locked';
    case 'HOST':
      return 'HOST Co';
    case 'TAGS':
      return 'release-keys';
    case 'SERIAL':
      return 'deadbeef';
    case 'TYPE':
      return 'Production build';
    case 'USER':
      return 'LINUX General';
    case 'UNKNOWN':
      return 'KGTT General';
    case 'ANDROID_ID':
      return 'b6932a00c88d8b50';
    case 'IS_EMULATOR':
    case 'IS_USERDEBUG':
    case 'IS_DEBUGGABLE':
      return 'false';
  }
}

function systemMapper(key: string, fallback: () => string | null): string | undefined {
  switch (key) {
    case 'ro.product.real_model':
      return 'Go 6 Pro';
    case 'http.agent':
      return 'Mozilla/5.0 (Linux; Android 14; Go 6 Pro Build/SQ1D.220205.003) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.66.Mobile Safari/537.36';
    case 'os.version':
      return fallback()?.replace(/dirty|ksu|kernelsu|magisk|apatch|lineage/gi, 'nya');
  }
}

export { buildMapper, propMapper, systemMapper };
