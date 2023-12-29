import { PropertyJavaUseMapper, proxyJavaUse } from '../internal/proxy.js';

const ClassesString = {
    String: 'java.lang.String',
    Boolean: 'java.lang.Boolean',
    ArrayList: 'java.util.ArrayList',
    System: 'java.lang.System',
    Exception: 'java.lang.Exception',
    StringBuilder: 'java.lang.StringBuilder',
    Class: 'java.lang.Class',
    URL: 'java.net.URL',
    Cipher: 'javax.crypto.Cipher',
    SecretKeySpec: 'javax.crypto.spec.SecretKeySpec',
    Object: 'java.lang.Object',
    ClassLoader: 'java.lang.ClassLoader',
    BaseDexClassLoader: 'dalvik.system.BaseDexClassLoader',
    DexClassLoader: 'dalvik.system.DexClassLoader',
    InMemoryDexClassLoader: 'dalvik.system.InMemoryDexClassLoader',
    PathClassLoader: 'dalvik.system.PathClassLoader',
    Date: 'java.util.Date',
    Integer: 'java.lang.Integer',
    Method: 'java.lang.reflect.Method',
    Runtime: 'java.lang.Runtime',
    Map$Entry: 'java.util.Map$Entry',
    Locale: 'java.util.Locale',
    TimeZone: 'java.util.TimeZone',

    Application: 'android.app.Application',
    Settings$Secure: 'android.provider.Settings$Secure',
    WebView: 'android.webkit.WebView',
    ContentResolver: 'android.content.ContentResolver',
    WebChromeClient: 'android.webkit.WebChromeClient',
    Log: 'android.util.Log',
    JSONObject: 'org.json.JSONObject',
    Bundle: 'android.os.Bundle',
    Intent: 'android.content.Intent',
    Activity: 'android.app.Activity',
    SharedPreferences: 'android.content.SharedPreferences',
    SharedPreferencesImpl: 'android.app.SharedPreferencesImpl',
    PackageManager: 'android.content.pm.PackageManager',
    TelephonyManager: 'android.telephony.TelephonyManager',
    Build: 'android.os.Build',
    InstallReferrerClient: 'com.android.installreferrer.api.InstallReferrerClient',
    InstallReferrerStateListener: 'com.android.installreferrer.api.InstallReferrerStateListener',
    ReferrerDetails: 'com.android.installreferrer.api.ReferrerDetails',
};

type ClassesType = PropertyJavaUseMapper<typeof ClassesString>;
const ClassesProxy: ClassesType = proxyJavaUse(ClassesString);

export { ClassesType, ClassesProxy, ClassesString };
