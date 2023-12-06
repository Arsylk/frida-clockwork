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

    Application: 'android.app.Application',
    WebView: 'android.webkit.WebView',
    ContentResolver: 'android.content.ContentResolver',
    WebChromeClient: 'android.webkit.WebChromeClient',
    Log: 'android.util.Log',
    JSONObject: 'org.json.JSONObject',
    Bundle: 'android.os.Bundle',
    Intent: 'android.content.Intent',
    Activity: 'android.app.Activity',
    SharedPreferences: 'android.content.SharedPreferences',
    PackageManager: 'android.content.pm.PackageManager',
    TelephonyManager: 'android.telephony.TelephonyManager',
};

type ClassesType = PropertyJavaUseMapper<typeof ClassesString>;
const ClassesProxy: ClassesType = proxyJavaUse(ClassesString);

export { ClassesType, ClassesProxy };
