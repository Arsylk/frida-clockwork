import { ClassesString, stacktrace } from '@clockwork/common';

const prefsMeasurementInternalIgnored = [
    'consent_settings',
    'consent_source',
    'last_upload_attempt',
    'backoff',
    'midnight_offset',
    'last_upload',
    'last_delete_stale',
    'health_monitor:start',
    'health_monitor:count',
    'app_backgrounded',
    'start_new_session',
    'deferred_analytics_collection',
    'measurement_enabled',
    'default_event_parameters',
    'session_timeout',
    'previous_os_version',
    'use_service',
    'deferred_attribution_cache_timestamp',
    'first_open_time',
];

const applovinPrivacyIgnored = [
    'com.applovin.sdk.compliance.has_user_consent',
    'com.applovin.sdk.compliance.is_age_restricted_user',
    'com.applovin.sdk.compliance.is_do_not_sell',
];

const settingsKeysIgnored = [
    'render_shadows_in_compositor',
    'force_resizable_activities',
    'use_blast_adapter_sv',
    'show_angle_in_use_dialog_box',
    'accessibility_captioning_enabled',
];

const Filter = {
    json: (_: any, ...args: any[]) => {
        let trace = stacktrace();
        trace = trace.substring(trace.indexOf('\n'));

        if (trace.includes('at org.json.JSONObject.<init>')) return false;
        if (trace.includes('at org.json.JSONObject.get')) return false;
        if (trace.includes('at org.json.JSONObject.opt')) return false;
        if (trace.includes('at com.facebook.internal.')) return false;
        if (trace.includes('at com.google.android.gms.internal.ads.')) return false;
        if (trace.includes('at com.google.android.gms.ads.internal.config.')) return false;
        if (trace.includes('at com.google.firebase.installations.local.PersistedInstallation')) return false;
        if (trace.includes('at com.unity3d.services.core.configuration.PrivacyConfigurationLoader'))
            return false;

        return true;
    },
    prefs: (method: Java.Method, ...args: any[]) => {
        const trace = stacktrace();
        if (trace.includes('at com.yandex.mobile.ads.core.initializer.MobileAdsInitializeProvider.'))
            return false;
        if (trace.includes('at com.facebook.FacebookSdk.getLimitEventAndDataUsage')) return false;
        if (trace.includes('at com.facebook.internal.')) return false;
        if (trace.includes('at com.appsflyer.internal.')) return false;
        if (trace.includes('at com.onesignal.OneSignalPrefs.')) return false;
        if (trace.includes('at com.google.android.gms.')) return false;
        // if (trace.includes('at com.google.android.gms.ads.internal.config.')) return false;
        // if (trace.includes('at com.google.android.gms.internal.appset')) return false;
        // if (trace.includes('at com.google.android.gms.measurement.internal.')) {
        //     if (args[0] && prefsMeasurementInternalIgnored.includes(args[0])) {
        //         return false;
        //     }
        // }
        if (trace.includes('at com.google.firebase.heartbeatinfo.DefaultHeartBeatController.')) {
            if (args[0] && ['last-used-date'].includes(args[0])) {
                return false;
            }
        }
        if (trace.includes('at com.applovin.impl.privacy.a')) {
            if (args[0] && applovinPrivacyIgnored.includes(args[0])) {
                return false;
            }
        }
        if (
            trace.includes('at com.applovin.sdk.AppLovinSdk.getInstance') &&
            trace.includes('at com.applovin.impl.sdk.')
        ) {
            if (args[0]?.startsWith('com.applovin.sdk.')) {
                if (method.methodName === 'contains') {
                    return false;
                }
            }
        }
        if (method.methodName === 'getInt' && args[0] === 'music') {
            return false;
        }

        return true;
    },
    url: () => {
        const trace = stacktrace();
        if (trace.includes('at com.facebook.internal.')) return false;
        if (trace.includes('at com.appsflyer.internal.')) return false;
        if (trace.includes('at com.onesignal.OneSignalPrefs.')) return false;
        if (trace.includes('at com.google.android.gms.internal.ads.')) return false;
        if (trace.includes('at com.adjust.sdk.SdkClickHandler.sendSdkClick')) return false;
        if (trace.includes('at com.appsgeyser.sdk.ads.AdsLoader')) return false;
        // console.log(trace);
        return true;
    },
    date: () => {
        let trace = stacktrace();
        trace = trace.substring(trace.indexOf('\n'));

        if (trace.includes('at com.facebook.FacebookSdk.getGraphApiVersion(')) return false;
        if (trace.includes('at com.safedk.android.utils.SdksMapping.printAllSdkVersions')) return false;
        if (trace.includes('at com.applovin.sdk.AppLovinInitProvider.onCreate')) return false;
        if (trace.includes('at com.google.firebase.provider.FirebaseInitProvider.onCreate')) return false;
        if (trace.includes('at com.google.firebase.crashlytics.CrashlyticsRegistrar')) return false;
        if (trace.includes('at android.icu.util.Currency.getAvailableCurrencyCodes')) return false;
        // console.log(trace)

        return true;
    },
    settings: (_: any, ...args: any) => {
        const key = `${args[1]}`;
        return !settingsKeysIgnored.includes(key);
    },
    systemproperties: (_: any, ...args: any) => {
        const key = `${args[0]}`;
        switch (key) {
            case 'persist.sys.fflag.override.settings_auto_text_wrapping':
            case 'debug.force_rtl':
            case 'ro.build.version.sdk':
                return false;
        }
        return true;
    },
    systemprop: (_: any, ...args: any) => {
        const key = `${args[0]}`;
        switch (key) {
            case 'line.separator':
            case 'jsse.enableSNIExtension':
            case 'http.proxyHost':
            case 'proxyHost':
            case 'socksProxyHost':
            case 'http.keepAlive':
            case 'http.maxConnections':
            case 'http.keepAliveDuration':
            case 'javax.net.ssl.keyStore':
            case 'com.android.org.conscrypt.useEngineSocketByDefault':
            case 'java.library.path':
            case 'java.version':
            case 'java.vm.name':
            case 'file.separator':
            case 'guava.concurrent.generate_cancellation_cause':
                return false;
        }
        return true;
    },
    urlencoder: (_: any, ...args: any[]) => {
        let trace = stacktrace();
        trace = trace.substring(trace.indexOf('\n'));

        if (trace.includes('at java.net.URLEncoder.encode')) return false;
        return true;
    },
};

const FilterJni = {
    getFieldId: (className: string, typeName: string, name: string) => {
        if (className === 'io.flutter.embedding.engine.FlutterJNI' && name === 'refreshRateFPS') return false;
        return true;
    },
};

export { Filter, FilterJni };
