import { stacktrace } from '@clockwork/common';

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
const Filter = {
    json: (_: any, ...args: any[]) => {
        let trace = stacktrace();
        trace = trace.substring(trace.indexOf('\n'));

        if (trace.includes('at org.json.JSONObject.get')) return false;
        if (trace.includes('at org.json.JSONObject.opt')) return false;
        if (trace.includes('at com.facebook.internal.')) return false;
        if (trace.includes('at com.google.android.gms.internal.ads.')) return false;
        if (trace.includes('at com.google.firebase.installations.local.PersistedInstallation')) return false;
        if (trace.includes('at com.unity3d.services.core.configuration.PrivacyConfigurationLoader')) return false;

        return true;
    },
    prefs: (_: any, ...args: any[]) => {
        const trace = stacktrace();
        if (trace.includes('at com.facebook.internal.')) return false;
        if (trace.includes('at com.appsflyer.internal.')) return false;
        if (trace.includes('at com.onesignal.OneSignalPrefs.')) return false;
        if (trace.includes('at com.google.android.gms.internal.ads.')) return false;
        if (trace.includes('at com.google.android.gms.measurement.internal.')) {
            if (args[0] && prefsMeasurementInternalIgnored.includes(args[0])) {
                return false;
            }
        }
        if (trace.includes('at com.google.firebase.heartbeatinfo.DefaultHeartBeatController.')) {
            if (args[0] && ['last-used-date'].includes(args[0])) {
                return false;
            }
        }
        return true;
    },
    url: () => {
        const trace = stacktrace();
        if (trace.includes('at com.facebook.internal.')) return false;
        if (trace.includes('at com.appsflyer.internal.')) return false;
        if (trace.includes('at com.onesignal.OneSignalPrefs.')) return false;
        if (trace.includes('at com.google.android.gms.internal.ads.')) return false;
        return true;
    },
};

export { Filter };