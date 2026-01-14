import { Classes, ClassesString, Text, tryNull } from '@clockwork/common';
import { Filter, always, hook } from '@clockwork/hooks';
import Java from 'frida-java-bridge';

type Config = {
  timezoneId: string;
  mcc: string;
  mnc: string;
  code: string;
  locale: [string, string];
  country: string;
  operator: string;
};

const Configurations: { [key: string]: Config } = {
  BR: {
    timezoneId: 'America/Sao_Paulo',
    mcc: '724',
    mnc: '10',
    code: '55',
    locale: ['BR', 'pt'],
    country: 'br',
    operator: 'Vivo',
  },
  IN: {
    timezoneId: 'Asia/Kolkata',
    mcc: '404',
    mnc: '299',
    code: '91',
    locale: ['IN', 'in'],
    country: 'in',
    operator: 'Failed Calls',
  },
  VI: {
    timezoneId: 'America/St_Thomas',
    mcc: '376',
    mnc: '999',
    code: '1340',
    locale: ['VI', 'vi'],
    country: 'vi',
    operator: 'Fix Line',
  },
  VN: {
    timezoneId: 'Asia/Saigon',
    mcc: '452',
    mnc: '01',
    code: '84',
    locale: ['VN', 'vi'],
    country: 'vn',
    operator: 'MobiFone',
  },
  RU: {
    timezoneId: 'Europe/Moscow',
    mcc: '255',
    mnc: '999',
    code: '79',
    locale: ['RU', 'ru'],
    country: 'ru',
    operator: 'Fix Line',
  },
  ID: {
    timezoneId: 'Asia/Jakarta',
    mcc: '510',
    mnc: '11',
    code: '62',
    locale: ['ID', 'id'],
    country: 'id',
    operator: 'XL',
  },
  PH: {
    timezoneId: 'Asia/Manila',
    mcc: '515',
    mnc: '03',
    code: '63',
    locale: ['PH', 'fil'],
    country: 'ph',
    operator: 'Smart',
  },
  US: {
    timezoneId: 'America/New_York',
    mcc: '312',
    mnc: '080',
    code: '63',
    locale: ['EN', 'us'],
    country: 'us',
    operator: 'AT&T Mobility',
  },
  TH: {
    timezoneId: 'Asia/Bangkok',
    mcc: '520',
    mnc: '04',
    code: '66',
    locale: ['TH', 'th'],
    country: 'th',
    operator: 'TrueMove H',
  },
  NN: {
    timezoneId: 'Asia/Ho_Chi_Minh',
    mcc: '452',
    mnc: '01',
    code: '84',
    locale: ['no', 'ni'],
    country: 'ni',
    operator: 'MobiFone',
  },
  KR: {
    timezoneId: 'Asia/Seoul',
    mcc: '450',
    mnc: '08',
    code: '82',
    locale: ['KR', 'ko'],
    country: 'kr',
    operator: 'olleh / KT',
  },
  PK: {
    timezoneId: 'Asia/Karachi',
    mcc: '410',
    mnc: '04',
    code: '92',
    locale: ['PK', 'ur'],
    country: 'pk',
    operator: 'Zong',
  },
  TR: {
    timezoneId: 'Europe/Istanbul',
    mcc: '286',
    mnc: '299',
    code: '90',
    locale: ['TR', 'tr'],
    country: 'tr',
    operator: 'Asistan Telekom',
  },
  BD: {
    timezoneId: 'Asia/Dhaka',
    mcc: '470',
    mnc: '03',
    code: '90',
    locale: ['BD', 'bn'],
    country: 'bd',
    operator: 'Banglalink',
  },
};

function mock(key: keyof typeof Configurations): void;
function mock(config: Config): void;
function mock(keyOrConfig: Config | keyof typeof Configurations) {
  const config = typeof keyOrConfig === 'object' ? (keyOrConfig as Config) : Configurations[keyOrConfig];
  const number = `${config.code}${Text.stringNumber(10)}`;
  const mccmnc = `${config.mcc}${config.mnc}`;
  const subscriber = `${mccmnc}${Text.stringNumber(15 - mccmnc.length)}`;
  hook(Classes.TelephonyManager, 'getLine1Number', { replace: always(number) });
  hook(Classes.TelephonyManager, 'getSimOperator', {
    replace: always(mccmnc),
  });
  hook(Classes.TelephonyManager, 'getSimOperatorName', {
    replace: always(config.operator),
  });
  hook(Classes.TelephonyManager, 'getNetworkOperator', {
    replace: always(mccmnc),
  });
  hook(Classes.TelephonyManager, 'getNetworkOperatorName', {
    replace: always(config.operator),
  });
  hook(Classes.TelephonyManager, 'getSimCountryIso', {
    replace: always(config.country),
  });
  hook(Classes.TelephonyManager, 'getNetworkCountryIso', {
    replace: always(config.country),
  });
  hook(Classes.TelephonyManager, 'getSubscriberId', {
    replace: always(subscriber),
  });
  hook(Classes.TimeZone, 'getID', { replace: always(config.timezoneId) });
  hook(Classes.TimeZone, 'getDefault', {
    replace() {
      return Classes.TimeZone.getTimeZone('timezoneId');
    },
  });
  hook(Classes.Locale, 'getDefault', {
    replace(method, ...args) {
      const cls = tryNull(() => Classes.Locale.$new(config.locale[1], config.locale[0]));
      return cls ?? Classes.Locale.getDefault();
    },
    logging: { call: false, return: false },
  });

  for (const mth of ['getDefault', 'getAdjustedDefault']) {
    hook(Classes.LocaleList, mth, {
      replace(method, ...args) {
        const cls = tryNull(() => Classes.Locale.$new(config.locale[1], config.locale[0]));
        const target = cls ?? Classes.Locale.getDefault();
        return Classes.LocaleList.$new(Java.array(ClassesString.Locale, [target]));
      },
      logging: { call: false, return: false },
    });
  }

  hook(Classes.Resources, 'getConfiguration', {
    after(method, returnValue, ...args) {
      returnValue.mcc.value = Number(config.mcc);
      returnValue.mnc.value = Number(config.mnc);
      returnValue.setLocale(Classes.Locale.$new(config.locale[1], config.locale[0]));
    },
    logging: { call: false, return: false },
  });

  hook(Classes.Date, 'getTime', {
    loggingPredicate: Filter.date,
    // replace(method, ...args) {
    //     const calendar = Classes.Calendar.getInstance(Classes.TimeZone.getTimeZone('UTC'));
    //     const zdt = Classes.ZonedDateTime.ofInstant(
    //         Classes.Instant.ofEpochMilli(this.getTime()),
    //         Classes.ZoneId.of(config.timezoneId),
    //     );
    //     calendar.set(1, zdt.getYear());
    //     calendar.set(2, zdt.getMonthValue() - 1);
    //     calendar.set(5, zdt.getDayOfMonth());
    //     calendar.set(11, zdt.getHour());
    //     calendar.set(12, zdt.getMinute());
    //     calendar.set(13, zdt.getSecond());
    //     calendar.set(14, zdt.getNano() / 1_000_000);
    //     return calendar.getTimeInMillis();
    // },
  });

  hook(Classes.Calendar, 'getInstance', {
    logging: { call: false, return: false },
    loggingPredicate: Filter.date,
    replace(method, ...args) {
      const returnValue = method.call(this, ...args);
      returnValue.setTimeZone(Classes.TimeZone.getTimeZone(config.timezoneId));
      return returnValue;
    },
  });

  const SkuClass = findClass(ClassesString.SkuDetails);
  if (SkuClass) {
    hook(SkuClass, 'getPriceCurrencyCode', {
      replace(method, ...args) {
        let code = method.call(this, ...args);
        try {
          const cls = tryNull(() => Classes.Locale.$new(config.locale[1], config.locale[0]));
          const target = cls ?? Classes.Locale.getDefault();
          const currency = Classes.Currency.getInstance(target);
          if (currency && `${currency.getDisplayName()}` !== '') {
            code = currency.getCurrencyCode();
          }
        } finally {
          return code;
        }
      },
    });
  }
}

export { mock };
