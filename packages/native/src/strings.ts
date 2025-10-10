import { isNully, Libc } from '@clockwork/common';
import { Color, logger } from '@clockwork/logging';
import { addressOf } from './utils.js';
const { dim, green, red, italic, gray } = Color.use();

function strOneLine(ptr: NativePointer, max = -1): string {
  const all = `${ptr.readCString()}`.replace(/\n/g, '\\n');
  return max !== -1 ? all.substring(0, max) : all;
}

function colorsign(success: boolean): string {
  return success ? green('?') : red('?');
}

function hookStrstr(
  predicate: (ptr: NativePointer) => boolean,
  fn?: (haystack: NativePointer, needle: NativePointer) => void,
) {
  const array: ('strstr' | 'strcasestr')[] = ['strstr', 'strcasestr'];
  for (const key of array) {
    const func = Libc[key];
    Interceptor.replace(
      func,
      new NativeCallback(
        function (this: InvocationContext, haystack, needle) {
          fn?.call(this, haystack, needle);
          const strNeedle = needle.readCString();
          if (
            // strNeedle === 'true' ||
            strNeedle === 'REJECT' ||
            strNeedle === 'linjector' ||
            strNeedle === 'gmain' ||
            strNeedle === 'gum-js-loop' ||
            strNeedle === 'frida'
          ) {
            return NULL;
          }
          const strHaystack = haystack.readCString();
          const ret = strNeedle === 'XUpoCgpF ' ? haystack : func(haystack, needle);

          if (
            predicate(this.returnAddress) &&
            !strNeedle.includes('TracerPid') &&
            !strNeedle.includes('"frida:rpc"') &&
            !strHaystack.includes('Noto Serif') &&
            !strHaystack.includes('Noto Sans') &&
            !strHaystack.includes('Roboto')
          ) {
            const isFound = ret && !ret.isNull();
            const strhay = gray(`"${strOneLine(haystack, 100)}"`);
            const strned = isFound ? `"${strOneLine(needle, 100)}"` : gray(`"${strOneLine(needle, 100)}"`);
            logger.info(
              { tag: key },
              `${strhay} ${colorsign(isFound)} ${strned} &${this.threadId} ${this.returnAddress ? addressOf(this.returnAddress) : ''}`,
            );
          }

          return ret;
        } as any,
        'pointer',
        ['pointer', 'pointer'],
      ),
    );
  }
}

function hookStrlen(predicate: (ptr: NativePointer) => boolean) {
  Interceptor.replace(
    Libc.strlen,
    new NativeCallback(
      function (s) {
        const ret = Libc.strlen(s);

        if (predicate(this.returnAddress)) {
          const strs = gray(`"${strOneLine(s)}"`);
          logger.info({ tag: 'strlen' }, `${strs} # ${Color.number(ret)} ${addressOf(this.returnAddress)}`);
        }

        return ret;
      },
      'int',
      ['pointer'],
    ),
  );
}

function hookStrcpy(predicate: (ptr: NativePointer) => boolean) {
  const array: ('stpcpy' | 'strcpy')[] = ['stpcpy', 'strcpy'];
  for (const key of array) {
    const func = Libc[key];
    Interceptor.replace(
      func,
      new NativeCallback(
        function (dst, src) {
          if (predicate(this.returnAddress)) {
            const strdst = dim(`"${strOneLine(dst)}"`);
            const strsrc = dim(`"${strOneLine(src)}"`);
            logger.info({ tag: key }, `${strdst} | ${strsrc}`);
          }

          const ret = func(dst, src);
          return ret;
        },
        'pointer',
        ['pointer', 'pointer'],
      ),
    );
  }
}

// hooking strcmp appears to kill the app regardless of what app it is ?
function hookStrcmp(predicate: (ptr: NativePointer, threadId: number) => boolean) {
  const array: ('strcmp' | 'strncmp' | 'strcasecmp')[] = ['strcmp', 'strncmp', 'strcasecmp'];
  for (const key of array.slice(-1)) {
    const func = Libc[key];
    Interceptor.attach(func, {
      onEnter({ 0: a, 1: b }) {
        if (predicate(this.returnAddress, this.threadId)) {
          logger.info(
            { tag: key },
            `${a.readCString()} ? ${b.readCString()} ${addressOf(this.returnAddress)}`,
          );
        }
      },
      onLeave(retval) {},
    });
    // Interceptor.replace(
    // 	func,
    // 	new NativeCallback(
    // 		function (s1, s2) {
    // 			const ret = func(s1, s2);

    // 			if (predicate(this.returnAddress)) {
    // 				const strs1 =
    // 					ret === 0 ? `"${strOneLine(s1)}"` : gray(`"${strOneLine(s1)}"`);
    // 				const strs2 =
    // 					ret >= 0 ? `"${strOneLine(s2)}"` : gray(`"${strOneLine(s2)}"`);
    // 				logger.info({ tag: key }, `${strs1} = ${strs2}`);
    // 			}

    // 			return ret;
    // 		},
    // 		"int",
    // 		["pointer", "pointer"],
    // 	),
    // );
  }
}

function hookStrcat(predicate: (ptr: NativePointer) => boolean) {
  Interceptor.replace(
    Libc.strcat,
    new NativeCallback(
      function (dst, src) {
        const ret = Libc.strcat(dst, src);
        if (predicate(this.returnAddress)) {
          const strs = gray(`"${strOneLine(ret)}"`);
          logger.info({ tag: 'strcat' }, `${strs}`);
        }

        return ret;
      },
      'pointer',
      ['pointer', 'pointer'],
    ),
  );
}
function hookStrchr(predicate: (ptr: NativePointer) => boolean) {
  Interceptor.replace(
    Libc.strchr,
    new NativeCallback(
      function (str, z) {
        const ret = Libc.strchr(str, z);
        if (predicate(this.returnAddress)) {
          const isFound = !isNully(ret);
          const strs = gray(`"${strOneLine(str, 100)}"`);
          const strChar = gray(`'${String.fromCharCode(z).replace(/\n/g, '\\n')}'`);
          const strRet = isFound ? `= ${ret.sub(str)}` : '';
          logger.info(
            { tag: 'strchr' },
            `${strs} ${colorsign(isFound)} ${strChar} ${strRet} ${addressOf(this.returnAddress)}`,
          );
        }

        return ret;
      },
      'pointer',
      ['pointer', 'int'],
    ),
  );
}

function hookStrtoLong(predicate: (ptr: NativePointer) => boolean) {
  Interceptor.replace(
    Libc.strtoll,
    new NativeCallback(
      function (src, endptr, base) {
        if (predicate(this.returnAddress)) {
          const strsrc = dim(`"${strOneLine(src)}"`);
          logger.info({ tag: 'strtoll' }, `${strsrc}`);
        }

        const ret = Libc.strtoll(src, endptr, base);
        return new Int64(ret);
      },
      'int64',
      ['pointer', 'pointer', 'int'],
    ),
  );

  Interceptor.replace(
    Libc.strtoull,
    new NativeCallback(
      function (src, endptr, base) {
        if (predicate(this.returnAddress)) {
          const strsrc = dim(`"${strOneLine(src)}"`);
          logger.info({ tag: 'strtoull' }, `${strsrc}`);
        }

        const ret = Libc.strtoull(src, endptr, base);
        return new UInt64(ret);
      },
      'uint64',
      ['pointer', 'pointer', 'int'],
    ),
  );
}

function hookStrtok(predicate: (ptr: NativePointer) => boolean) {
  Interceptor.replace(
    Libc.strtok,
    new NativeCallback(
      function (src, delim) {
        if (predicate(this.returnAddress)) {
          const ret = Libc.strtok(src, delim);
          const msg = `${dim(`"${strOneLine(src)}") : "${dim(`${strOneLine(delim)}" = ${strOneLine(ret)}`)}`)}`;
          logger.info({ tag: 'strtoll' }, `${msg}`);
          return ret;
        }

        return Libc.strtok(src, delim);
      },
      'pointer',
      ['pointer', 'pointer'],
    ),
  );

  Interceptor.replace(
    Libc.strtok_r,
    new NativeCallback(
      function (src, delim, saveptr) {
        if (predicate(this.returnAddress)) {
          const ret = Libc.strtok_r(src, delim, saveptr);
          const msg = `${dim(`"${src}" : "${dim(`${strOneLine(delim)}" = ${ret}`)}`)} { save: ${saveptr.readCString()} }`;
          logger.info({ tag: 'strtok_r' }, `${msg}`);
          return ret;
        }

        return Libc.strtok_r(src, delim, saveptr);
      },
      'pointer',
      ['pointer', 'pointer', 'pointer'],
    ),
  );
}

export { hookStrcmp, hookStrcpy, hookStrlen, hookStrstr, hookStrchr, hookStrcat, hookStrtok, hookStrtoLong };
