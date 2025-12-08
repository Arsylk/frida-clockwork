import { pino } from 'pino';
import { getColor } from './autocolor.js';
import * as Color from './color.js';

const logger = pino({
  browser: {
    write: (o: any) => {
      if (Reflect.get(globalThis, 'NOLOG') === true) return;
      const msg = o.msg;
      const level = o.level;
      const tag = o.tag;
      const id = o.id;
      let print: string | null = `${msg}`;
      if (tag) {
        const color = getColor(tag);
        const ctag = `[${color(`${tag}`)}${id ? `:${id}` : ''}] `;
        print = `${msg}`.replaceAll(/^/g, ctag);
      }
      if (print) console.log(print);
    },
  },
});

function log(message?: any, ...optionalParams: any[]): void {
  logger.info(message, ...optionalParams);
}

function error(message: any) {
  logger.error(message);
}

function subLogger(tag: string) {
  return logger.child({ tag: tag });
}

export { log, error, subLogger, logger, Color };
