import { pino } from 'pino';
import { getColor } from './autocolor.js';
import * as Color from './color.js';
import { Filter } from './filter.js';

const logger = pino({
    browser: {
        write: (o: any) => {
            const msg = o['msg'],
                level = o['level'],
                tag = o['tag'];
            let print: string | null = `${msg}`;
            if (tag) {
                const color = getColor(tag);
                print = `[${color(`${tag}`)}] ${msg}`;
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

export { log, error, subLogger, logger, Color, Filter };
