import { attachRegisterNatives } from './registerNatives.js';
import { attachSystemPropertyGet } from './systemPropertyGet.js';
import { Inject } from './inject.js';
import { dumpFile } from './utils.js';
import { HooahTrace } from './hooah.js';

function gPtr(value: string | number): NativePointer {
    return ptr(value).sub('0x100000');
}

export { gPtr, attachRegisterNatives, attachSystemPropertyGet, Inject, dumpFile, HooahTrace };
