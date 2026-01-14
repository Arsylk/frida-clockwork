import { Color } from '@clockwork/logging';
import { JavaPrimitive } from './define/consts.js';
const { gray } = Color.use();

function maxLengh(message: any, length: number): string {
  const msgString = `${message}`;
  return msgString.substring(0, Math.min(msgString.length, length));
}

function noLines(message: any): string {
  return `${message}`.replaceAll('\n', '\\n');
}

function toHex(decimal: any, length = 2): string {
  return `${'0'.repeat(length - 1)}${Number(decimal).toString(16)}`.slice(-length);
}

function toHexString(array: ArrayBuffer | null, separator = ' ') {
  if (!array) return;
  const buff = new Uint8Array(array);
  const mapped: string[] = [];
  for (const n of buff) {
    mapped.push(toHex(n));
  }
  return mapped.join(separator);
}

function ba2hex(b): string {
  let hexStr = '';
  for (let i = 0; i < b.length; i++) {
    let hex = (b[i] & 0xff).toString(16);
    hex = hex.length === 1 ? `0${hex}` : hex;
    hexStr += hex;
  }
  return hexStr;
}

function toByteSize(size: number): string {
  const i = size === 0 ? 0 : Math.floor(Math.log(size) / Math.log(1024));
  return `${Number((size / 1024 ** i).toFixed(2)) * 1} ${['B', 'kB', 'MB', 'GB', 'TB'][i]}`;
}

function stringNumber(length: number): string {
  let text = '';
  for (let i = 0; i < length; i++) {
    text += `${Math.floor(Math.random() * 10) % 10}`;
  }
  return text;
}

function uuid() {
  const range = '0123456789abcdefghijklmnopqrstuvwxyz';
  const rnd = () => range.charAt(Math.round(Math.random() * (range.length - 1)));
  const len = (n: number) => {
    const arr = Array(n);
    for (let i = 0; i < n; i += 1) {
      arr.push(rnd());
    }
    return arr.join('');
  };
  return Array(len(8), len(4), len(4), len(4), len(12)).join('-');
}

const JavaPrimitiveReversed = Object.fromEntries(
  Reflect.ownKeys(JavaPrimitive).map((key) => [JavaPrimitive[key], key]),
) as {
  [K in keyof typeof JavaPrimitive as (typeof JavaPrimitive)[K]]: K;
};

function toPrettyType(type?: string): string {
  if (!type) return 'null';
  const len = type.length;
  for (; type.charAt(0) === '['; type = type.substring(1));
  const depth = len - type.length;
  if (type.charAt(0) === 'L' && type.charAt(type.length - 1) === ';')
    return type.substring(1, type.length - 1).replace('/', '.') + '[]'.repeat(depth);
  return (JavaPrimitiveReversed[type] ?? type) + '[]'.repeat(depth);
}

function base64(input: string) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let output = '';
  let i = 0;

  while (i < input.length) {
    const a = input.charCodeAt(i++);
    const b = input.charCodeAt(i++);
    const c = input.charCodeAt(i++);
    const index1 = a >> 2;
    const index2 = ((a & 3) << 4) | (b >> 4);
    const index3 = Number.isNaN(b) ? 64 : ((b & 15) << 2) | (c >> 6);
    const index4 = Number.isNaN(c) ? 64 : c & 63;

    output += chars.charAt(index1) + chars.charAt(index2) + chars.charAt(index3) + chars.charAt(index4);
  }

  return output;
}

function stringify(data: any) {
  const mapped = Reflect.ownKeys(data).map((k: symbol | string) => {
    const value = data[k];

    let strValue = `${value}`;
    if (typeof value === 'object' && strValue === '[object Object]') {
      strValue = stringify(value);
    }
    if (typeof value === 'number' || typeof value === 'bigint' || typeof value === 'boolean') {
      strValue = Color.number(strValue);
    }
    if (typeof value === 'string') {
      strValue = Color.string(strValue);
    }
    if (typeof value === 'function') {
      strValue = Color.method(strValue);
      strValue = `${strValue} ${value.name}(${value.arguments})`;
    }

    return `${gray(String(k))}: ${strValue}`;
  });
  return `{ ${mapped.join(', ')} }`;
}

export {
  base64,
  maxLengh,
  noLines,
  stringify,
  stringNumber,
  toByteSize,
  toHex,
  toHexString,
  ba2hex,
  toPrettyType,
  uuid,
};
