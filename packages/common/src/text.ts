function maxLengh(message: any, length: number): string {
    const msgString = `${message}`;
    return msgString.substring(0, Math.min(msgString.length, length));
}

function noLines(message: any): string {
    return `${message}`.replaceAll('\n', '\\n');
}

function toHex(decimal: any): string {
    return ('0' + Number(decimal).toString(16)).slice(-2);
}

function toByteSize(size: number): string {
    const i = size === 0 ? 0 : Math.floor(Math.log(size) / Math.log(1024));
    return Number((size / Math.pow(1024, i)).toFixed(2)) * 1 + ' ' + ['B', 'kB', 'MB', 'GB', 'TB'][i];
}

function stringNumber(length: number): string { 
    let text = '';
    for (let i = 0; i < length; i++) {
        text += `${Math.floor((Math.random() * 10)) % 10}`
    }
    return text;
}

const PRIMITIVE_TYPE: { [key: string]: string } = {
    Z: 'boolean',
    B: 'byte',
    C: 'char',
    D: 'double',
    F: 'float',
    I: 'int',
    J: 'long',
    S: 'short',
    V: 'void',
}

function toPrettyType(type: string): string {
    const len = type.length;
    for (; type.charAt(0) === '['; type = type.substring(1));
    const depth = len - type.length;
    if (type.charAt(0) === 'L' && type.charAt(type.length - 1) === ';')
        return type.substring(1, type.length - 1).replaceAll('/', '.') + '[]'.repeat(depth);
    return (PRIMITIVE_TYPE[type] ?? type) + '[]'.repeat(depth);
}

export { maxLengh, noLines, toHex, toByteSize, toPrettyType, stringNumber };
