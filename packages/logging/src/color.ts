import { createColors } from 'colorette';

const enable = true;
const Colors = Object.assign(createColors({ useColor: enable }), {
    orange: (text: string | number) => (enable ? `\x1b[38;2;250;179;135m${text}\x1b[39m` : `${text}`),
    lavender: (text: string | number) => (enable ? `\x1b[38;2;180;190;254m${text}\x1b[39m` : `${text}`),
});
const { cyan, green, gray, blue, underline, yellow, magenta, orange } = use();

function use() {
    return Colors;
}

const className: (className: any) => string = (className: any) => {
    if (!className) return className;
    const splits: string[] = `${className}`.split('.');
    return splits.map(cyan).join('.');
};

const method: (methodName: any) => string = (methodName: any) => {
    if (!methodName) return methodName;
    return green(`${methodName}`);
};

const field: (fieldName: any) => string = (fieldName: any) => {
    if (!fieldName) return fieldName;
    return magenta(`${fieldName}`);
};

const keyword: (value: any) => string = (value: any) => {
    return gray(`${value}`);
};

const args: (args: any[]) => string = (args: string[]) => {
    if (args.length === 0) return '';
    const joinBy = true ? ', \n' : ', ';
    const joined = args.map((arg: any) => `    ${arg}`).join(joinBy);
    return `\n${joined}\n`;
};

const bracket: (char: any) => string = (char: any) => {
    if (!char) return char;
    return blue(`${char}`);
};

const url: (url: any) => string = (url: string) => {
    return underline(`${url}`);
};

const string: (string: any) => string = (string: any) => {
    return yellow(`"${string}"`);
};

const char: (char: any) => string = (char: any) => {
    return yellow(`'${`${char}`.replace('\n', '\\\n').replace('\r', '\\\r')}'`);
};

const number: (number: any) => string = (number: any) => {
    return magenta(`${number}`);
};

export { args, bracket, char, className, field, keyword, method, number, string, url, use };
