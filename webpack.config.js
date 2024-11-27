import { resolve } from 'path';

const base = {
    name: 'base',
    module: {
        rules: [
            {
                test: /\.ts$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
        ],
    },
    resolve: {
        extensions: ['.ts', '.js'],
        fallback: {
            assert: '@frida/assert',
            'base64-js': '@frida/base64-js',
            buffer: '@frida/buffer',
            crosspath: '@frida/crosspath',
            crypto: '@frida/crypto',
            diagnostics_channel: '@frida/diagnostics_channel',
            events: '@frida/events',
            http: '@frida/http',
            'http-parser-js': '@frida/http-parser-js',
            https: '@frida/https',
            ieee754: '@frida/ieee754',
            net: '@frida/net',
            os: '@frida/os',
            path: '@frida/path',
            process: '@frida/process',
            punycode: '@frida/punycode',
            querystring: '@frida/querystring',
            'readable-stream': '@frida/readable-stream',
            'reserved-words': '@frida/reserved-words',
            stream: '@frida/stream',
            string_decoder: '@frida/string_decoder',
            terser: '@frida/terser',
            timers: '@frida/timers',
            tty: '@frida/tty',
            url: '@frida/url',
            util: '@frida/util',
            vm: '@frida/vm',
            fs: 'frida-fs',
        },
    },
    mode: 'production',
    mode: 'development',
    devtool: 'inline-source-map',
};
export default [
    Object.assign(Object.assign({}, base), {
        name: 'index',
        entry: './agent/index.ts',
        output: {
            filename: 'script.js',
            path: resolve('./agent/dist'),
        },
    }),
    Object.assign(Object.assign({}, base), {
        name: 'justdump',
        entry: './agent/justdump.ts',
        output: {
            filename: 'justdump.js',
            path: resolve('./agent/dist'),
        },
    }),
    Object.assign(Object.assign({}, base), {
        name: 'justcocos',
        entry: './agent/justcocos.ts',
        output: {
            filename: 'justcocos.js',
            path: resolve('./agent/dist'),
        },
    }),
    Object.assign(Object.assign({}, base), {
        name: 'caller',
        entry: './agent/caller.ts',
        output: {
            filename: 'caller.js',
            path: resolve('./agent/dist'),
        },
    }),
];
