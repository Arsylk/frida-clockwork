import { resolve } from "node:path";
import * as url from "node:url";
const __dirname = url.fileURLToPath(new URL("..", import.meta.url));

export default {
  name: "agent",
  entry: {
    script: "./agent/script.ts",
    justdump: "./agent/justdump.ts",
    justcocos: "./agent/justcocos.ts",
    justcli: "./agent/justcli.ts",
    justcloak: "./agent/justcloak.ts",
    libreveny: "./agent/libreveny.so.ts",
  },
  output: {
    filename: "[name].js",
    path: resolve("./agent/dist"),
    assetModuleFilename: "clang/[hash][ext]",
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: "ts-loader",
        exclude: /node_modules/,
      },
      {
        test: /\.c$/,
        type: "asset",
        parser: {
          dataUrlCondition: {
            maxSize: 100 * 1024,
          },
        },
      },
    ],
  },
  resolve: {
    extensions: [".ts", ".js"],
    alias: {
      "@src": "../src/",
    },
    fallback: {
      assert: "@frida/assert",
      "base64-js": "@frida/base64-js",
      buffer: "@frida/buffer",
      crosspath: "@frida/crosspath",
      crypto: "@frida/crypto",
      diagnostics_channel: "@frida/diagnostics_channel",
      events: "@frida/events",
      http: "@frida/http",
      "http-parser-js": "@frida/http-parser-js",
      https: "@frida/https",
      ieee754: "@frida/ieee754",
      net: "@frida/net",
      os: "@frida/os",
      path: "@frida/path",
      process: "@frida/process",
      punycode: "@frida/punycode",
      querystring: "@frida/querystring",
      "readable-stream": "@frida/readable-stream",
      "reserved-words": "@frida/reserved-words",
      stream: "@frida/stream",
      string_decoder: "@frida/string_decoder",
      terser: "@frida/terser",
      timers: "@frida/timers",
      tty: "@frida/tty",
      url: "@frida/url",
      util: "@frida/util",
      vm: "@frida/vm",
      fs: "frida-fs",
    },
  },
  mode: "development",
  devtool: "inline-source-map",
};
