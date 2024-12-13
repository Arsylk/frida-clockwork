import { subLogger } from '@clockwork/logging';
import { getSelfFiles, mkdir } from '@clockwork/native';
const logger = subLogger('dexdump');

const FLAG_ENABLE_DEEP_SEARCH = false;

function dump() {
    let enable_deep_search = FLAG_ENABLE_DEEP_SEARCH;
    mkdir(`${getSelfFiles()}/frida_dumped_files/`);
    const scandexVar = scandex();
    scandexVar.forEach((scandex) => {
        try {
            const buf = memorydump(scandex.addr, scandex.size);

            logger.trace(typeof buf);

            let buffer;
            if (buf?.slice(0, 4) != getBytesFromString('dex\n')) {
                // const buffer =
                // getConcatByteArrays(getBytesFromString("dex\n035\x00"),buf.slice(8,buf.byteLength))
                // const concatenated = await new Blob([
                // getBytesFromString("dex\n035\x00"), buf.slice(8,buf.length)
                // ]).arrayBuffer();

                // buffer.set( getBytesFromString("dex\n035\x00"), 0)
                // buffer.set( buf.slice(8,buf.length), 8)
                buffer = buf;
            } else {
                buffer = buf;
            }

            // For Device
            //@ts-ignore
            const file: any = new File(
                //@ts-ignore
                `${getSelfFiles()}/frida_dumped_files/${scandex.addr}.dex`,
                'wb',
            );
            file.write(buffer);
            file.flush();
            file.close();
        } catch (e) {
            logger.warn(e);
        }
    });

    function getBytesFromString(str: string) {
        const buffer: any = new ArrayBuffer(str.length);
        for (let i = 0; i < str.length; ++i) {
            const code = str.charCodeAt(i);
            buffer[i] = [code & 0xff, (code / 256) >>> 0];
        }

        return buffer;
    }

    function getConcatByteArrays(array1: any, array2: any) {
        logger.trace(typeof array1);
        // logger.trace(array2)

        const buffer: any = new ArrayBuffer(array1.byteLength + array2.byteLength);
        for (let i = 0; i < array1.byteLength; ++i) {
            buffer[i] = array1[i];
        }
        logger.trace(typeof buffer);

        for (let i = array1.byteLength; i < array1.byteLength + array2.byteLength; ++i) {
            buffer[i] = array2[i];
        }

        // logger.trace(buffer)

        return buffer;
    }

    function memorydump(address: NativePointer, size: number) {
        // return new NativePointer(address).readByteArray(size);
        return address.readByteArray(size);
    }

    function switchmode(bool: boolean) {
        enable_deep_search = bool;
    }

    function scandex() {
        const result: any[] = [];
        Process.enumerateRanges('r--').forEach((range) => {
            try {
                Memory.scanSync(range.base, range.size, '64 65 78 0a 30 ?? ?? 00').forEach((match) => {
                    // range.file.path.startsWith("/data/app/") ||
                    if (
                        range?.file?.path?.startsWith('/data/dalvik-cache/') ||
                        range?.file?.path?.startsWith('/system/')
                    ) {
                        return;
                    }

                    if (verify(match.address, range, false)) {
                        const dex_size = match.address.add(0x20).readUInt();
                        result.push({ addr: match.address, size: dex_size });
                    }
                });

                if (enable_deep_search) {
                    Memory.scanSync(range.base, range.size, '70 00 00 00').forEach((match) => {
                        const dex_base = match.address.sub(0x3c);
                        if (dex_base < range.base) {
                            return;
                        }
                        if (dex_base.readCString(4) != 'dex\n' && verify(dex_base, range, true)) {
                            const dex_size = dex_base.add(0x20).readUInt();
                            result.push({ addr: dex_base, size: dex_size });
                        }
                    });
                } else {
                    if (range.base.readCString(4) != 'dex\n' && verify(range.base, range, true)) {
                        const dex_size = range.base.add(0x20).readUInt();
                        result.push({ addr: range.base, size: dex_size });
                    }
                }
            } catch (e) {}
        });

        return result;
    }
}

function verify(dexptr: NativePointer, range: RangeDetails | null, enable_verify_maps: boolean) {
    if (range != null) {
        const range_end = range.base.add(range.size);
        // verify header_size
        if (dexptr.add(0x70) > range_end) {
            return false;
        }

        // verify file_size
        const dex_size = dexptr.add(0x20).readUInt();
        if (dexptr.add(dex_size) > range_end) {
            return false;
        }

        if (enable_verify_maps) {
            const maps_offset = dexptr.add(0x34).readUInt();
            if (maps_offset === 0) {
                return false;
            }

            const maps_address = dexptr.add(maps_offset);
            if (maps_address > range_end) {
                return false;
            }

            const maps_size = maps_address.readUInt();
            if (maps_size < 2 || maps_size > 50) {
                return false;
            }
            const maps_end = maps_address.add(maps_size * 0xc + 4);
            if (maps_end < range.base || maps_end > range_end) {
                return false;
            }
            return verifyByMaps(dexptr, maps_address);
        } else {
            return dexptr.add(0x3c).readUInt() === 0x70;
        }
    }
}

function verifyByMaps(dexptr: NativePointer, mapsptr: NativePointer) {
    const maps_offset = dexptr.add(0x34).readUInt();
    const maps_size = mapsptr.readUInt();
    for (let i = 0; i < maps_size; i++) {
        const item_type = mapsptr.add(4 + i * 0xc).readU16();
        if (item_type === 4096) {
            const map_offset = mapsptr.add(4 + i * 0xc + 8).readUInt();
            if (maps_offset === map_offset) {
                return true;
            }
        }
    }
    return false;
}

/**
 * The entrypoint function.
 */
function scheduleDexDump(delay = 10_000) {
    setTimeout(() => {
        Java.performNow(() => {
            logger.info('start dumping');
            try {
                dump();
            } catch (err: any) {
                logger.warn(`failed to dump:${err.message}`);
                return;
            }
            logger.info('finish dumping');
        });
    }, delay);
}

function hookArtLoader() {
    const hashMap = new Map<string, string>();
    let basepath: string | null = null;
    let dexCount = 1;

    const onEnter = (args: InvocationArguments) => {
        const dexPtr = args[5];
        //ptr(dex_file).add(Process.pointerSize) is "const uint8_t* const begin_;"
        //ptr(dex_file).add(Process.pointerSize + Process.pointerSize) is "const size_t size_;"
        const base = dexPtr.add(Process.pointerSize).readPointer();
        const size = dexPtr.add(Process.pointerSize * 2).readUInt();
        const key = `${base}`;
        const value = `${size}`;

        if (hashMap.get(key) === value) return;
        hashMap.set(key, value);

        const magic = base.readCString();
        if (magic?.includes('dex')) {
            const dexPath = `${getSelfFiles()}/dump_dex`;
            mkdir(dexPath);
            const dexFile = `${basepath ?? dexPath}/class${dexCount === 1 ? '' : dexCount}.dex`;
            logger.info({ tag: 'art' }, `dex: ${dexFile}`);
            dexCount += 1;
            //@ts-ignore
            File.writeAllBytes(dexFile, base.readByteArray(size));
            basepath ??= dexPath;
        }
    };

    const libart = Process.getModuleByName('libart.so');
    for (const { name, address } of libart.enumerateSymbols()) {
        //这个DefineClass的函数签名是Android9的
        //_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE
        if (
            name.includes('ClassLinker') &&
            name.includes('DefineClass') &&
            name.includes('Thread') &&
            name.includes('DexFile')
        ) {
            logger.info({ tag: 'art' }, `${name}: ${address}`);
            Interceptor.attach(address, {
                onEnter: onEnter,
            });
        }
    }
}

export { verify as dexBytesVerify, scheduleDexDump, hookArtLoader };
