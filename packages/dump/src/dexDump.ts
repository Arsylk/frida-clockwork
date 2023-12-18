import { subLogger } from "@clockwork/logging";
const logger = subLogger('dexdump')

const FLAG_ENABLE_DEEP_SEARCH = false;

function dump() {
    var enable_deep_search = FLAG_ENABLE_DEEP_SEARCH;
    var know_paths = ['.js', '.html', '.xml'];
    var AppClassLoader = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext().getClassLoader();
    var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
    var context = currentApplication.getApplicationContext();

    var file = Java.use('java.io.File');
    var string = Java.use('java.lang.String');
    var BufferedInputStream = Java.use('java.io.BufferedInputStream');
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    var OutputStreamWriter = Java.use('java.io.BufferedOutputStream');
    var files_path = 'widget';
    var listFile = context.getAssets().list(files_path);
    var strClass = Java.use('java.lang.String');
    logger.trace(listFile);

    // For Device
    var dir_to_write = file.$new(context.getFilesDir() + "/frida_dumped_files/");
    dir_to_write.mkdirs();
    var scandexVar = scandex();
    // logger.trace(JSON.stringify(scandexVar))

    // missing cleanup

    scandexVar.forEach((scandex) => {
        try {
            const buf = memorydump(scandex.addr, scandex.size);

            logger.trace(typeof buf);

            if (buf?.slice(0, 4) != getBytesFromString('dex\n')) {
                // var buffer =
                // getConcatByteArrays(getBytesFromString("dex\n035\x00"),buf.slice(8,buf.byteLength))
                // var concatenated = await new Blob([
                // getBytesFromString("dex\n035\x00"), buf.slice(8,buf.length)
                // ]).arrayBuffer();

                // buffer.set( getBytesFromString("dex\n035\x00"), 0)
                // buffer.set( buf.slice(8,buf.length), 8)
                var buffer = buf;
            } else {
                var buffer = buf;
            }

            // For Device
            //@ts-ignore
            var file: any = new File(context.getFilesDir() + `/frida_dumped_files/${scandex.addr}.dex`, 'wb');
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
        const result: any[]  = [];
        Process.enumerateRanges('r--').forEach(function (range) {
            try {
                Memory.scanSync(range.base, range.size, '64 65 78 0a 30 ?? ?? 00').forEach(function (match) {
                    // range.file.path.startsWith("/data/app/") ||
                    if (range?.file?.path?.startsWith('/data/dalvik-cache/') || range?.file?.path?.startsWith('/system/')) {
                        return;
                    }

                    if (verify(match.address, range, false)) {
                        const dex_size = match.address.add(0x20).readUInt();
                        result.push({ addr: match.address, size: dex_size });
                    }
                });

                if (enable_deep_search) {
                    Memory.scanSync(range.base, range.size, '70 00 00 00').forEach(function (match) {
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

    function verify_by_maps(dexptr: NativePointer, mapsptr: NativePointer) {
        var maps_offset = dexptr.add(0x34).readUInt();
        var maps_size = mapsptr.readUInt();
        for (var i = 0; i < maps_size; i++) {
            var item_type = mapsptr.add(4 + i * 0xc).readU16();
            if (item_type === 4096) {
                var map_offset = mapsptr.add(4 + i * 0xc + 8).readUInt();
                if (maps_offset === map_offset) {
                    return true;
                }
            }
        }
        return false;
    }

    function verify(dexptr: NativePointer, range: RangeDetails | null, enable_verify_maps: boolean) {
        if (range != null) {
            var range_end = range.base.add(range.size);
            // verify header_size
            if (dexptr.add(0x70) > range_end) {
                return false;
            }

            // verify file_size
            var dex_size = dexptr.add(0x20).readUInt();
            if (dexptr.add(dex_size) > range_end) {
                return false;
            }

            if (enable_verify_maps) {
                var maps_offset = dexptr.add(0x34).readUInt();
                if (maps_offset === 0) {
                    return false;
                }

                var maps_address = dexptr.add(maps_offset);
                if (maps_address > range_end) {
                    return false;
                }

                var maps_size = maps_address.readUInt();
                if (maps_size < 2 || maps_size > 50) {
                    return false;
                }
                var maps_end = maps_address.add(maps_size * 0xc + 4);
                if (maps_end < range.base || maps_end > range_end) {
                    return false;
                }
                return verify_by_maps(dexptr, maps_address);
            } else {
                return dexptr.add(0x3c).readUInt() === 0x70;
            }
        }
    }
}

/**
 * The entrypoint function.
 */
function scheduleDexDump(delay: number = 10_000) {
    setTimeout(() => {
        Java.performNow(() => {
            logger.info('start dumping');
            try {
                dump();
            } catch (err: any) {
                logger.warn('failed to dump:' + err.message);
                return;
            }
            logger.info('finish dumping');
        });
    }, delay);
}


export { scheduleDexDump }
