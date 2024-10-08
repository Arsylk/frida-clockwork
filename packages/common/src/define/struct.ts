import { type PropertyStructMapper, type StructCreator, proxyStruct } from '../internal/proxy.js';
import type { StructTypes } from '../types.js';

const Time = {
    tm: proxyStruct({
        tm_sec: 'int',
        tm_min: 'int',
        tm_hour: 'int',
        tm_mday: 'int',
        tm_mon: 'int',
        tm_year: 'int',
        tm_wday: 'int',
        tm_yday: 'int',
        tm_isdst: 'long',
        tm_gmtoff: 'long',
        tm_zone: 'pointer', // -> string
    }),
    timeval: proxyStruct({
        tv_sec: 'int',
        tv_usec: 'int',
    }),
    timezone: proxyStruct({
        tz_minuteswest: 'int',
        tz_dsttime: 'int',
    }),
};

const Stat = {
    timespec: proxyStruct({
        tv_sec: 'long',
        tv_nsec: 'long',
    }),
    stat: proxyStruct({
        st_dev: 'long',
        __pad0: 'string',
        __st_ino: 'long',
        st_mode: 'int',
        st_nlink: 'int',
        st_uid: 'long',
        st_gid: 'long',
        st_rdev: 'long',
        __pad3: 'string',
        st_size: 'long',
        st_blksize: 'long',
        st_blocks: 'long',
        st_atim: 'pointer', // -> timespec
        st_mtim: 'pointer', // -> timespec
        st_ctim: 'pointer', // -> timespec
        st_ino: 'long',
    }),
};

const Unity = {
    Il2CppClass: proxyStruct({
        image: 'pointer',
        gc_desc: 'pointer',
        name: 'string*',
        namespaze: 'string*',
        byval_arg_data: 'pointer',
        byval_arg_bits: 'short',
        this_arg_data: 'pointer',
        this_arg_bits: 'short',
        element_class: 'pointer',
        castClass: 'pointer',
        declaringType: 'pointer',
        parent: 'pointer',
        generic_class: 'pointer',
        typeMetadataHandle: 'pointer',
        interopData: 'pointer',
        klass: 'pointer',
        fields: 'pointer',
        events: 'pointer',
        properties: 'pointer',
        methods: 'pointer',
        nestedTypes: 'pointer',
        implementedInterfaces: 'pointer',
        interfaceOffsets: 'pointer',
    }),
};

function malloc<T extends { [key: string]: StructTypes }>(struct: StructCreator<T>) {
    return struct(Memory.alloc(struct.size));
}

function toObject<T extends { [key: string]: StructTypes }>(struct: PropertyStructMapper<T>) {
    return Object.assign(
        {},
        ...Reflect.ownKeys(struct).map((k: symbol | string) => {
            const { value } = struct[k as string];
            return { [k]: value };
        }),
    );
}

export { Stat, Time, Unity, malloc, toObject };
