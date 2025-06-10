import Java from 'frida-java-bridge';
import { logger } from '@clockwork/logging';

type BaseJavaWrapper<T extends Java.Members<T>> = Java.Wrapper<T>;
type BaseJavaMembers<T> = Java.Members<T>;
// biome-ignore lint/complexity/noBannedTypes: Makes types happy
type Wrapper<T extends BaseJavaMembers<T> = {}> = BaseJavaWrapper<T> & {
    // raw name
    $n: string;
    // list members
    $m: string[];
    // native class model
    $l: { find(memeber: string): any; list(): string[] };
    // list all mebmers //? including parent classes
    $list(): string[];
    // get member //? including parent classes
    $find(): any | undefined;
    // has member //? including parent classes
    $has(): boolean;
    // super wrapper
    $s: Wrapper | undefined;
};
interface EnumerateMembersCallbacks {
    onMatchMethod?: (clazz: Wrapper, member: string, depth: number) => void;
    onMatchField?: (clazz: Wrapper, member: string, depth: number) => void;
    onComplete?: () => void;
}
// biome-ignore lint/complexity/noBannedTypes: <explanation>
interface ChooseCallback<T extends Java.Members<T> = {}> {
    // biome-ignore lint/suspicious/noConfusingVoidType: <explanation>
    onMatch?: (instance: Java.Wrapper<T>, factory: Java.ClassFactory) => void | EnumerateAction;
    // biome-ignore lint/suspicious/noConfusingVoidType: <explanation>
    onComplete?: (factory: Java.ClassFactory) => void | EnumerateAction;
}

function enumerateMembers(
    clazz: Java.Wrapper,
    callback: EnumerateMembersCallbacks,
    maxDepth: number = Number.POSITIVE_INFINITY,
) {
    let current: Wrapper | undefined = clazz as Wrapper;
    let depth = 0;
    while (depth < maxDepth && current && current.$n !== 'java.lang.Object') {
        const model = current.$l;
        const members = model.list();

        for (const member of members) {
            const handle = model.find(member);
            switch (`${handle}`.charAt(0)) {
                case 'm': {
                    callback.onMatchMethod?.(current, member, depth);
                    break;
                }
                case 'f': {
                    callback.onMatchField?.(current, member, depth);
                    break;
                }
            }
        }

        current = current.$s;
        depth += 1;
    }

    callback.onComplete?.();
}

function findClass(className: string, ...loaders: Java.Wrapper[]): Java.Wrapper | null {
    try {
        const mLoaders = [...(loaders ??= []), ...Java.enumerateClassLoadersSync()];
        for (const loader of mLoaders) {
            try {
                if (loader.loadClass(className)) {
                    const factory = Java.ClassFactory.get(loader);
                    const cls = factory.use(className);
                    return cls;
                }
            } catch (notFound) {}
        }
    } catch (err) {
        logger.error({ tag: 'findClass' }, JSON.stringify(err));
    }
    return null;
}

function getFindUnique(logging = true) {
    const found = new Set<string>();

    return (clazzName: string, fn: (clazz: Java.Wrapper) => void) => {
        const clazz = findClass(clazzName);
        if (!clazz) {
            logging && logger.info({ tag: 'findUnique' }, `class ${clazzName} not found !`);
            return;
        }

        const ptr = `${clazz.$l.handle}`;
        if (!found.has(ptr)) {
            found.add(ptr);
            fn(clazz);
        }
    };
}

function findChoose(
    className: string,
    callback?: ChooseCallback,
    ...loaders: Java.Wrapper[]
): Java.Wrapper[] {
    const hashes = new Set<number>();
    const results: Java.Wrapper[] = [];
    try {
        const mLoaders = [...(loaders ??= []), ...Java.enumerateClassLoadersSync()];
        for (const loader of mLoaders) {
            try {
                if (loader.loadClass(className)) {
                    let stop = false;
                    const factory = Java.ClassFactory.get(loader);
                    factory.choose(className, {
                        onMatch: (instance) => {
                            const hash = instance.hashCode();
                            if (!hashes.has(hash)) {
                                hashes.add(hash);
                                results.push(instance);
                            }
                            return callback?.onMatch?.(instance, factory);
                        },
                        onComplete() {
                            if (callback?.onComplete?.(factory) === 'stop') {
                                stop = true;
                            }
                        },
                    });
                    if (stop) return results;
                }
            } catch (notFound) {}
        }
    } catch (err) {
        logger.error({ tag: 'findChoose' }, JSON.stringify(err));
    }
    return results;
}

export { enumerateMembers, findChoose, findClass, getFindUnique };
