import { tryNull } from '@clockwork/common';
import { subLogger } from '@clockwork/logging';
import * as Native from '@clockwork/native';
import 'frida-il2cpp-bridge';
const logger = subLogger('unity');

Object.defineProperty(globalThis, 'Il2Cpp', { value: Il2Cpp, writable: false });

function setVersion(version: string) {
    (globalThis as typeof globalThis & { IL2CPP_UNITY_VERSION: string }).IL2CPP_UNITY_VERSION = version;
}

function attachStrings() {
    Il2Cpp.perform(() => {
        // const mscorlib = Il2Cpp.domain.assembly('mscorlib').image;
        // const concat = mscorlib.class('System.String').method<Il2Cpp.String>('Concat', 1);
        // concat.implementation = (...args) => {
        //     const ret = mscorlib.class('System.String').method<Il2Cpp.String>('Concat', 1).invoke(args[0]);
        //     if (ret.toString().includes('http://18.141.246.67/api/res_config?channel=')) {
        //         return Il2Cpp.string('https://pastebin.com/raw/29VmuaFs');
        //     }
        //     return ret;
        // };

        // const SystemString = Il2Cpp.corlib.assembly.image.class('System.String');
        // logger.info({ tag: 'test' }, `${SystemString}`);
        // logger.info({ tag: 'test' }, `${SystemString.methods}`);
        // const Contains = SystemString.method<boolean>('Contains', 1);
        // Contains.implementation = function (...args) {
        //     logger.info({ tag: 'System.String.Contains' }, `${this} =~ ${args[0]}`);
        //     if (new Il2Cpp.String(args[0] as NativePointer).content === 'Brazil') return true;
        //     return this.method<boolean>(Contains.name, Contains.parameterCount).invoke(...args);
        // };

        Il2Cpp.trace(true)
            .assemblies(Il2Cpp.corlib.assembly)
            .filterClasses((kclass) => kclass.name === 'String')
            .filterMethods(
                (m) =>
                    !m.name.includes('get_Chars') &&
                    !m.name.includes('FastAllocateString') &&
                    // !m.name.includes('FillStringChecked') &&
                    !m.name.includes('CtorCharArrayStartLength') &&
                    m.name !== 'Ctor' &&
                    m.name !== 'CreateString' &&
                    m.name !== 'wstrcpy',
            )
            .and()
            .attach();
    });
}

function attachScenes() {
    Il2Cpp.perform(() => {
        const CoreModule = Il2Cpp.domain.assembly('UnityEngine.CoreModule');
        Il2Cpp.trace(true)
            .assemblies(CoreModule)
            .filterClasses((kclass) => kclass.fullName === 'UnityEngine.SceneManagement.SceneManager')
            .and()
            .attach();
    });
}

function unitypatchSsl() {
    Il2Cpp.perform(() => {
        tryNull(() => {
            const WebRequest = Il2Cpp.domain.assembly('UnityEngine.UnityWebRequestModule').image;
            const CertificateHandler = WebRequest.class('UnityEngine.Networking.CertificateHandler');
            const ValidateCertificateNative = CertificateHandler.method<boolean>('ValidateCertificateNative');
            ValidateCertificateNative.implementation = (...args) => true;
        });

        tryNull(() => {
            const TlsProvider = Il2Cpp.domain.assembly('System').image.class('Mono.Unity.UnityTlsProvider');
            const ValidateCertificate = TlsProvider.method<boolean>('ValidateCertificate');
            ValidateCertificate.implementation = (...args) => true;
        });
        tryNull(() => {
            const TlsModule = Il2Cpp.domain.assembly('UnityEngine.TLSModule').image;
            for (const cls of TlsModule.classes) logger.info({ tag: 'il2cls' }, `${cls.name}`);
        });
    });
}

function mempatchSsl() {
    Native.Inject.afterInitArrayModule((m) => {
        const pattern =
            'f? ?? ?c ?? f7 5b 01 a9 f5 53 02 a9 f3 7b 03 a9 ?? ?? 40 f9 f3 03 02 aa f4 03 01 aa ?? ?? 40 f9';
        Memory.scan(m.base, m.size, pattern, {
            onMatch(address, size) {
                logger.info(
                    `Memory.scan() found match at ${address.sub(m.base)} with size ${size}\nGhidra addr ${address.sub(m.base).add(0x100000)}`,
                );
                logger.info('Hooking SSL pinning!');
                if (Process.pointerSize === 0x8) {
                    Interceptor.attach(address, {
                        onLeave: (retval) => {
                            retval.replace(ptr(0x0));
                        },
                    });
                }
                return 'stop';
            },
            onComplete() {
                logger.trace(`Memory.scan() ${pattern} complete`);
            },
        });
    });
}

function patchSsl() {
    unitypatchSsl();
    mempatchSsl();
}

function listGameObjects() {
    Il2Cpp.perform(() => {
        const fmt = (gmObj: Il2Cpp.Object) => {
            return `${gmObj}`;
        };
        const snap = Il2Cpp.MemorySnapshot.capture();
        if (!snap) return;
        for (const obj of snap.objects) {
            logger.info({ tag: 'il2cpp' }, fmt(obj));
        }
    });
}

export { attachScenes, attachStrings, listGameObjects, mempatchSsl, patchSsl, setVersion, unitypatchSsl };
