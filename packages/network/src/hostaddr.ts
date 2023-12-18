import { Libc } from '@clockwork/common';
import { logger, Color } from '@clockwork/logging';

function attachGetHostByName() {
    Interceptor.attach(Libc.gethostbyname, {
        onEnter(args) {
            this.name = args[0].readCString();
        },
        onLeave(retval) {
            logger.info({ tag: 'gethostbyname' }, `${Color.url(this.name)} -> result: ${retval}`);
        },
    });
}

function attachGetAddrInfo(detailed: boolean = false) {
    Interceptor.attach(Libc.getaddrinfo, {
        onEnter(args) {
            this.host = args[0].readCString();
            this.port = args[1].readCString();
            this.result = args[2];
        },
        onLeave(retval) {
            const resInt = retval.toUInt32();
            const text = !this.port || this.port === 'null' ? `${this.host}` : `${this.host}:${this.port}`;
            const result = resInt === 0x0 ? 'success' : 'failure';
            logger.info({ tag: 'getaddrinfo' }, `${Color.url(text)} -> ${result}`);
            if (resInt == 0x0) {
                let ptr: NativePointer = this.result;
                if (!detailed) return;

                const aiFlags = (ptr = ptr.add(0)).readInt();
                const aiFamilty = (ptr = ptr.add(4)).readInt();
                const aiSockType = (ptr = ptr.add(4)).readInt();
                const aiProtocol = (ptr = ptr.add(4)).readInt();
                const aiAddrLen = (ptr = ptr.add(4)).readUInt();
                const aiAddr = (ptr = ptr.add(4)).readPointer();
                const aiCannonName = (ptr = ptr.add(8)).readCString();
                const aiNext = (ptr = ptr.add(8)).readPointer();
                logger.info(
                    { tag: 'getaddrinfo' },
                    JSON.stringify(
                        {
                            aiFlags: aiFlags,
                            aiFamilty: aiFamilty,
                            aiSockType: aiSockType,
                            aiProtocol: aiProtocol,
                            aiAddrLen: aiAddrLen,
                            aiAddr: aiAddr,
                            aiCannonName: aiCannonName,
                            aiNext: aiNext,
                        },
                        null,
                        2,
                    ),
                );
            }
        },
    });
}

function attachInteAton() {
    Interceptor.attach(Libc.inet_aton, {
        onEnter(args) {
            this.addr = args[0].readCString();
        },
        onLeave(retval) {
            logger.info({tag: 'inet_aton'}, `${this.addr} -> ${retval}`)
        },
    })
}


export { attachGetAddrInfo, attachGetHostByName, attachInteAton };
