import { Libc, Text } from '@clockwork/common';
import { Color, logger } from '@clockwork/logging';
import { addressOf } from '@clockwork/native';

function attachGetHostByName() {
    Interceptor.attach(Libc.gethostbyname, {
        onEnter(args) {
            this.name = args[0].readCString();
        },
        onLeave(retval) {
            logger.info(
                { tag: 'gethostbyname' },
                `${Color.url(this.name)} -> result: ${retval} ${addressOf(this.returnAddress)}`,
            );
        },
    });
}

function attachGetAddrInfo(detailed = false) {
    Interceptor.attach(Libc.getaddrinfo, {
        onEnter(args) {
            this.host = args[0].readCString();
            this.port = args[1].readCString();
            this.result = args[2];
        },
        onLeave(retval) {
            const resInt = retval.toUInt32();
            const port = `${this.port}`;
            let text = `${this.host}`;
            if (port && port !== 'null') {
                if (port.match(/[0-9]+/)) {
                    text = `${text}:${port}`;
                } else {
                    text = `${port}://${text}`;
                }
            }
            const result = resInt === 0x0 ? 'success' : 'failure';
            logger.info(
                { tag: 'getaddrinfo' },
                `${Color.url(text)} -> ${result} ${addressOf(this.returnAddress)}`,
            );
            if (resInt === 0x0) {
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

                const text = Text.stringify({
                    aiFlags: aiFlags,
                    aiFamilty: aiFamilty,
                    aiSockType: aiSockType,
                    aiProtocol: aiProtocol,
                    aiAddrLen: aiAddrLen,
                    aiAddr: aiAddr,
                    aiCannonName: aiCannonName,
                    aiNext: aiNext,
                });
                logger.info({ tag: 'getaddrinfo' }, `${text} ${addressOf(this.returnAddress)}`);
            }
        },
    });
}

function attachInetAton() {
    Interceptor.attach(Libc.inet_aton, {
        onEnter(args) {
            this.addr = args[0].readCString();
        },
        onLeave(retval) {
            logger.info({ tag: 'inet_aton' }, `${this.addr} -> ${retval} ${addressOf(this.returnAddress)}`);
        },
    });

    Interceptor.attach(Libc.inet_addr, {
        onEnter(args) {
            this.addr = args[0].readCString();
        },
        onLeave(retval) {
            logger.info({ tag: 'inet_addr' }, `${this.addr} -> ${retval} ${addressOf(this.returnAddress)}`);
        },
    });
}
export { attachGetAddrInfo, attachGetHostByName, attachInetAton as attachInteAton };
