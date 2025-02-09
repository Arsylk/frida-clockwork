import * as Anticloak from '@clockwork/anticloak';
import * as Native from '@clockwork/native';
import { injectSsl } from '@clockwork/network';
import { Inject, ProcMaps } from '@clockwork/cmodules';
import { Color, logger } from '@clockwork/logging';
const { red, green, redBright, magentaBright: pink, gray, dim, black } = Color.use();

const predicate: (ptr: NativePointer) => true | undefined = () => true;

Native.attachSystemPropertyGet(predicate, (key) => {
    const value = Anticloak.BuildProp.propMapper(key);
    return value;
});

Inject.registerCallback(() => {});
