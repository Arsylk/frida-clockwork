type Returnable = (...args: any) => any;
type ReturnOptional<T extends Returnable> = (
  this: ThisType<T>,
  ...args: Parameters<T>
) => ReturnType<T> | undefined;
type OmitFirstArg<T> = T extends (x: any, ...args: infer P) => infer R ? (...args: P) => R : never;
type StructTypes =
  | 'short'
  | 'int'
  | 'uint'
  | 'long'
  | 'string'
  | 'string*'
  | 'pointer'
  | 'char'
  | 'uint64'
  | 'int64'
  | 'short'
  | 'ushort'
  | 'byte';
type JavaArgument = any;
type JavaArguments = Variadic;

export type { JavaArgument, JavaArguments, OmitFirstArg, ReturnOptional, Returnable, StructTypes };
