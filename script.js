/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./node_modules/base64-js/index.js":
/*!*****************************************!*\
  !*** ./node_modules/base64-js/index.js ***!
  \*****************************************/
/***/ ((__unused_webpack_module, exports) => {

"use strict";


exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  var i
  for (i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}


/***/ }),

/***/ "./node_modules/buffer/index.js":
/*!**************************************!*\
  !*** ./node_modules/buffer/index.js ***!
  \**************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */



const base64 = __webpack_require__(/*! base64-js */ "./node_modules/base64-js/index.js")
const ieee754 = __webpack_require__(/*! ieee754 */ "./node_modules/ieee754/index.js")
const customInspectSymbol =
  (typeof Symbol === 'function' && typeof Symbol['for'] === 'function') // eslint-disable-line dot-notation
    ? Symbol['for']('nodejs.util.inspect.custom') // eslint-disable-line dot-notation
    : null

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

const K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    const arr = new Uint8Array(1)
    const proto = { foo: function () { return 42 } }
    Object.setPrototypeOf(proto, Uint8Array.prototype)
    Object.setPrototypeOf(arr, proto)
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  const buf = new Uint8Array(length)
  Object.setPrototypeOf(buf, Buffer.prototype)
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayView(value)
  }

  if (value == null) {
    throw new TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof SharedArrayBuffer !== 'undefined' &&
      (isInstance(value, SharedArrayBuffer) ||
      (value && isInstance(value.buffer, SharedArrayBuffer)))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  const valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  const b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(value[Symbol.toPrimitive]('string'), encodingOrOffset, length)
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Object.setPrototypeOf(Buffer.prototype, Uint8Array.prototype)
Object.setPrototypeOf(Buffer, Uint8Array)

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpreted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  const length = byteLength(string, encoding) | 0
  let buf = createBuffer(length)

  const actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  const length = array.length < 0 ? 0 : checked(array.length) | 0
  const buf = createBuffer(length)
  for (let i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayView (arrayView) {
  if (isInstance(arrayView, Uint8Array)) {
    const copy = new Uint8Array(arrayView)
    return fromArrayBuffer(copy.buffer, copy.byteOffset, copy.byteLength)
  }
  return fromArrayLike(arrayView)
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  let buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(buf, Buffer.prototype)

  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    const len = checked(obj.length) | 0
    const buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  let x = a.length
  let y = b.length

  for (let i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  let i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  const buffer = Buffer.allocUnsafe(length)
  let pos = 0
  for (i = 0; i < list.length; ++i) {
    let buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      if (pos + buf.length > buffer.length) {
        if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf)
        buf.copy(buffer, pos)
      } else {
        Uint8Array.prototype.set.call(
          buffer,
          buf,
          pos
        )
      }
    } else if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    } else {
      buf.copy(buffer, pos)
    }
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  const len = string.length
  const mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  let loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  let loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coercion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  const i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  const len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (let i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  const len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (let i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  const len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (let i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  const length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  let str = ''
  const max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}
if (customInspectSymbol) {
  Buffer.prototype[customInspectSymbol] = Buffer.prototype.inspect
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  let x = thisEnd - thisStart
  let y = end - start
  const len = Math.min(x, y)

  const thisCopy = this.slice(thisStart, thisEnd)
  const targetCopy = target.slice(start, end)

  for (let i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [val], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  let indexSize = 1
  let arrLength = arr.length
  let valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  let i
  if (dir) {
    let foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      let found = true
      for (let j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  const remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  const strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  let i
  for (i = 0; i < length; ++i) {
    const parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  const remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  let loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
      case 'latin1':
      case 'binary':
        return asciiWrite(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  const res = []

  let i = start
  while (i < end) {
    const firstByte = buf[i]
    let codePoint = null
    let bytesPerSequence = (firstByte > 0xEF)
      ? 4
      : (firstByte > 0xDF)
          ? 3
          : (firstByte > 0xBF)
              ? 2
              : 1

    if (i + bytesPerSequence <= end) {
      let secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
const MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  const len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  let res = ''
  let i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  let ret = ''
  end = Math.min(buf.length, end)

  for (let i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  let ret = ''
  end = Math.min(buf.length, end)

  for (let i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  const len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  let out = ''
  for (let i = start; i < end; ++i) {
    out += hexSliceLookupTable[buf[i]]
  }
  return out
}

function utf16leSlice (buf, start, end) {
  const bytes = buf.slice(start, end)
  let res = ''
  // If bytes.length is odd, the last 8 bits must be ignored (same as node.js)
  for (let i = 0; i < bytes.length - 1; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  const len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  const newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(newBuf, Buffer.prototype)

  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUintLE =
Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let val = this[offset]
  let mul = 1
  let i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUintBE =
Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  let val = this[offset + --byteLength]
  let mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUint8 =
Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUint16LE =
Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUint16BE =
Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUint32LE =
Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUint32BE =
Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readBigUInt64LE = defineBigIntMethod(function readBigUInt64LE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const lo = first +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 24

  const hi = this[++offset] +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    last * 2 ** 24

  return BigInt(lo) + (BigInt(hi) << BigInt(32))
})

Buffer.prototype.readBigUInt64BE = defineBigIntMethod(function readBigUInt64BE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const hi = first * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    this[++offset]

  const lo = this[++offset] * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    last

  return (BigInt(hi) << BigInt(32)) + BigInt(lo)
})

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let val = this[offset]
  let mul = 1
  let i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let i = byteLength
  let mul = 1
  let val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  const val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  const val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readBigInt64LE = defineBigIntMethod(function readBigInt64LE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const val = this[offset + 4] +
    this[offset + 5] * 2 ** 8 +
    this[offset + 6] * 2 ** 16 +
    (last << 24) // Overflow

  return (BigInt(val) << BigInt(32)) +
    BigInt(first +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 24)
})

Buffer.prototype.readBigInt64BE = defineBigIntMethod(function readBigInt64BE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const val = (first << 24) + // Overflow
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    this[++offset]

  return (BigInt(val) << BigInt(32)) +
    BigInt(this[++offset] * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    last)
})

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUintLE =
Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  let mul = 1
  let i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUintBE =
Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  let i = byteLength - 1
  let mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUint8 =
Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUint16LE =
Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUint16BE =
Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUint32LE =
Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUint32BE =
Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function wrtBigUInt64LE (buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7)

  let lo = Number(value & BigInt(0xffffffff))
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  let hi = Number(value >> BigInt(32) & BigInt(0xffffffff))
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  return offset
}

function wrtBigUInt64BE (buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7)

  let lo = Number(value & BigInt(0xffffffff))
  buf[offset + 7] = lo
  lo = lo >> 8
  buf[offset + 6] = lo
  lo = lo >> 8
  buf[offset + 5] = lo
  lo = lo >> 8
  buf[offset + 4] = lo
  let hi = Number(value >> BigInt(32) & BigInt(0xffffffff))
  buf[offset + 3] = hi
  hi = hi >> 8
  buf[offset + 2] = hi
  hi = hi >> 8
  buf[offset + 1] = hi
  hi = hi >> 8
  buf[offset] = hi
  return offset + 8
}

Buffer.prototype.writeBigUInt64LE = defineBigIntMethod(function writeBigUInt64LE (value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, BigInt(0), BigInt('0xffffffffffffffff'))
})

Buffer.prototype.writeBigUInt64BE = defineBigIntMethod(function writeBigUInt64BE (value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, BigInt(0), BigInt('0xffffffffffffffff'))
})

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    const limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  let i = 0
  let mul = 1
  let sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    const limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  let i = byteLength - 1
  let mul = 1
  let sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeBigInt64LE = defineBigIntMethod(function writeBigInt64LE (value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, -BigInt('0x8000000000000000'), BigInt('0x7fffffffffffffff'))
})

Buffer.prototype.writeBigInt64BE = defineBigIntMethod(function writeBigInt64BE (value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, -BigInt('0x8000000000000000'), BigInt('0x7fffffffffffffff'))
})

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  const len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      const code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  } else if (typeof val === 'boolean') {
    val = Number(val)
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  let i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    const bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    const len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// CUSTOM ERRORS
// =============

// Simplified versions from Node, changed for Buffer-only usage
const errors = {}
function E (sym, getMessage, Base) {
  errors[sym] = class NodeError extends Base {
    constructor () {
      super()

      Object.defineProperty(this, 'message', {
        value: getMessage.apply(this, arguments),
        writable: true,
        configurable: true
      })

      // Add the error code to the name to include it in the stack trace.
      this.name = `${this.name} [${sym}]`
      // Access the stack to generate the error message including the error code
      // from the name.
      this.stack // eslint-disable-line no-unused-expressions
      // Reset the name to the actual name.
      delete this.name
    }

    get code () {
      return sym
    }

    set code (value) {
      Object.defineProperty(this, 'code', {
        configurable: true,
        enumerable: true,
        value,
        writable: true
      })
    }

    toString () {
      return `${this.name} [${sym}]: ${this.message}`
    }
  }
}

E('ERR_BUFFER_OUT_OF_BOUNDS',
  function (name) {
    if (name) {
      return `${name} is outside of buffer bounds`
    }

    return 'Attempt to access memory outside buffer bounds'
  }, RangeError)
E('ERR_INVALID_ARG_TYPE',
  function (name, actual) {
    return `The "${name}" argument must be of type number. Received type ${typeof actual}`
  }, TypeError)
E('ERR_OUT_OF_RANGE',
  function (str, range, input) {
    let msg = `The value of "${str}" is out of range.`
    let received = input
    if (Number.isInteger(input) && Math.abs(input) > 2 ** 32) {
      received = addNumericalSeparator(String(input))
    } else if (typeof input === 'bigint') {
      received = String(input)
      if (input > BigInt(2) ** BigInt(32) || input < -(BigInt(2) ** BigInt(32))) {
        received = addNumericalSeparator(received)
      }
      received += 'n'
    }
    msg += ` It must be ${range}. Received ${received}`
    return msg
  }, RangeError)

function addNumericalSeparator (val) {
  let res = ''
  let i = val.length
  const start = val[0] === '-' ? 1 : 0
  for (; i >= start + 4; i -= 3) {
    res = `_${val.slice(i - 3, i)}${res}`
  }
  return `${val.slice(0, i)}${res}`
}

// CHECK FUNCTIONS
// ===============

function checkBounds (buf, offset, byteLength) {
  validateNumber(offset, 'offset')
  if (buf[offset] === undefined || buf[offset + byteLength] === undefined) {
    boundsError(offset, buf.length - (byteLength + 1))
  }
}

function checkIntBI (value, min, max, buf, offset, byteLength) {
  if (value > max || value < min) {
    const n = typeof min === 'bigint' ? 'n' : ''
    let range
    if (byteLength > 3) {
      if (min === 0 || min === BigInt(0)) {
        range = `>= 0${n} and < 2${n} ** ${(byteLength + 1) * 8}${n}`
      } else {
        range = `>= -(2${n} ** ${(byteLength + 1) * 8 - 1}${n}) and < 2 ** ` +
                `${(byteLength + 1) * 8 - 1}${n}`
      }
    } else {
      range = `>= ${min}${n} and <= ${max}${n}`
    }
    throw new errors.ERR_OUT_OF_RANGE('value', range, value)
  }
  checkBounds(buf, offset, byteLength)
}

function validateNumber (value, name) {
  if (typeof value !== 'number') {
    throw new errors.ERR_INVALID_ARG_TYPE(name, 'number', value)
  }
}

function boundsError (value, length, type) {
  if (Math.floor(value) !== value) {
    validateNumber(value, type)
    throw new errors.ERR_OUT_OF_RANGE(type || 'offset', 'an integer', value)
  }

  if (length < 0) {
    throw new errors.ERR_BUFFER_OUT_OF_BOUNDS()
  }

  throw new errors.ERR_OUT_OF_RANGE(type || 'offset',
                                    `>= ${type ? 1 : 0} and <= ${length}`,
                                    value)
}

// HELPER FUNCTIONS
// ================

const INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  let codePoint
  const length = string.length
  let leadSurrogate = null
  const bytes = []

  for (let i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  const byteArray = []
  for (let i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  let c, hi, lo
  const byteArray = []
  for (let i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  let i
  for (i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

// Create lookup table for `toString('hex')`
// See: https://github.com/feross/buffer/issues/219
const hexSliceLookupTable = (function () {
  const alphabet = '0123456789abcdef'
  const table = new Array(256)
  for (let i = 0; i < 16; ++i) {
    const i16 = i * 16
    for (let j = 0; j < 16; ++j) {
      table[i16 + j] = alphabet[i] + alphabet[j]
    }
  }
  return table
})()

// Return not function with Error if BigInt not supported
function defineBigIntMethod (fn) {
  return typeof BigInt === 'undefined' ? BufferBigIntNotDefined : fn
}

function BufferBigIntNotDefined () {
  throw new Error('BigInt not supported')
}


/***/ }),

/***/ "./node_modules/events/events.js":
/*!***************************************!*\
  !*** ./node_modules/events/events.js ***!
  \***************************************/
/***/ ((module) => {

"use strict";
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.



var R = typeof Reflect === 'object' ? Reflect : null
var ReflectApply = R && typeof R.apply === 'function'
  ? R.apply
  : function ReflectApply(target, receiver, args) {
    return Function.prototype.apply.call(target, receiver, args);
  }

var ReflectOwnKeys
if (R && typeof R.ownKeys === 'function') {
  ReflectOwnKeys = R.ownKeys
} else if (Object.getOwnPropertySymbols) {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target)
      .concat(Object.getOwnPropertySymbols(target));
  };
} else {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target);
  };
}

function ProcessEmitWarning(warning) {
  if (console && console.warn) console.warn(warning);
}

var NumberIsNaN = Number.isNaN || function NumberIsNaN(value) {
  return value !== value;
}

function EventEmitter() {
  EventEmitter.init.call(this);
}
module.exports = EventEmitter;
module.exports.once = once;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._eventsCount = 0;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
var defaultMaxListeners = 10;

function checkListener(listener) {
  if (typeof listener !== 'function') {
    throw new TypeError('The "listener" argument must be of type Function. Received type ' + typeof listener);
  }
}

Object.defineProperty(EventEmitter, 'defaultMaxListeners', {
  enumerable: true,
  get: function() {
    return defaultMaxListeners;
  },
  set: function(arg) {
    if (typeof arg !== 'number' || arg < 0 || NumberIsNaN(arg)) {
      throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + arg + '.');
    }
    defaultMaxListeners = arg;
  }
});

EventEmitter.init = function() {

  if (this._events === undefined ||
      this._events === Object.getPrototypeOf(this)._events) {
    this._events = Object.create(null);
    this._eventsCount = 0;
  }

  this._maxListeners = this._maxListeners || undefined;
};

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
  if (typeof n !== 'number' || n < 0 || NumberIsNaN(n)) {
    throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received ' + n + '.');
  }
  this._maxListeners = n;
  return this;
};

function _getMaxListeners(that) {
  if (that._maxListeners === undefined)
    return EventEmitter.defaultMaxListeners;
  return that._maxListeners;
}

EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
  return _getMaxListeners(this);
};

EventEmitter.prototype.emit = function emit(type) {
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  var doError = (type === 'error');

  var events = this._events;
  if (events !== undefined)
    doError = (doError && events.error === undefined);
  else if (!doError)
    return false;

  // If there is no 'error' event listener then throw.
  if (doError) {
    var er;
    if (args.length > 0)
      er = args[0];
    if (er instanceof Error) {
      // Note: The comments on the `throw` lines are intentional, they show
      // up in Node's output if this results in an unhandled exception.
      throw er; // Unhandled 'error' event
    }
    // At least give some kind of context to the user
    var err = new Error('Unhandled error.' + (er ? ' (' + er.message + ')' : ''));
    err.context = er;
    throw err; // Unhandled 'error' event
  }

  var handler = events[type];

  if (handler === undefined)
    return false;

  if (typeof handler === 'function') {
    ReflectApply(handler, this, args);
  } else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      ReflectApply(listeners[i], this, args);
  }

  return true;
};

function _addListener(target, type, listener, prepend) {
  var m;
  var events;
  var existing;

  checkListener(listener);

  events = target._events;
  if (events === undefined) {
    events = target._events = Object.create(null);
    target._eventsCount = 0;
  } else {
    // To avoid recursion in the case that type === "newListener"! Before
    // adding it to the listeners, first emit "newListener".
    if (events.newListener !== undefined) {
      target.emit('newListener', type,
                  listener.listener ? listener.listener : listener);

      // Re-assign `events` because a newListener handler could have caused the
      // this._events to be assigned to a new object
      events = target._events;
    }
    existing = events[type];
  }

  if (existing === undefined) {
    // Optimize the case of one listener. Don't need the extra array object.
    existing = events[type] = listener;
    ++target._eventsCount;
  } else {
    if (typeof existing === 'function') {
      // Adding the second element, need to change to array.
      existing = events[type] =
        prepend ? [listener, existing] : [existing, listener];
      // If we've already got an array, just append.
    } else if (prepend) {
      existing.unshift(listener);
    } else {
      existing.push(listener);
    }

    // Check for listener leak
    m = _getMaxListeners(target);
    if (m > 0 && existing.length > m && !existing.warned) {
      existing.warned = true;
      // No error code for this since it is a Warning
      // eslint-disable-next-line no-restricted-syntax
      var w = new Error('Possible EventEmitter memory leak detected. ' +
                          existing.length + ' ' + String(type) + ' listeners ' +
                          'added. Use emitter.setMaxListeners() to ' +
                          'increase limit');
      w.name = 'MaxListenersExceededWarning';
      w.emitter = target;
      w.type = type;
      w.count = existing.length;
      ProcessEmitWarning(w);
    }
  }

  return target;
}

EventEmitter.prototype.addListener = function addListener(type, listener) {
  return _addListener(this, type, listener, false);
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.prependListener =
    function prependListener(type, listener) {
      return _addListener(this, type, listener, true);
    };

function onceWrapper() {
  if (!this.fired) {
    this.target.removeListener(this.type, this.wrapFn);
    this.fired = true;
    if (arguments.length === 0)
      return this.listener.call(this.target);
    return this.listener.apply(this.target, arguments);
  }
}

function _onceWrap(target, type, listener) {
  var state = { fired: false, wrapFn: undefined, target: target, type: type, listener: listener };
  var wrapped = onceWrapper.bind(state);
  wrapped.listener = listener;
  state.wrapFn = wrapped;
  return wrapped;
}

EventEmitter.prototype.once = function once(type, listener) {
  checkListener(listener);
  this.on(type, _onceWrap(this, type, listener));
  return this;
};

EventEmitter.prototype.prependOnceListener =
    function prependOnceListener(type, listener) {
      checkListener(listener);
      this.prependListener(type, _onceWrap(this, type, listener));
      return this;
    };

// Emits a 'removeListener' event if and only if the listener was removed.
EventEmitter.prototype.removeListener =
    function removeListener(type, listener) {
      var list, events, position, i, originalListener;

      checkListener(listener);

      events = this._events;
      if (events === undefined)
        return this;

      list = events[type];
      if (list === undefined)
        return this;

      if (list === listener || list.listener === listener) {
        if (--this._eventsCount === 0)
          this._events = Object.create(null);
        else {
          delete events[type];
          if (events.removeListener)
            this.emit('removeListener', type, list.listener || listener);
        }
      } else if (typeof list !== 'function') {
        position = -1;

        for (i = list.length - 1; i >= 0; i--) {
          if (list[i] === listener || list[i].listener === listener) {
            originalListener = list[i].listener;
            position = i;
            break;
          }
        }

        if (position < 0)
          return this;

        if (position === 0)
          list.shift();
        else {
          spliceOne(list, position);
        }

        if (list.length === 1)
          events[type] = list[0];

        if (events.removeListener !== undefined)
          this.emit('removeListener', type, originalListener || listener);
      }

      return this;
    };

EventEmitter.prototype.off = EventEmitter.prototype.removeListener;

EventEmitter.prototype.removeAllListeners =
    function removeAllListeners(type) {
      var listeners, events, i;

      events = this._events;
      if (events === undefined)
        return this;

      // not listening for removeListener, no need to emit
      if (events.removeListener === undefined) {
        if (arguments.length === 0) {
          this._events = Object.create(null);
          this._eventsCount = 0;
        } else if (events[type] !== undefined) {
          if (--this._eventsCount === 0)
            this._events = Object.create(null);
          else
            delete events[type];
        }
        return this;
      }

      // emit removeListener for all listeners on all events
      if (arguments.length === 0) {
        var keys = Object.keys(events);
        var key;
        for (i = 0; i < keys.length; ++i) {
          key = keys[i];
          if (key === 'removeListener') continue;
          this.removeAllListeners(key);
        }
        this.removeAllListeners('removeListener');
        this._events = Object.create(null);
        this._eventsCount = 0;
        return this;
      }

      listeners = events[type];

      if (typeof listeners === 'function') {
        this.removeListener(type, listeners);
      } else if (listeners !== undefined) {
        // LIFO order
        for (i = listeners.length - 1; i >= 0; i--) {
          this.removeListener(type, listeners[i]);
        }
      }

      return this;
    };

function _listeners(target, type, unwrap) {
  var events = target._events;

  if (events === undefined)
    return [];

  var evlistener = events[type];
  if (evlistener === undefined)
    return [];

  if (typeof evlistener === 'function')
    return unwrap ? [evlistener.listener || evlistener] : [evlistener];

  return unwrap ?
    unwrapListeners(evlistener) : arrayClone(evlistener, evlistener.length);
}

EventEmitter.prototype.listeners = function listeners(type) {
  return _listeners(this, type, true);
};

EventEmitter.prototype.rawListeners = function rawListeners(type) {
  return _listeners(this, type, false);
};

EventEmitter.listenerCount = function(emitter, type) {
  if (typeof emitter.listenerCount === 'function') {
    return emitter.listenerCount(type);
  } else {
    return listenerCount.call(emitter, type);
  }
};

EventEmitter.prototype.listenerCount = listenerCount;
function listenerCount(type) {
  var events = this._events;

  if (events !== undefined) {
    var evlistener = events[type];

    if (typeof evlistener === 'function') {
      return 1;
    } else if (evlistener !== undefined) {
      return evlistener.length;
    }
  }

  return 0;
}

EventEmitter.prototype.eventNames = function eventNames() {
  return this._eventsCount > 0 ? ReflectOwnKeys(this._events) : [];
};

function arrayClone(arr, n) {
  var copy = new Array(n);
  for (var i = 0; i < n; ++i)
    copy[i] = arr[i];
  return copy;
}

function spliceOne(list, index) {
  for (; index + 1 < list.length; index++)
    list[index] = list[index + 1];
  list.pop();
}

function unwrapListeners(arr) {
  var ret = new Array(arr.length);
  for (var i = 0; i < ret.length; ++i) {
    ret[i] = arr[i].listener || arr[i];
  }
  return ret;
}

function once(emitter, name) {
  return new Promise(function (resolve, reject) {
    function errorListener(err) {
      emitter.removeListener(name, resolver);
      reject(err);
    }

    function resolver() {
      if (typeof emitter.removeListener === 'function') {
        emitter.removeListener('error', errorListener);
      }
      resolve([].slice.call(arguments));
    };

    eventTargetAgnosticAddListener(emitter, name, resolver, { once: true });
    if (name !== 'error') {
      addErrorHandlerIfEventEmitter(emitter, errorListener, { once: true });
    }
  });
}

function addErrorHandlerIfEventEmitter(emitter, handler, flags) {
  if (typeof emitter.on === 'function') {
    eventTargetAgnosticAddListener(emitter, 'error', handler, flags);
  }
}

function eventTargetAgnosticAddListener(emitter, name, listener, flags) {
  if (typeof emitter.on === 'function') {
    if (flags.once) {
      emitter.once(name, listener);
    } else {
      emitter.on(name, listener);
    }
  } else if (typeof emitter.addEventListener === 'function') {
    // EventTarget does not have `error` event semantics like Node
    // EventEmitters, we do not listen for `error` events here.
    emitter.addEventListener(name, function wrapListener(arg) {
      // IE does not have builtin `{ once: true }` support so we
      // have to do it manually.
      if (flags.once) {
        emitter.removeEventListener(name, wrapListener);
      }
      listener(arg);
    });
  } else {
    throw new TypeError('The "emitter" argument must be of type EventEmitter. Received type ' + typeof emitter);
  }
}


/***/ }),

/***/ "./node_modules/frida-buffer/index.js":
/*!********************************************!*\
  !*** ./node_modules/frida-buffer/index.js ***!
  \********************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

/*
 * Short-circuit auto-detection in the buffer module to avoid a Duktape
 * compatibility issue with __proto__.
 */
__webpack_require__.g.TYPED_ARRAY_SUPPORT = true;
 
module.exports = __webpack_require__(/*! buffer/ */ "./node_modules/frida-buffer/node_modules/buffer/index.js");


/***/ }),

/***/ "./node_modules/frida-buffer/node_modules/buffer/index.js":
/*!****************************************************************!*\
  !*** ./node_modules/frida-buffer/node_modules/buffer/index.js ***!
  \****************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */



var base64 = __webpack_require__(/*! base64-js */ "./node_modules/base64-js/index.js")
var ieee754 = __webpack_require__(/*! ieee754 */ "./node_modules/ieee754/index.js")
var customInspectSymbol =
  (typeof Symbol === 'function' && typeof Symbol['for'] === 'function') // eslint-disable-line dot-notation
    ? Symbol['for']('nodejs.util.inspect.custom') // eslint-disable-line dot-notation
    : null

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    var proto = { foo: function () { return 42 } }
    Object.setPrototypeOf(proto, Uint8Array.prototype)
    Object.setPrototypeOf(arr, proto)
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  Object.setPrototypeOf(buf, Buffer.prototype)
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayView(value)
  }

  if (value == null) {
    throw new TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof SharedArrayBuffer !== 'undefined' &&
      (isInstance(value, SharedArrayBuffer) ||
      (value && isInstance(value.buffer, SharedArrayBuffer)))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  var valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  var b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(
      value[Symbol.toPrimitive]('string'), encodingOrOffset, length
    )
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Object.setPrototypeOf(Buffer.prototype, Uint8Array.prototype)
Object.setPrototypeOf(Buffer, Uint8Array)

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpreted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayView (arrayView) {
  if (isInstance(arrayView, Uint8Array)) {
    var copy = new Uint8Array(arrayView)
    return fromArrayBuffer(copy.buffer, copy.byteOffset, copy.byteLength)
  }
  return fromArrayLike(arrayView)
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(buf, Buffer.prototype)

  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      if (pos + buf.length > buffer.length) {
        Buffer.from(buf).copy(buffer, pos)
      } else {
        Uint8Array.prototype.set.call(
          buffer,
          buf,
          pos
        )
      }
    } else if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    } else {
      buf.copy(buffer, pos)
    }
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  var len = string.length
  var mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coercion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}
if (customInspectSymbol) {
  Buffer.prototype[customInspectSymbol] = Buffer.prototype.inspect
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [val], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  var strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
      case 'latin1':
      case 'binary':
        return asciiWrite(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF)
      ? 4
      : (firstByte > 0xDF)
          ? 3
          : (firstByte > 0xBF)
              ? 2
              : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += hexSliceLookupTable[buf[i]]
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  // If bytes.length is odd, the last 8 bits must be ignored (same as node.js)
  for (var i = 0; i < bytes.length - 1; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(newBuf, Buffer.prototype)

  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUintLE =
Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUintBE =
Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUint8 =
Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUint16LE =
Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUint16BE =
Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUint32LE =
Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUint32BE =
Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUintLE =
Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUintBE =
Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUint8 =
Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUint16LE =
Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUint16BE =
Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUint32LE =
Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUint32BE =
Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  } else if (typeof val === 'boolean') {
    val = Number(val)
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    var len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

// Create lookup table for `toString('hex')`
// See: https://github.com/feross/buffer/issues/219
var hexSliceLookupTable = (function () {
  var alphabet = '0123456789abcdef'
  var table = new Array(256)
  for (var i = 0; i < 16; ++i) {
    var i16 = i * 16
    for (var j = 0; j < 16; ++j) {
      table[i16 + j] = alphabet[i] + alphabet[j]
    }
  }
  return table
})()


/***/ }),

/***/ "./node_modules/ieee754/index.js":
/*!***************************************!*\
  !*** ./node_modules/ieee754/index.js ***!
  \***************************************/
/***/ ((__unused_webpack_module, exports) => {

/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}


/***/ }),

/***/ "./node_modules/quick-format-unescaped/index.js":
/*!******************************************************!*\
  !*** ./node_modules/quick-format-unescaped/index.js ***!
  \******************************************************/
/***/ ((module) => {

"use strict";

function tryStringify (o) {
  try { return JSON.stringify(o) } catch(e) { return '"[Circular]"' }
}

module.exports = format

function format(f, args, opts) {
  var ss = (opts && opts.stringify) || tryStringify
  var offset = 1
  if (typeof f === 'object' && f !== null) {
    var len = args.length + offset
    if (len === 1) return f
    var objects = new Array(len)
    objects[0] = ss(f)
    for (var index = 1; index < len; index++) {
      objects[index] = ss(args[index])
    }
    return objects.join(' ')
  }
  if (typeof f !== 'string') {
    return f
  }
  var argLen = args.length
  if (argLen === 0) return f
  var str = ''
  var a = 1 - offset
  var lastPos = -1
  var flen = (f && f.length) || 0
  for (var i = 0; i < flen;) {
    if (f.charCodeAt(i) === 37 && i + 1 < flen) {
      lastPos = lastPos > -1 ? lastPos : 0
      switch (f.charCodeAt(i + 1)) {
        case 100: // 'd'
        case 102: // 'f'
          if (a >= argLen)
            break
          if (args[a] == null)  break
          if (lastPos < i)
            str += f.slice(lastPos, i)
          str += Number(args[a])
          lastPos = i + 2
          i++
          break
        case 105: // 'i'
          if (a >= argLen)
            break
          if (args[a] == null)  break
          if (lastPos < i)
            str += f.slice(lastPos, i)
          str += Math.floor(Number(args[a]))
          lastPos = i + 2
          i++
          break
        case 79: // 'O'
        case 111: // 'o'
        case 106: // 'j'
          if (a >= argLen)
            break
          if (args[a] === undefined) break
          if (lastPos < i)
            str += f.slice(lastPos, i)
          var type = typeof args[a]
          if (type === 'string') {
            str += '\'' + args[a] + '\''
            lastPos = i + 2
            i++
            break
          }
          if (type === 'function') {
            str += args[a].name || '<anonymous>'
            lastPos = i + 2
            i++
            break
          }
          str += ss(args[a])
          lastPos = i + 2
          i++
          break
        case 115: // 's'
          if (a >= argLen)
            break
          if (lastPos < i)
            str += f.slice(lastPos, i)
          str += String(args[a])
          lastPos = i + 2
          i++
          break
        case 37: // '%'
          if (lastPos < i)
            str += f.slice(lastPos, i)
          str += '%'
          lastPos = i + 2
          i++
          a--
          break
      }
      ++a
    }
    ++i
  }
  if (lastPos === -1)
    return f
  else if (lastPos < flen) {
    str += f.slice(lastPos)
  }

  return str
}


/***/ }),

/***/ "./agent/index.ts":
/*!************************!*\
  !*** ./agent/index.ts ***!
  \************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
var Anticloak = __importStar(__webpack_require__(/*! @clockwork/anticloak */ "./packages/anticloak/dist/index.js"));
var Cocos2dx = __importStar(__webpack_require__(/*! @clockwork/cocos2dx */ "./packages/cocos2dx/dist/index.js"));
var common_1 = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
var text_1 = __webpack_require__(/*! @clockwork/common/dist/text */ "./packages/common/dist/text.js");
var Dump = __importStar(__webpack_require__(/*! @clockwork/dump */ "./packages/dump/dist/index.js"));
var hooks_1 = __webpack_require__(/*! @clockwork/hooks */ "./packages/hooks/dist/index.js");
var JniTrace = __importStar(__webpack_require__(/*! @clockwork/jnitrace */ "./packages/jnitrace/dist/index.js"));
var logging_1 = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
var Native = __importStar(__webpack_require__(/*! @clockwork/native */ "./packages/native/dist/index.js"));
var Network = __importStar(__webpack_require__(/*! @clockwork/network */ "./packages/network/dist/index.js"));
var Unity = __importStar(__webpack_require__(/*! @clockwork/unity */ "./packages/unity/dist/index.js"));
var _a = logging_1.Color.use(), red = _a.red, green = _a.green, redBright = _a.redBright, pink = _a.magentaBright, gray = _a.gray, dim = _a.dim, black = _a.black;
var uniqHook = (0, hooks_1.getHookUnique)(false);
var uniqFind = (0, common_1.getFindUnique)(false);
function hookActivity() {
    (0, hooks_1.hook)(common_1.Classes.Activity, '$init', {
        after: function () {
            logging_1.logger.info({ tag: 'activity' }, "".concat(gray('$init'), ": ").concat(this.$className));
        },
    });
    (0, hooks_1.hook)(common_1.Classes.Activity, 'onCreate', {
        after: function () {
            logging_1.logger.info({ tag: 'activity' }, "".concat(gray('onCreate'), ": ").concat(this.$className));
        },
        logging: { arguments: false },
    });
    (0, hooks_1.hook)(common_1.Classes.Activity, 'onResume', {
        after: function () {
            logging_1.logger.info({ tag: 'activity' }, "".concat(gray('onResume'), ": ").concat(this.$className));
        },
        logging: { arguments: false },
    });
    (0, hooks_1.hook)(common_1.Classes.Activity, 'startActivity');
    (0, hooks_1.hook)(common_1.Classes.Activity, 'startActivities');
}
function hookWebview(trace) {
    var logging = { short: true };
    (0, hooks_1.hook)(common_1.Classes.WebView, 'evaluateJavascript', {
        logging: __assign(__assign({}, logging), { transform: function (value, type, id) { return (id === 0 ? common_1.Text.maxLengh(value, 300) : value); } }),
    });
    (0, hooks_1.hook)(common_1.Classes.WebView, 'loadDataWithBaseURL', {
        logging: __assign(__assign({}, logging), { transform: function (value, type, id) { return (id === 1 ? common_1.Text.maxLengh(value, 300) : value); } }),
    });
    (0, hooks_1.hook)(common_1.Classes.WebView, 'loadUrl', {
        logging: logging,
        after: function () {
            if (trace) {
                var strace = (0, common_1.stacktrace)();
                if (!strace.includes('com.google.android.gms.ads.internal.webview.') &&
                    !strace.includes('com.google.android.gms.internal.')) {
                    logging_1.logger.info(pink(strace));
                }
            }
        },
    });
}
function hookNetwork() {
    (0, hooks_1.hook)(common_1.Classes.URL, 'openConnection', {
        loggingPredicate: hooks_1.Filter.url,
    });
    var RealCall = null;
    hooks_1.ClassLoader.perform(function () {
        !RealCall &&
            (RealCall = (0, common_1.findClass)('okhttp3.internal.connection.RealCall')) &&
            'callStart' in RealCall &&
            (0, hooks_1.hook)(RealCall, 'callStart', {
                after: function () {
                    var _a, _b, _c;
                    var original = (_a = this.originalRequest) === null || _a === void 0 ? void 0 : _a.value;
                    if (original) {
                        var url = (_b = original._url) === null || _b === void 0 ? void 0 : _b.value;
                        var method = (_c = original._method) === null || _c === void 0 ? void 0 : _c.value;
                        logging_1.logger.info(
                        //@ts-ignore
                        "".concat(dim(method), " ").concat(logging_1.Color.url(
                        //@ts-ignore
                        common_1.Classes.String.valueOf(url))));
                    }
                },
            });
    });
    (0, hooks_1.hook)(common_1.Classes.InetSocketAddress, '$init', {
        logging: { multiline: false, short: true },
    });
    function byteBufferToBase64(buffer, limit) {
        if (limit === void 0) { limit = buffer.remaining(); }
        buffer.mark();
        var rawarr = [];
        for (var i = 0; i < limit; i += 1)
            rawarr.push(0);
        var bytes = Java.array('byte', rawarr);
        buffer.get(bytes);
        var b64 = common_1.Classes.String.$new(common_1.Classes.Base64.getEncoder().encode(bytes));
        buffer.reset();
        return b64;
    }
    (0, hooks_1.hook)(common_1.Classes.DatagramChannelImpl, 'send', {
        before: function (method, buffer) {
            var b64 = byteBufferToBase64(buffer);
            logging_1.logger.info({ tag: 'send' }, "".concat(this.localAddress(), " -> ").concat(this.remoteAddress(), " | ").concat(gray("".concat(b64))));
        },
    });
    (0, hooks_1.hook)(common_1.Classes.DatagramChannelImpl, 'read', {
        logging: { multiline: false },
        after: function (method, returnValue, buffer) {
            buffer.position(0);
            var b64 = byteBufferToBase64(buffer, returnValue);
            logging_1.logger.info({ tag: 'read' }, "".concat(this.remoteAddress(), " -> ").concat(this.localAddress(), " | ").concat(gray("".concat(b64))));
        },
    });
}
function hookRuntimeExec() {
    var mReplace = function (sArg) {
        sArg = sArg.replace(/su$/g, 'nya');
        sArg = sArg.replace(/^rm -r/g, 'file ');
        sArg = sArg.replace(/^getprop/g, 'ls');
        return common_1.Classes.String.$new("".concat(sArg));
    };
     false &&
        0;
    (0, hooks_1.hook)(common_1.Classes.ProcessBuilder, 'start', {
        before: function (method) {
            var args = [];
            for (var _i = 1; _i < arguments.length; _i++) {
                args[_i - 1] = arguments[_i];
            }
            var newlist = [];
            for (var i = 0; i < this._command.value.size(); i += 1) {
                var newvalue = mReplace("".concat(this._command.value.get(i)));
                this._command.value.set(i, newvalue);
                newlist.push(newvalue);
            }
            logging_1.logger.info({ tag: 'exec' }, "".concat(newlist, " ").concat(pink((0, common_1.stacktrace)())));
        },
    });
}
function hookCrypto() {
    (0, hooks_1.hook)(common_1.Classes.SecretKeySpec, '$init', {
        logging: {
            multiline: false,
            short: true,
            transform: function (value, type, id) {
                return (id === 0 || undefined) &&
                    (0, common_1.tryNull)(function () { return [
                        (function () {
                            var sb = '';
                            for (var _i = 0, value_1 = value; _i < value_1.length; _i++) {
                                var b = value_1[_i];
                                sb += (0, text_1.toHex)(b);
                            }
                            return [sb];
                        })(),
                        "".concat(common_1.ClassesString.Object, "[]"),
                    ]; });
            },
        },
    });
    (0, hooks_1.hook)(common_1.Classes.Cipher, 'getInstance', {
        logging: { multiline: false, short: true },
    });
    (0, hooks_1.hook)(common_1.Classes.Cipher, 'doFinal', {
        after: function (method, returnValue) {
            var args = [];
            for (var _i = 2; _i < arguments.length; _i++) {
                args[_i - 2] = arguments[_i];
            }
            if (this.opmode.value === 1) {
                var str = (0, common_1.tryNull)(function () { return common_1.Classes.String.$new(args[0], common_1.Classes.StandardCharsets.UTF_8.value); });
                str !== null && str !== void 0 ? str : (str = (0, common_1.tryNull)(function () { return common_1.Classes.String.$new(args[0]); }));
                str !== null && str !== void 0 ? str : (str = (0, common_1.tryNull)(function () {
                    return common_1.Classes.Arrays.toString
                        .overload('[B')
                        .call(common_1.Classes.Arrays, args[0]);
                }));
                str !== null && str !== void 0 ? str : (str = "".concat(args[0]));
                logging_1.logger.info({ tag: 'encrypt' }, "".concat(str));
            }
            if (this.opmode.value === 2) {
                var transformed = (0, common_1.tryNull)(function () {
                    return common_1.Classes.String.$new(returnValue, common_1.Classes.StandardCharsets.UTF_8.value);
                });
                transformed !== null && transformed !== void 0 ? transformed : (transformed = (0, common_1.tryNull)(function () { return common_1.Classes.String.$new(returnValue); }));
                transformed !== null && transformed !== void 0 ? transformed : (transformed = (0, common_1.tryNull)(function () {
                    return common_1.Classes.Arrays.toString
                        .overload('[B')
                        .call(common_1.Classes.Arrays, returnValue);
                }));
                //@ts-ignore
                transformed !== null && transformed !== void 0 ? transformed : (transformed = "".concat(common_1.Classes.String.valueOf(returnValue)));
            }
        },
        logging: { arguments: false, return: false },
    });
}
function hookJson(fn) {
    var getOpt = ['get', 'opt'];
    var types = ['Boolean', 'Double', 'Int', 'JSONArray', 'JSONObject', 'Long', 'String'];
    (0, hooks_1.hook)(common_1.Classes.JSONObject, '$init', {
        loggingPredicate: hooks_1.Filter.json,
        logging: { short: true },
        predicate: function (_, index) { return index !== 0; },
    });
    (0, hooks_1.hook)(common_1.Classes.JSONObject, 'has', {
        loggingPredicate: hooks_1.Filter.json,
        logging: { multiline: false, short: true },
        replace: function (method, key) {
            var found = (fn === null || fn === void 0 ? void 0 : fn(key, 'has')) !== undefined;
            return found || method.call(this, key);
        },
    });
    var _loop_1 = function (item) {
        (0, hooks_1.hook)(common_1.Classes.JSONObject, item, {
            loggingPredicate: hooks_1.Filter.json,
            logging: { multiline: false, short: true },
            replace: fn ? (0, hooks_1.ifKey)(function (key) { return fn(key, item); }) : undefined,
        });
    };
    for (var _i = 0, getOpt_1 = getOpt; _i < getOpt_1.length; _i++) {
        var item = getOpt_1[_i];
        _loop_1(item);
    }
    for (var _a = 0, types_1 = types; _a < types_1.length; _a++) {
        var type = types_1[_a];
        var _loop_2 = function (item) {
            var name_1 = "".concat(item).concat(type);
            (0, hooks_1.hook)(common_1.Classes.JSONObject, name_1, {
                loggingPredicate: hooks_1.Filter.json,
                logging: { multiline: false, short: true },
                replace: fn ? (0, hooks_1.ifKey)(function (key) { return fn(key, name_1); }) : undefined,
            });
        };
        for (var _b = 0, getOpt_2 = getOpt; _b < getOpt_2.length; _b++) {
            var item = getOpt_2[_b];
            _loop_2(item);
        }
    }
    // hook(Classes.JSONObject, 'put')
}
function hookPrefs(fn) {
    var keyFns = ['getBoolean', 'getFloat', 'getInt', 'getLong', 'getString', 'getStringSet'];
    (0, hooks_1.hook)(common_1.Classes.SharedPreferencesImpl, 'contains', {
        loggingPredicate: hooks_1.Filter.prefs,
        logging: { multiline: false, short: true },
        replace: (0, hooks_1.compat)(function () {
            var found = (fn === null || fn === void 0 ? void 0 : fn.call(this, this.originalArgs[0], 'contains')) !== undefined;
            return found || this.fallback();
        }),
    });
    (0, hooks_1.hook)(common_1.Classes.SharedPreferencesImpl, 'getAll', {
        loggingPredicate: hooks_1.Filter.prefs,
        logging: { multiline: false, short: true },
    });
    var _loop_3 = function (item) {
        (0, hooks_1.hook)(common_1.Classes.SharedPreferencesImpl, item, {
            loggingPredicate: hooks_1.Filter.prefs,
            logging: { multiline: false, short: true },
            replace: (0, hooks_1.compat)(function () {
                var result = fn === null || fn === void 0 ? void 0 : fn.call(this, this.originalArgs[0], item);
                return result !== undefined ? result : this.fallback();
            }),
        });
    };
    for (var _i = 0, keyFns_1 = keyFns; _i < keyFns_1.length; _i++) {
        var item = keyFns_1[_i];
        _loop_3(item);
    }
    // hook('java.util.Properties', 'getProperty');
}
function hookPreferences(fn) {
    var Preferences = null;
    var Preferences$Key = null;
    hooks_1.ClassLoader.perform(function () {
        !Preferences &&
            (Preferences = (0, common_1.findClass)(common_1.ClassesString.Preferences)) &&
            (0, hooks_1.hook)(Preferences, '$init', {
                predicate: function (method) {
                    return method.argumentTypes.length > 0;
                },
                after: function (method, returnValue) {
                    var args = [];
                    for (var _i = 2; _i < arguments.length; _i++) {
                        args[_i - 2] = arguments[_i];
                    }
                    var contains = function (method, key) {
                        var found = (fn === null || fn === void 0 ? void 0 : fn(key, 'contains')) !== undefined;
                        return found || method.call(this, key);
                    };
                    var get = function (method, key) {
                        var keyStr = key.getName();
                        var result = fn === null || fn === void 0 ? void 0 : fn(keyStr, method.name);
                        if (result !== undefined)
                            return result;
                        return method.call(this, key);
                    };
                    'contains' in this &&
                        (0, hooks_1.hook)(this.$className, 'contains', {
                            replace: fn ? contains : undefined,
                            logging: { short: true, multiline: false },
                        });
                    'get' in this &&
                        (0, hooks_1.hook)(this.$className, 'get', {
                            replace: fn ? get : undefined,
                            logging: { short: true, multiline: false },
                        });
                    'asMap' in this &&
                        (0, hooks_1.hook)(this.$className, 'asMap', {
                            logging: { short: true, multiline: false },
                        });
                },
            });
        !Preferences$Key &&
            (Preferences$Key = (0, common_1.findClass)(common_1.ClassesString.Preferences$Key)) &&
            (0, hooks_1.hook)(Preferences$Key, '$init', {
                logging: { multiline: false, short: true },
            });
    });
}
function hookFirestore() {
    var FirebaseFirestore = null;
    var QueryDocumentSnapshot = null;
    var QuerySnapshot = null;
    var DocumentSnapshot = null;
    var test = null;
    var fn = function () {
        if (!test && (test = (0, common_1.findClass)('net.envelopment.carding.meretrix.QefSneakSecta'))) {
            (0, common_1.enumerateMembers)(test, {
                onMatchMethod: function (clazz, member) {
                    (0, hooks_1.hook)(clazz, member);
                },
            });
        }
        if (!FirebaseFirestore &&
            (FirebaseFirestore = (0, common_1.findClass)('com.google.firebase.firestore.FirebaseFirestore'))) {
            (0, hooks_1.hook)(FirebaseFirestore, '$init', {
                predicate: function (overload) { return overload.argumentTypes.length > 0; },
                logging: { short: true },
            });
            'collection' in FirebaseFirestore &&
                (0, hooks_1.hook)(FirebaseFirestore, 'collection', {
                    logging: { short: true, multiline: false },
                });
        }
        if (!QueryDocumentSnapshot &&
            (QueryDocumentSnapshot = (0, common_1.findClass)('com.google.firebase.firestore.QueryDocumentSnapshot'))) {
            'getId' in QueryDocumentSnapshot &&
                (0, hooks_1.hook)(QueryDocumentSnapshot, 'getId', {
                    logging: { short: true, multiline: false },
                });
            'getData' in QueryDocumentSnapshot &&
                (0, hooks_1.hook)(QueryDocumentSnapshot, 'getData', {
                    logging: { short: true, multiline: false },
                });
        }
        if (!QuerySnapshot && (QuerySnapshot = (0, common_1.findClass)('com.google.firebase.firestore.QuerySnapshot'))) {
            (0, hooks_1.hook)(QuerySnapshot, '$init', {
                loggingPredicate: function (method) { return method.argumentTypes.length > 0; },
                logging: { short: true },
            });
        }
        if (!DocumentSnapshot &&
            (DocumentSnapshot = (0, common_1.findClass)('com.google.firebase.firestore.DocumentSnapshot'))) {
            (0, hooks_1.hook)(DocumentSnapshot, '$init', { logging: { short: true } });
            'get' in DocumentSnapshot && (0, hooks_1.hook)(DocumentSnapshot, 'get', { logging: { short: true } });
        }
    };
    hooks_1.ClassLoader.perform(fn);
}
function bypassIntentFlags() {
    if (common_1.Classes.Build$VERSION.SDK_INT.value < 34)
        return;
    (0, hooks_1.hook)(common_1.Classes.PendingIntent, 'getBroadcastAsUser', {
        replace: function (method) {
            var args = [];
            for (var _i = 1; _i < arguments.length; _i++) {
                args[_i - 1] = arguments[_i];
            }
            var flags = args[3];
            var flagImmutableSet = (flags & common_1.Classes.PendingIntent.FLAG_IMMUTABLE.value) !== 0;
            var flagMutableSet = (flags & common_1.Classes.PendingIntent.FLAG_MUTABLE.value) !== 0;
            if (!flagImmutableSet && !flagMutableSet) {
                var newFlags = flags | common_1.Classes.PendingIntent.FLAG_MUTABLE.value;
                args[3] = newFlags;
            }
            return method.call.apply(method, __spreadArray([this], args, false));
        },
        logging: { call: false, return: false },
    });
    (0, hooks_1.hook)(common_1.Classes.PendingIntent, 'checkPendingIntent', {
        replace: function (method) {
            var args = [];
            for (var _i = 1; _i < arguments.length; _i++) {
                args[_i - 1] = arguments[_i];
            }
            return;
        },
        logging: { call: false, return: false },
    });
    (0, hooks_1.hook)('android.os.UserHandle', 'isCore', {
        replace: (0, hooks_1.always)(true),
        logging: { call: false, return: false },
    });
}
function bypassReceiverFlags() {
    if (common_1.Classes.Build$VERSION.SDK_INT.value < 34)
        return;
    (0, hooks_1.hook)(common_1.Classes.ContextImpl, 'registerReceiverInternal', {
        replace: function (method) {
            var args = [];
            for (var _i = 1; _i < arguments.length; _i++) {
                args[_i - 1] = arguments[_i];
            }
            var EXPORTED = common_1.Classes.Context.RECEIVER_EXPORTED.value;
            var NOT_EXPORTED = common_1.Classes.Context.RECEIVER_NOT_EXPORTED.value;
            if ((args[6] & NOT_EXPORTED) === 0) {
                args[6] |= EXPORTED;
            }
            return method.call.apply(method, __spreadArray([this], args, false));
        },
        logging: { call: false, return: false },
    });
    (0, hooks_1.hook)('android.app.AlarmManager', 'setExact', {
        replace: function (method) {
            method.call(this, false);
        },
        logging: { call: false, return: false },
    });
}
function swapIntent(target, dest) {
    (0, hooks_1.hook)(common_1.Classes.Intent, '$init', {
        predicate: function (_, index) { return index === 1; },
        replace: function (method, context, clazz) {
            var _a;
            logging_1.logger.info(clazz.getName());
            if ("".concat(clazz.getName()) === target) {
                clazz = (_a = (0, common_1.findClass)(dest)) === null || _a === void 0 ? void 0 : _a.class;
            }
            return method.call(this, context, clazz);
        },
    });
}
Java.deoptimizeEverything();
Java.performNow(function () {
    // hook(Classes.URL, '$init', {replace(method, ...args) {
    //     if (`${args[0]}` === 'https://muizgLw7vnwg.shop') args[0] = 'https://google.pl/'
    //     return method.call(this, ...args);
    // }})
    // hook('com.android.org.conscrypt.TrustManagerImpl', 'verifyChain', {
    //     replace: (_, ...params) => params[0],
    //     logging: {arguments: false, return: false}
    // });
    // return
    var C4_URL = 'https://google.pl/search?q=hi';
    var AD_ID = 'fwqna41l-mrux-l4pi-mi6q-imrr3t83da4n';
    var INSTALL_REFERRER = 'utm_source=facebook_ads&utm_medium=Non-rganic&media_source=true_network&http_referrer=BingSearch';
    hookActivity();
    hookWebview(true);
    hookNetwork();
    hookJson(function (key, _method) {
        switch (key) {
            case 'install_referrer':
            case 'referrer':
            case 'applink_url':
            case 'af_message':
            case 'af_status':
            case 'tracker_name':
            case 'network':
            case 'campaign':
            case 'google_utm_source':
                return INSTALL_REFERRER;
            case 'gaid':
            case 'android_imei':
            case 'android_meid':
            case 'android_device_id':
                return '4102978102398';
        }
    });
    hookPrefs(function (key, _method) {
        switch (key) {
            case 'oskdoskdue':
                return 0;
            case 'isAudit':
            case 'IS_AUDIT':
                return false;
            case 'invld_id':
            case 'key_umeng_sp_oaid':
            case 'UTDID2':
            case 'adid':
            case 'com.flurry.sdk.advertising_id':
            case 'tenjin_advertising_id':
            case 'uuid':
            case 'AF_CAMPAIGN':
                return 'Non-organic';
            case 'country':
            case 'userCountry':
            case 'key_real_country':
            case 'KEY_LOCALE':
            case 'key_country':
                return 'BR';
            case 'ro.aliyun.clouduuid':
            case 'ro.sys.aliyun.clouduuid':
            case 'loginID':
                return '4102978102398';
        }
    });
    hookPreferences(function () { });
    hookFirestore();
    hookCrypto();
    hookRuntimeExec();
    bypassIntentFlags();
    bypassReceiverFlags();
    // uniqFind('android.opengl.GLSurfaceView', (clazz) =>
    //     enumerateMembers(
    //         clazz,
    //         {
    //             onMatchMethod(clazz, member, depth) {
    //                 hook(clazz, member);
    //             },
    //         },
    //         1,
    //     ),
    // );
    // hook('android.content.ContextWrapper', 'getSharedPreferences', {
    //     logging: { multiline: false, short: true, return: false },
    // });
    (0, hooks_1.hook)(common_1.Classes.Process, 'killProcess', {
        after: function () {
            logging_1.logger.info({ tag: 'killProcess' }, redBright((0, common_1.stacktrace)()));
        },
        logging: { multiline: false, return: false },
    });
    (0, hooks_1.hook)(common_1.Classes.ActivityManager, 'getRunningAppProcesses', {
        logging: { short: true, multiline: false },
    });
    (0, hooks_1.hook)(common_1.Classes.ActivityManager$RunningAppProcessInfo, '$init', {
        logging: { short: true, multiline: false },
    });
    // hook(Classes.Activity, 'finish', { replace: () => {}, logging: { multiline: false, return: false } });
    // hook(Classes.Activity, 'finishAffinity', {
    //     replace: () => {},
    //     logging: { multiline: false, return: false },
    // });
    (0, hooks_1.hook)(common_1.Classes.ApplicationPackageManager, 'getPackageInfo', {
        logging: { multiline: false, short: true },
        replace: function (method) {
            var args = [];
            for (var _i = 1; _i < arguments.length; _i++) {
                args[_i - 1] = arguments[_i];
            }
            if ("".concat(args[0]) === 'com.topjohnwu.magisk') {
                args[0] = 'come.just.test.fake.app';
            }
            return method.call.apply(method, __spreadArray([this], args, false));
        },
        after: function (_method, returnValue) {
            var _a;
            var mPackage = this.mContext.value.getPackageName();
            if (mPackage === ((_a = returnValue === null || returnValue === void 0 ? void 0 : returnValue.packageName) === null || _a === void 0 ? void 0 : _a.value)) {
            }
        },
    });
    Anticloak.Debug.hookVMDebug();
    // Anticloak.Debug.hookDigestEquals();
    Anticloak.Debug.hookVerify();
    Anticloak.generic();
    Anticloak.hookDevice();
    Anticloak.hookSettings();
    Anticloak.hookAdId(AD_ID);
    Anticloak.Country.mock('BR');
    Anticloak.InstallReferrer.replace({ install_referrer: INSTALL_REFERRER });
    (0, hooks_1.hook)(common_1.Classes.SystemProperties, 'get', {
        loggingPredicate: hooks_1.Filter.systemproperties,
        logging: { multiline: false, short: true },
        replace: (0, hooks_1.ifKey)(function (key) {
            var value = Anticloak.BuildProp.propMapper(key);
            return value;
        }),
    });
    (0, hooks_1.hook)(common_1.Classes.System, 'getProperty', {
        loggingPredicate: hooks_1.Filter.systemprop,
        logging: { multiline: false, short: true },
        replace: (0, hooks_1.ifKey)(function (key) {
            var value = Anticloak.BuildProp.systemMapper(key);
            return value;
        }),
    });
    (0, hooks_1.hook)(common_1.Classes.DisplayManager, 'createVirtualDisplay');
    (0, hooks_1.hook)(common_1.Classes.SimpleDateFormat, 'parse', {
        logging: { short: true, multiline: false },
    });
    (0, hooks_1.hook)(common_1.Classes.DexPathList, '$init', {
        logging: { short: true, multiline: false },
    });
    // hook(Classes.Runtime, 'loadLibrary0', { logging: { short: true, multiline: false } });
    hooks_1.ClassLoader.perform(function () {
    });
});
Network.injectSsl();
Network.attachGetAddrInfo();
Network.attachGetHostByName();
Network.attachNativeSocket();
Network.attachInteAton();
// Native.attachRegisterNatives();
Native.attachSystemPropertyGet(function (key) {
    var value = Anticloak.BuildProp.propMapper(key);
    return value;
});
Process.setExceptionHandler(function (exception) {
    var _a, _b;
    var ctx = exception.context;
    logging_1.logger.error({ tag: 'exception' }, "".concat(black(exception.type), ": ").concat((_a = exception.memory) === null || _a === void 0 ? void 0 : _a.operation, " ").concat((_b = exception.memory) === null || _b === void 0 ? void 0 : _b.address, " at: ").concat(gray("".concat(exception.address)), " x0: ").concat(red("".concat(ctx.x0)), " x1: ").concat(red("".concat(ctx.x1))));
    return exception.type === 'abort';
});
Native.initLibart();
Cocos2dx.dump({ name: 'libcocos2djs.so', fn_dump: ptr(0x0080004c), fn_key: ptr(0x006f9170) });
// Cocos2dx.hookLocalStorage((key) => {
//     switch (key) {
//         case '__FirstLanuchTime':
//             return 'false';
//         case 'GMNeedLog':
//             return 'true';
//         case 'isRealUser':
//         case 'force_update':
//             return 'true';
//     }
// });
// Unity.setVersion('2022.1.10f1');
// Unity.patchSsl();
// Unity.attachStrings();
// Unity.attachScenes();
common_1.emitter.on('il2cpp', Unity.listGameObjects);
var enable = true;
setTimeout(function () { return (enable = true); }, 5000);
common_1.emitter.on('jni', function (_) { return (enable = !enable); });
var isNativeEnabled = true;
var predicate = function (r) {
    // if (1 === 1) return false;
    function isWithinOwnRange(ptr) {
        var path = Native.Inject.modules.findPath(ptr);
        return (path === null || path === void 0 ? void 0 : path.includes('/data')) === true && !path.includes('/com.google.android.trichromelibrary');
    }
    if (!isNativeEnabled)
        return false;
    if (!r)
        return false;
    if (isWithinOwnRange(r))
        return true;
    return  false && 0;
};
JniTrace.attach(function (_a) {
    var returnAddress = _a.returnAddress;
    return enable && predicate(returnAddress);
});
Native.Files.hookAccess(predicate);
// Native.Files.hookOpen(predicate);
Native.Files.hookFopen(predicate, true, function (path) {
    // if (path === '/proc/self/maps' || path === `/proc/${Process.id}/maps`) {
    //     return `/data/data/${getSelfProcessName()}/files/fake_maps`;
    // }
    if (path === null || path === void 0 ? void 0 : path.endsWith('/su')) {
        return path.replace(/\/su$/, '/nya');
    }
});
Native.Files.hookOpendir(predicate);
// Native.Files.hookStat(predicate);
Native.Files.hookRemove(predicate);
// Native.Strings.hookStrlen(predicate);
// Native.Strings.hookStrcpy(predicate);
// Native.Strings.hookStrcmp(predicate);
// Native.Strings.hookStrstr(predicate);
// Native.Strings.hookStrtoLong(predicate);
Native.TheEnd.hook(predicate);
Native.System.hookSystem();
Native.System.hookGetauxval();
// Native.Time.hookDifftime(predicate);
// Native.Time.hookTime(predicate);
// Native.Time.hookLocaltime(predicate);
// Native.Time.hookGettimeofday(predicate);
Anticloak.Debug.hookPtrace();
Native.Pthread.hookPthread_create();
// Native.Logcat.hookLogcat();
Anticloak.Jigau.memoryPatch();
Interceptor.attach(Libc.sprintf, {
    onEnter: function (args) {
        this.dst = args[0];
    },
    onLeave: function (retval) {
        var text = this.dst.readCString();
        logging_1.logger.info({ tag: 'sprintf' }, "".concat(text));
    },
});
Interceptor.attach(Libc.posix_spawn, {
    onEnter: function (_a) {
        var pid = _a[0], path = _a[1], action = _a[2];
        var pathStr = path.readCString();
        logging_1.logger.info({ tag: 'posix_spawn' }, "".concat(pathStr, " ").concat(action));
    },
    onLeave: function (retval) {
        logging_1.logger.info({ tag: 'posix_spawn' }, "".concat(retval));
    },
});
common_1.emitter.on('so', function () { return Dump.initSoDump(); });
common_1.emitter.on('dex', function () { return Dump.scheduleDexDump(0); });
var GL_ENUM = {
    7936: 'GL_VENDOR',
    7937: 'GL_RENDERER',
    7938: 'GL_VERSION',
    7939: 'GL_EXTENSIONS',
};
Interceptor.attach(Module.getExportByName(null, 'glGetString'), {
    onEnter: function (args) {
        this.name = args[0];
    },
    onLeave: function (retval) {
        var _a;
        var name = this.name.toInt32();
        var label = (_a = GL_ENUM[name]) !== null && _a !== void 0 ? _a : 'UNKNOWN';
        if (label === 'GL_VENDOR' || label === 'GL_RENDERER') {
            var value = retval.readCString();
            var newvalue = value === null || value === void 0 ? void 0 : value.replace(/x86|sdk|open|source|emulator|google|aosp|apple|ranchu|goldfish|cuttlefish|generic|unknown/gi, 'nya');
            retval.writeUtf8String(newvalue !== null && newvalue !== void 0 ? newvalue : '');
        }
        logging_1.logger.info({ tag: 'opengl' }, "".concat(label, "(").concat(dim("".concat(this.name)), ") -> ").concat(retval.readCString()));
    },
});
// Native.Inject.attachRelativeTo('libil2cpp.so', gPtr(0x160e2dc), {
//     onEnter([__this, value, methodInfo]: [NativePointer, boolean, any]) {
//         const _o = __this.readPointer();
//         const il2class = Struct.Unity.Il2CppClass(_o);
//         logger.info(
//             { tag: 'setactive' },
//             `setActive(${__this}, ${value}) [${methodInfo}] ${JSON.stringify(Struct.toObject(il2class))}`,
//         );
//         logger.info(
//             { tag: 'setactive' },
//             pink(
//                 Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join(', \n'),
//             ),
//             6,
//         );
//         const clazz = Il2Cpp.api.objectGetClass(__this);
//         Il2Cpp.api.classHasReferences(clazz);
//         // const others = [Struct.Unity.Il2CppClass(_o.add(0x50).readPointer())];
//         // for (const key of others) {
//         //     logger.info({ tag: 'setother' }, `${_ToString?.(_o) as any} )`);
//         // }
//     },
// } as any);
// [
//     'fwrite',
//     'faccessat',
//     'vprintf',
//     '__android_log_print',
//     'sprintf',
//     'statvfs',
//     'pthread_kill',
//     'killpg',
//     'tgkill',
//     'signal',
//     'abort',
// ].forEach((ex) => {
//     const exp = Module.getExportByName(null, ex);
//     Interceptor.attach(exp, {
//         onEnter(args) {
//             const arg = ex === '__android_log_print' ? args[2] : args[0];
//             switch (ex) {
//                 case '__android_log_print': {
//                     logger.info({ tag: ex }, `"${args[2].readCString()}"`);
//                     return;
//                 }
//                 case 'sprintf': {
//                     logger.info({ tag: ex }, `"${args[0].readCString()}" "${args[1].readCString()}"`);
//                     return;
//                 }
//                 default: {
//                     logger.info(
//                         { tag: ex },
//                         `"${arg.readCString()}" -> $com.lomol.workout.loseweightm{DebugSymbol.fromAddress(this.returnAddress)}`,
//                     );
//                     return;
//                 }
//             }
//         },
//     });
// });
var fork_ptr = Module.getExportByName('libc.so', 'fork');
var fork = new NativeFunction(fork_ptr, 'int', []);
Interceptor.replace(fork_ptr, new NativeCallback(function () {
    var retval = fork();
    logging_1.logger.info({ tag: 'fork' }, "".concat(retval, " ").concat(DebugSymbol.fromAddress(this.returnAddress)));
    return retval;
    // return -1;
}, 'int', []));
Interceptor.replace(Libc.fgets, new NativeCallback(function (buffer, size, fp) {
    var retval = Libc.fgets(buffer, size, fp);
    // if (predicate(this.returnAddress)) {
    //     const endUserMssg = buffer.readCString(size)?.trimEnd();
    //     logger.info({ tag: 'fgets' }, `${endUserMssg}`);
    // }
    return retval;
}, 'pointer', ['pointer', 'int', 'pointer']));
// // setTimeout(() => {
// const dir = `/data/data/com.scoutant.shorttv/files`;
// Libc.system(Memory.allocUtf8String(`mkdir -p ${dir}`));
// // @ts-ignore
// File.writeAllText(`${dir}/fake_maps`, File.readAllText('/proc/self/maps'));
// })
// '));


/***/ }),

/***/ "./node_modules/pino/browser.js":
/*!**************************************!*\
  !*** ./node_modules/pino/browser.js ***!
  \**************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";


const format = __webpack_require__(/*! quick-format-unescaped */ "./node_modules/quick-format-unescaped/index.js")

module.exports = pino

const _console = pfGlobalThisOrFallback().console || {}
const stdSerializers = {
  mapHttpRequest: mock,
  mapHttpResponse: mock,
  wrapRequestSerializer: passthrough,
  wrapResponseSerializer: passthrough,
  wrapErrorSerializer: passthrough,
  req: mock,
  res: mock,
  err: asErrValue,
  errWithCause: asErrValue
}
function levelToValue (level, logger) {
  return level === 'silent'
    ? Infinity
    : logger.levels.values[level]
}
const baseLogFunctionSymbol = Symbol('pino.logFuncs')
const hierarchySymbol = Symbol('pino.hierarchy')

const logFallbackMap = {
  error: 'log',
  fatal: 'error',
  warn: 'error',
  info: 'log',
  debug: 'log',
  trace: 'log'
}

function appendChildLogger (parentLogger, childLogger) {
  const newEntry = {
    logger: childLogger,
    parent: parentLogger[hierarchySymbol]
  }
  childLogger[hierarchySymbol] = newEntry
}

function setupBaseLogFunctions (logger, levels, proto) {
  const logFunctions = {}
  levels.forEach(level => {
    logFunctions[level] = proto[level] ? proto[level] : (_console[level] || _console[logFallbackMap[level] || 'log'] || noop)
  })
  logger[baseLogFunctionSymbol] = logFunctions
}

function shouldSerialize (serialize, serializers) {
  if (Array.isArray(serialize)) {
    const hasToFilter = serialize.filter(function (k) {
      return k !== '!stdSerializers.err'
    })
    return hasToFilter
  } else if (serialize === true) {
    return Object.keys(serializers)
  }

  return false
}

function pino (opts) {
  opts = opts || {}
  opts.browser = opts.browser || {}

  const transmit = opts.browser.transmit
  if (transmit && typeof transmit.send !== 'function') { throw Error('pino: transmit option must have a send function') }

  const proto = opts.browser.write || _console
  if (opts.browser.write) opts.browser.asObject = true
  const serializers = opts.serializers || {}
  const serialize = shouldSerialize(opts.browser.serialize, serializers)
  let stdErrSerialize = opts.browser.serialize

  if (
    Array.isArray(opts.browser.serialize) &&
    opts.browser.serialize.indexOf('!stdSerializers.err') > -1
  ) stdErrSerialize = false

  const customLevels = Object.keys(opts.customLevels || {})
  const levels = ['error', 'fatal', 'warn', 'info', 'debug', 'trace'].concat(customLevels)

  if (typeof proto === 'function') {
    levels.forEach(function (level) {
      proto[level] = proto
    })
  }
  if (opts.enabled === false || opts.browser.disabled) opts.level = 'silent'
  const level = opts.level || 'info'
  const logger = Object.create(proto)
  if (!logger.log) logger.log = noop

  setupBaseLogFunctions(logger, levels, proto)
  // setup root hierarchy entry
  appendChildLogger({}, logger)

  Object.defineProperty(logger, 'levelVal', {
    get: getLevelVal
  })
  Object.defineProperty(logger, 'level', {
    get: getLevel,
    set: setLevel
  })

  const setOpts = {
    transmit,
    serialize,
    asObject: opts.browser.asObject,
    formatters: opts.browser.formatters,
    levels,
    timestamp: getTimeFunction(opts)
  }
  logger.levels = getLevels(opts)
  logger.level = level

  logger.setMaxListeners = logger.getMaxListeners =
  logger.emit = logger.addListener = logger.on =
  logger.prependListener = logger.once =
  logger.prependOnceListener = logger.removeListener =
  logger.removeAllListeners = logger.listeners =
  logger.listenerCount = logger.eventNames =
  logger.write = logger.flush = noop
  logger.serializers = serializers
  logger._serialize = serialize
  logger._stdErrSerialize = stdErrSerialize
  logger.child = child

  if (transmit) logger._logEvent = createLogEventShape()

  function getLevelVal () {
    return levelToValue(this.level, this)
  }

  function getLevel () {
    return this._level
  }
  function setLevel (level) {
    if (level !== 'silent' && !this.levels.values[level]) {
      throw Error('unknown level ' + level)
    }
    this._level = level

    set(this, setOpts, logger, 'error') // <-- must stay first
    set(this, setOpts, logger, 'fatal')
    set(this, setOpts, logger, 'warn')
    set(this, setOpts, logger, 'info')
    set(this, setOpts, logger, 'debug')
    set(this, setOpts, logger, 'trace')

    customLevels.forEach((level) => {
      set(this, setOpts, logger, level)
    })
  }

  function child (bindings, childOptions) {
    if (!bindings) {
      throw new Error('missing bindings for child Pino')
    }
    childOptions = childOptions || {}
    if (serialize && bindings.serializers) {
      childOptions.serializers = bindings.serializers
    }
    const childOptionsSerializers = childOptions.serializers
    if (serialize && childOptionsSerializers) {
      var childSerializers = Object.assign({}, serializers, childOptionsSerializers)
      var childSerialize = opts.browser.serialize === true
        ? Object.keys(childSerializers)
        : serialize
      delete bindings.serializers
      applySerializers([bindings], childSerialize, childSerializers, this._stdErrSerialize)
    }
    function Child (parent) {
      this._childLevel = (parent._childLevel | 0) + 1

      // make sure bindings are available in the `set` function
      this.bindings = bindings

      if (childSerializers) {
        this.serializers = childSerializers
        this._serialize = childSerialize
      }
      if (transmit) {
        this._logEvent = createLogEventShape(
          [].concat(parent._logEvent.bindings, bindings)
        )
      }
    }
    Child.prototype = this
    const newLogger = new Child(this)

    // must happen before the level is assigned
    appendChildLogger(this, newLogger)
    // required to actually initialize the logger functions for any given child
    newLogger.level = this.level

    return newLogger
  }
  return logger
}

function getLevels (opts) {
  const customLevels = opts.customLevels || {}

  const values = Object.assign({}, pino.levels.values, customLevels)
  const labels = Object.assign({}, pino.levels.labels, invertObject(customLevels))

  return {
    values,
    labels
  }
}

function invertObject (obj) {
  const inverted = {}
  Object.keys(obj).forEach(function (key) {
    inverted[obj[key]] = key
  })
  return inverted
}

pino.levels = {
  values: {
    fatal: 60,
    error: 50,
    warn: 40,
    info: 30,
    debug: 20,
    trace: 10
  },
  labels: {
    10: 'trace',
    20: 'debug',
    30: 'info',
    40: 'warn',
    50: 'error',
    60: 'fatal'
  }
}

pino.stdSerializers = stdSerializers
pino.stdTimeFunctions = Object.assign({}, { nullTime, epochTime, unixTime, isoTime })

function getBindingChain (logger) {
  const bindings = []
  if (logger.bindings) {
    bindings.push(logger.bindings)
  }

  // traverse up the tree to get all bindings
  let hierarchy = logger[hierarchySymbol]
  while (hierarchy.parent) {
    hierarchy = hierarchy.parent
    if (hierarchy.logger.bindings) {
      bindings.push(hierarchy.logger.bindings)
    }
  }

  return bindings.reverse()
}

function set (self, opts, rootLogger, level) {
  // override the current log functions with either `noop` or the base log function
  Object.defineProperty(self, level, {
    value: (levelToValue(self.level, rootLogger) > levelToValue(level, rootLogger)
      ? noop
      : rootLogger[baseLogFunctionSymbol][level]),
    writable: true,
    enumerable: true,
    configurable: true
  })

  if (!opts.transmit && self[level] === noop) {
    return
  }

  // make sure the log format is correct
  self[level] = createWrap(self, opts, rootLogger, level)

  // prepend bindings if it is not the root logger
  const bindings = getBindingChain(self)
  if (bindings.length === 0) {
    // early exit in case for rootLogger
    return
  }
  self[level] = prependBindingsInArguments(bindings, self[level])
}

function prependBindingsInArguments (bindings, logFunc) {
  return function () {
    return logFunc.apply(this, [...bindings, ...arguments])
  }
}

function createWrap (self, opts, rootLogger, level) {
  return (function (write) {
    return function LOG () {
      const ts = opts.timestamp()
      const args = new Array(arguments.length)
      const proto = (Object.getPrototypeOf && Object.getPrototypeOf(this) === _console) ? _console : this
      for (var i = 0; i < args.length; i++) args[i] = arguments[i]

      if (opts.serialize && !opts.asObject) {
        applySerializers(args, this._serialize, this.serializers, this._stdErrSerialize)
      }
      if (opts.asObject || opts.formatters) {
        write.call(proto, asObject(this, level, args, ts, opts.formatters))
      } else write.apply(proto, args)

      if (opts.transmit) {
        const transmitLevel = opts.transmit.level || self._level
        const transmitValue = rootLogger.levels.values[transmitLevel]
        const methodValue = rootLogger.levels.values[level]
        if (methodValue < transmitValue) return
        transmit(this, {
          ts,
          methodLevel: level,
          methodValue,
          transmitLevel,
          transmitValue: rootLogger.levels.values[opts.transmit.level || self._level],
          send: opts.transmit.send,
          val: levelToValue(self._level, rootLogger)
        }, args)
      }
    }
  })(self[baseLogFunctionSymbol][level])
}

function asObject (logger, level, args, ts, formatters = {}) {
  const {
    level: levelFormatter = () => logger.levels.values[level],
    log: logObjectFormatter = (obj) => obj
  } = formatters
  if (logger._serialize) applySerializers(args, logger._serialize, logger.serializers, logger._stdErrSerialize)
  const argsCloned = args.slice()
  let msg = argsCloned[0]
  const logObject = {}
  if (ts) {
    logObject.time = ts
  }
  logObject.level = levelFormatter(level, logger.levels.values[level])

  let lvl = (logger._childLevel | 0) + 1
  if (lvl < 1) lvl = 1
  // deliberate, catching objects, arrays
  if (msg !== null && typeof msg === 'object') {
    while (lvl-- && typeof argsCloned[0] === 'object') {
      Object.assign(logObject, argsCloned.shift())
    }
    msg = argsCloned.length ? format(argsCloned.shift(), argsCloned) : undefined
  } else if (typeof msg === 'string') msg = format(argsCloned.shift(), argsCloned)
  if (msg !== undefined) logObject.msg = msg

  const formattedLogObject = logObjectFormatter(logObject)
  return formattedLogObject
}

function applySerializers (args, serialize, serializers, stdErrSerialize) {
  for (const i in args) {
    if (stdErrSerialize && args[i] instanceof Error) {
      args[i] = pino.stdSerializers.err(args[i])
    } else if (typeof args[i] === 'object' && !Array.isArray(args[i])) {
      for (const k in args[i]) {
        if (serialize && serialize.indexOf(k) > -1 && k in serializers) {
          args[i][k] = serializers[k](args[i][k])
        }
      }
    }
  }
}

function transmit (logger, opts, args) {
  const send = opts.send
  const ts = opts.ts
  const methodLevel = opts.methodLevel
  const methodValue = opts.methodValue
  const val = opts.val
  const bindings = logger._logEvent.bindings

  applySerializers(
    args,
    logger._serialize || Object.keys(logger.serializers),
    logger.serializers,
    logger._stdErrSerialize === undefined ? true : logger._stdErrSerialize
  )
  logger._logEvent.ts = ts
  logger._logEvent.messages = args.filter(function (arg) {
    // bindings can only be objects, so reference equality check via indexOf is fine
    return bindings.indexOf(arg) === -1
  })

  logger._logEvent.level.label = methodLevel
  logger._logEvent.level.value = methodValue

  send(methodLevel, logger._logEvent, val)

  logger._logEvent = createLogEventShape(bindings)
}

function createLogEventShape (bindings) {
  return {
    ts: 0,
    messages: [],
    bindings: bindings || [],
    level: { label: '', value: 0 }
  }
}

function asErrValue (err) {
  const obj = {
    type: err.constructor.name,
    msg: err.message,
    stack: err.stack
  }
  for (const key in err) {
    if (obj[key] === undefined) {
      obj[key] = err[key]
    }
  }
  return obj
}

function getTimeFunction (opts) {
  if (typeof opts.timestamp === 'function') {
    return opts.timestamp
  }
  if (opts.timestamp === false) {
    return nullTime
  }
  return epochTime
}

function mock () { return {} }
function passthrough (a) { return a }
function noop () {}

function nullTime () { return false }
function epochTime () { return Date.now() }
function unixTime () { return Math.round(Date.now() / 1000.0) }
function isoTime () { return new Date(Date.now()).toISOString() } // using Date.now() for testability

/* eslint-disable */
/* istanbul ignore next */
function pfGlobalThisOrFallback () {
  function defd (o) { return typeof o !== 'undefined' && o }
  try {
    if (typeof globalThis !== 'undefined') return globalThis
    Object.defineProperty(Object.prototype, 'globalThis', {
      get: function () {
        delete Object.prototype.globalThis
        return (this.globalThis = this)
      },
      configurable: true
    })
    return globalThis
  } catch (e) {
    return defd(self) || defd(window) || defd(this) || {}
  }
}
/* eslint-enable */

module.exports["default"] = pino
module.exports.pino = pino


/***/ }),

/***/ "./node_modules/@frida/crypto/dist/index.js":
/*!**************************************************!*\
  !*** ./node_modules/@frida/crypto/dist/index.js ***!
  \**************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Hash: () => (/* binding */ Hash),
/* harmony export */   createHash: () => (/* binding */ createHash),
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var buffer__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! buffer */ "./node_modules/buffer/index.js");

/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = ({
    createHash,
});
function createHash(type) {
    return new Hash(new Checksum(type));
}
class Hash {
    constructor(checksum) {
        this.checksum = checksum;
    }
    update(data, inputEncoding) {
        // TODO: TypedArray
        if (data instanceof DataView)
            throw new Error("DataView not yet supported");
        if (inputEncoding !== undefined)
            throw new Error("inputEncoding not yet supported");
        if (data instanceof buffer__WEBPACK_IMPORTED_MODULE_0__.Buffer)
            this.checksum.update(data.buffer);
        else
            this.checksum.update(data);
        return this;
    }
    digest(encoding = "binary") {
        if (encoding === "hex")
            return this.checksum.getString();
        const rawDigest = buffer__WEBPACK_IMPORTED_MODULE_0__.Buffer.from(this.checksum.getDigest());
        if (encoding === "binary")
            return rawDigest;
        return rawDigest.toString(encoding);
    }
    copy() {
        throw new Error("copy() not yet supported");
    }
}


/***/ }),

/***/ "./node_modules/@frida/tty/index.js":
/*!******************************************!*\
  !*** ./node_modules/@frida/tty/index.js ***!
  \******************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ReadStream: () => (/* binding */ ReadStream),
/* harmony export */   WriteStream: () => (/* binding */ WriteStream),
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__),
/* harmony export */   isatty: () => (/* binding */ isatty)
/* harmony export */ });
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = ({
  isatty,
  ReadStream,
  WriteStream,
});

function isatty() {
  return false;
}

function ReadStream() {
  throw new Error('tty.ReadStream is not implemented');
}

function WriteStream() {
  throw new Error('tty.WriteStream is not implemented');
}


/***/ }),

/***/ "./node_modules/colorette/index.js":
/*!*****************************************!*\
  !*** ./node_modules/colorette/index.js ***!
  \*****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   bgBlack: () => (/* binding */ bgBlack),
/* harmony export */   bgBlackBright: () => (/* binding */ bgBlackBright),
/* harmony export */   bgBlue: () => (/* binding */ bgBlue),
/* harmony export */   bgBlueBright: () => (/* binding */ bgBlueBright),
/* harmony export */   bgCyan: () => (/* binding */ bgCyan),
/* harmony export */   bgCyanBright: () => (/* binding */ bgCyanBright),
/* harmony export */   bgGreen: () => (/* binding */ bgGreen),
/* harmony export */   bgGreenBright: () => (/* binding */ bgGreenBright),
/* harmony export */   bgMagenta: () => (/* binding */ bgMagenta),
/* harmony export */   bgMagentaBright: () => (/* binding */ bgMagentaBright),
/* harmony export */   bgRed: () => (/* binding */ bgRed),
/* harmony export */   bgRedBright: () => (/* binding */ bgRedBright),
/* harmony export */   bgWhite: () => (/* binding */ bgWhite),
/* harmony export */   bgWhiteBright: () => (/* binding */ bgWhiteBright),
/* harmony export */   bgYellow: () => (/* binding */ bgYellow),
/* harmony export */   bgYellowBright: () => (/* binding */ bgYellowBright),
/* harmony export */   black: () => (/* binding */ black),
/* harmony export */   blackBright: () => (/* binding */ blackBright),
/* harmony export */   blue: () => (/* binding */ blue),
/* harmony export */   blueBright: () => (/* binding */ blueBright),
/* harmony export */   bold: () => (/* binding */ bold),
/* harmony export */   createColors: () => (/* binding */ createColors),
/* harmony export */   cyan: () => (/* binding */ cyan),
/* harmony export */   cyanBright: () => (/* binding */ cyanBright),
/* harmony export */   dim: () => (/* binding */ dim),
/* harmony export */   gray: () => (/* binding */ gray),
/* harmony export */   green: () => (/* binding */ green),
/* harmony export */   greenBright: () => (/* binding */ greenBright),
/* harmony export */   hidden: () => (/* binding */ hidden),
/* harmony export */   inverse: () => (/* binding */ inverse),
/* harmony export */   isColorSupported: () => (/* binding */ isColorSupported),
/* harmony export */   italic: () => (/* binding */ italic),
/* harmony export */   magenta: () => (/* binding */ magenta),
/* harmony export */   magentaBright: () => (/* binding */ magentaBright),
/* harmony export */   red: () => (/* binding */ red),
/* harmony export */   redBright: () => (/* binding */ redBright),
/* harmony export */   reset: () => (/* binding */ reset),
/* harmony export */   strikethrough: () => (/* binding */ strikethrough),
/* harmony export */   underline: () => (/* binding */ underline),
/* harmony export */   white: () => (/* binding */ white),
/* harmony export */   whiteBright: () => (/* binding */ whiteBright),
/* harmony export */   yellow: () => (/* binding */ yellow),
/* harmony export */   yellowBright: () => (/* binding */ yellowBright)
/* harmony export */ });
/* harmony import */ var tty__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! tty */ "./node_modules/@frida/tty/index.js");


const {
  env = {},
  argv = [],
  platform = "",
} = typeof process === "undefined" ? {} : process

const isDisabled = "NO_COLOR" in env || argv.includes("--no-color")
const isForced = "FORCE_COLOR" in env || argv.includes("--color")
const isWindows = platform === "win32"
const isDumbTerminal = env.TERM === "dumb"

const isCompatibleTerminal =
  tty__WEBPACK_IMPORTED_MODULE_0__ && tty__WEBPACK_IMPORTED_MODULE_0__.isatty && tty__WEBPACK_IMPORTED_MODULE_0__.isatty(1) && env.TERM && !isDumbTerminal

const isCI =
  "CI" in env &&
  ("GITHUB_ACTIONS" in env || "GITLAB_CI" in env || "CIRCLECI" in env)

const isColorSupported =
  !isDisabled &&
  (isForced || (isWindows && !isDumbTerminal) || isCompatibleTerminal || isCI)

const replaceClose = (
  index,
  string,
  close,
  replace,
  head = string.substring(0, index) + replace,
  tail = string.substring(index + close.length),
  next = tail.indexOf(close)
) => head + (next < 0 ? tail : replaceClose(next, tail, close, replace))

const clearBleed = (index, string, open, close, replace) =>
  index < 0
    ? open + string + close
    : open + replaceClose(index, string, close, replace) + close

const filterEmpty =
  (open, close, replace = open, at = open.length + 1) =>
  (string) =>
    string || !(string === "" || string === undefined)
      ? clearBleed(
          ("" + string).indexOf(close, at),
          string,
          open,
          close,
          replace
        )
      : ""

const init = (open, close, replace) =>
  filterEmpty(`\x1b[${open}m`, `\x1b[${close}m`, replace)

const colors = {
  reset: init(0, 0),
  bold: init(1, 22, "\x1b[22m\x1b[1m"),
  dim: init(2, 22, "\x1b[22m\x1b[2m"),
  italic: init(3, 23),
  underline: init(4, 24),
  inverse: init(7, 27),
  hidden: init(8, 28),
  strikethrough: init(9, 29),
  black: init(30, 39),
  red: init(31, 39),
  green: init(32, 39),
  yellow: init(33, 39),
  blue: init(34, 39),
  magenta: init(35, 39),
  cyan: init(36, 39),
  white: init(37, 39),
  gray: init(90, 39),
  bgBlack: init(40, 49),
  bgRed: init(41, 49),
  bgGreen: init(42, 49),
  bgYellow: init(43, 49),
  bgBlue: init(44, 49),
  bgMagenta: init(45, 49),
  bgCyan: init(46, 49),
  bgWhite: init(47, 49),
  blackBright: init(90, 39),
  redBright: init(91, 39),
  greenBright: init(92, 39),
  yellowBright: init(93, 39),
  blueBright: init(94, 39),
  magentaBright: init(95, 39),
  cyanBright: init(96, 39),
  whiteBright: init(97, 39),
  bgBlackBright: init(100, 49),
  bgRedBright: init(101, 49),
  bgGreenBright: init(102, 49),
  bgYellowBright: init(103, 49),
  bgBlueBright: init(104, 49),
  bgMagentaBright: init(105, 49),
  bgCyanBright: init(106, 49),
  bgWhiteBright: init(107, 49),
}

const createColors = ({ useColor = isColorSupported } = {}) =>
  useColor
    ? colors
    : Object.keys(colors).reduce(
        (colors, key) => ({ ...colors, [key]: String }),
        {}
      )

const {
  reset,
  bold,
  dim,
  italic,
  underline,
  inverse,
  hidden,
  strikethrough,
  black,
  red,
  green,
  yellow,
  blue,
  magenta,
  cyan,
  white,
  gray,
  bgBlack,
  bgRed,
  bgGreen,
  bgYellow,
  bgBlue,
  bgMagenta,
  bgCyan,
  bgWhite,
  blackBright,
  redBright,
  greenBright,
  yellowBright,
  blueBright,
  magentaBright,
  cyanBright,
  whiteBright,
  bgBlackBright,
  bgRedBright,
  bgGreenBright,
  bgYellowBright,
  bgBlueBright,
  bgMagentaBright,
  bgCyanBright,
  bgWhiteBright,
} = createColors()


/***/ }),

/***/ "./node_modules/frida-il2cpp-bridge/dist/index.js":
/*!********************************************************!*\
  !*** ./node_modules/frida-il2cpp-bridge/dist/index.js ***!
  \********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);

var __decorate = (undefined && undefined.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * The **core** object where all the necessary IL2CPP native functions are
     * held. \
     * `frida-il2cpp-bridge` is built around this object by providing an
     * easy-to-use abstraction layer: the user isn't expected to use it directly,
     * but it can in case of advanced use cases.
     *
     * The APIs depends on the Unity version, hence some of them may be
     * unavailable; moreover, they are searched by **name** (e.g.
     * `il2cpp_class_from_name`) hence they might get stripped, hidden or
     * renamed by a nasty obfuscator.
     *
     * However, it is possible to override or set the handle of any of the
     * exports by using a global variable:
     * ```ts
     * declare global {
     *     let IL2CPP_EXPORTS: Record<string, () => NativePointer>;
     * }
     *
     * IL2CPP_EXPORTS = {
     *     il2cpp_image_get_class: () => Il2Cpp.module.base.add(0x1204c),
     *     il2cpp_class_get_parent: () => {
     *         return Memory.scanSync(Il2Cpp.module.base, Il2Cpp.module.size, "2f 10 ee 10 34 a8")[0].address;
     *     },
     * };
     *
     * Il2Cpp.perform(() => {
     *     // ...
     * });
     * ```
     */
    Il2Cpp.api = {
        get alloc() {
            return r("il2cpp_alloc", "pointer", ["size_t"]);
        },
        get arrayGetLength() {
            return r("il2cpp_array_length", "uint32", ["pointer"]);
        },
        get arrayNew() {
            return r("il2cpp_array_new", "pointer", ["pointer", "uint32"]);
        },
        get assemblyGetImage() {
            return r("il2cpp_assembly_get_image", "pointer", ["pointer"]);
        },
        get classForEach() {
            return r("il2cpp_class_for_each", "void", ["pointer", "pointer"]);
        },
        get classFromName() {
            return r("il2cpp_class_from_name", "pointer", ["pointer", "pointer", "pointer"]);
        },
        get classFromObject() {
            return r("il2cpp_class_from_system_type", "pointer", ["pointer"]);
        },
        get classGetArrayClass() {
            return r("il2cpp_array_class_get", "pointer", ["pointer", "uint32"]);
        },
        get classGetArrayElementSize() {
            return r("il2cpp_class_array_element_size", "int", ["pointer"]);
        },
        get classGetAssemblyName() {
            return r("il2cpp_class_get_assemblyname", "pointer", ["pointer"]);
        },
        get classGetBaseType() {
            return r("il2cpp_class_enum_basetype", "pointer", ["pointer"]);
        },
        get classGetDeclaringType() {
            return r("il2cpp_class_get_declaring_type", "pointer", ["pointer"]);
        },
        get classGetElementClass() {
            return r("il2cpp_class_get_element_class", "pointer", ["pointer"]);
        },
        get classGetFieldFromName() {
            return r("il2cpp_class_get_field_from_name", "pointer", ["pointer", "pointer"]);
        },
        get classGetFields() {
            return r("il2cpp_class_get_fields", "pointer", ["pointer", "pointer"]);
        },
        get classGetFlags() {
            return r("il2cpp_class_get_flags", "int", ["pointer"]);
        },
        get classGetImage() {
            return r("il2cpp_class_get_image", "pointer", ["pointer"]);
        },
        get classGetInstanceSize() {
            return r("il2cpp_class_instance_size", "int32", ["pointer"]);
        },
        get classGetInterfaces() {
            return r("il2cpp_class_get_interfaces", "pointer", ["pointer", "pointer"]);
        },
        get classGetMethodFromName() {
            return r("il2cpp_class_get_method_from_name", "pointer", ["pointer", "pointer", "int"]);
        },
        get classGetMethods() {
            return r("il2cpp_class_get_methods", "pointer", ["pointer", "pointer"]);
        },
        get classGetName() {
            return r("il2cpp_class_get_name", "pointer", ["pointer"]);
        },
        get classGetNamespace() {
            return r("il2cpp_class_get_namespace", "pointer", ["pointer"]);
        },
        get classGetNestedClasses() {
            return r("il2cpp_class_get_nested_types", "pointer", ["pointer", "pointer"]);
        },
        get classGetParent() {
            return r("il2cpp_class_get_parent", "pointer", ["pointer"]);
        },
        get classGetStaticFieldData() {
            return r("il2cpp_class_get_static_field_data", "pointer", ["pointer"]);
        },
        get classGetValueTypeSize() {
            return r("il2cpp_class_value_size", "int32", ["pointer", "pointer"]);
        },
        get classGetType() {
            return r("il2cpp_class_get_type", "pointer", ["pointer"]);
        },
        get classHasReferences() {
            return r("il2cpp_class_has_references", "bool", ["pointer"]);
        },
        get classInitialize() {
            return r("il2cpp_runtime_class_init", "void", ["pointer"]);
        },
        get classIsAbstract() {
            return r("il2cpp_class_is_abstract", "bool", ["pointer"]);
        },
        get classIsAssignableFrom() {
            return r("il2cpp_class_is_assignable_from", "bool", ["pointer", "pointer"]);
        },
        get classIsBlittable() {
            return r("il2cpp_class_is_blittable", "bool", ["pointer"]);
        },
        get classIsEnum() {
            return r("il2cpp_class_is_enum", "bool", ["pointer"]);
        },
        get classIsGeneric() {
            return r("il2cpp_class_is_generic", "bool", ["pointer"]);
        },
        get classIsInflated() {
            return r("il2cpp_class_is_inflated", "bool", ["pointer"]);
        },
        get classIsInterface() {
            return r("il2cpp_class_is_interface", "bool", ["pointer"]);
        },
        get classIsSubclassOf() {
            return r("il2cpp_class_is_subclass_of", "bool", ["pointer", "pointer", "bool"]);
        },
        get classIsValueType() {
            return r("il2cpp_class_is_valuetype", "bool", ["pointer"]);
        },
        get domainGetAssemblyFromName() {
            return r("il2cpp_domain_assembly_open", "pointer", ["pointer", "pointer"]);
        },
        get domainGet() {
            return r("il2cpp_domain_get", "pointer", []);
        },
        get domainGetAssemblies() {
            return r("il2cpp_domain_get_assemblies", "pointer", ["pointer", "pointer"]);
        },
        get fieldGetClass() {
            return r("il2cpp_field_get_parent", "pointer", ["pointer"]);
        },
        get fieldGetFlags() {
            return r("il2cpp_field_get_flags", "int", ["pointer"]);
        },
        get fieldGetName() {
            return r("il2cpp_field_get_name", "pointer", ["pointer"]);
        },
        get fieldGetOffset() {
            return r("il2cpp_field_get_offset", "int32", ["pointer"]);
        },
        get fieldGetStaticValue() {
            return r("il2cpp_field_static_get_value", "void", ["pointer", "pointer"]);
        },
        get fieldGetType() {
            return r("il2cpp_field_get_type", "pointer", ["pointer"]);
        },
        get fieldSetStaticValue() {
            return r("il2cpp_field_static_set_value", "void", ["pointer", "pointer"]);
        },
        get free() {
            return r("il2cpp_free", "void", ["pointer"]);
        },
        get gcCollect() {
            return r("il2cpp_gc_collect", "void", ["int"]);
        },
        get gcCollectALittle() {
            return r("il2cpp_gc_collect_a_little", "void", []);
        },
        get gcDisable() {
            return r("il2cpp_gc_disable", "void", []);
        },
        get gcEnable() {
            return r("il2cpp_gc_enable", "void", []);
        },
        get gcGetHeapSize() {
            return r("il2cpp_gc_get_heap_size", "int64", []);
        },
        get gcGetMaxTimeSlice() {
            return r("il2cpp_gc_get_max_time_slice_ns", "int64", []);
        },
        get gcGetUsedSize() {
            return r("il2cpp_gc_get_used_size", "int64", []);
        },
        get gcHandleGetTarget() {
            return r("il2cpp_gchandle_get_target", "pointer", ["uint32"]);
        },
        get gcHandleFree() {
            return r("il2cpp_gchandle_free", "void", ["uint32"]);
        },
        get gcHandleNew() {
            return r("il2cpp_gchandle_new", "uint32", ["pointer", "bool"]);
        },
        get gcHandleNewWeakRef() {
            return r("il2cpp_gchandle_new_weakref", "uint32", ["pointer", "bool"]);
        },
        get gcIsDisabled() {
            return r("il2cpp_gc_is_disabled", "bool", []);
        },
        get gcIsIncremental() {
            return r("il2cpp_gc_is_incremental", "bool", []);
        },
        get gcSetMaxTimeSlice() {
            return r("il2cpp_gc_set_max_time_slice_ns", "void", ["int64"]);
        },
        get gcStartIncrementalCollection() {
            return r("il2cpp_gc_start_incremental_collection", "void", []);
        },
        get gcStartWorld() {
            return r("il2cpp_start_gc_world", "void", []);
        },
        get gcStopWorld() {
            return r("il2cpp_stop_gc_world", "void", []);
        },
        get getCorlib() {
            return r("il2cpp_get_corlib", "pointer", []);
        },
        get imageGetAssembly() {
            return r("il2cpp_image_get_assembly", "pointer", ["pointer"]);
        },
        get imageGetClass() {
            return r("il2cpp_image_get_class", "pointer", ["pointer", "uint"]);
        },
        get imageGetClassCount() {
            return r("il2cpp_image_get_class_count", "uint32", ["pointer"]);
        },
        get imageGetName() {
            return r("il2cpp_image_get_name", "pointer", ["pointer"]);
        },
        get initialize() {
            return r("il2cpp_init", "void", ["pointer"]);
        },
        get livenessAllocateStruct() {
            return r("il2cpp_unity_liveness_allocate_struct", "pointer", ["pointer", "int", "pointer", "pointer", "pointer"]);
        },
        get livenessCalculationBegin() {
            return r("il2cpp_unity_liveness_calculation_begin", "pointer", ["pointer", "int", "pointer", "pointer", "pointer", "pointer"]);
        },
        get livenessCalculationEnd() {
            return r("il2cpp_unity_liveness_calculation_end", "void", ["pointer"]);
        },
        get livenessCalculationFromStatics() {
            return r("il2cpp_unity_liveness_calculation_from_statics", "void", ["pointer"]);
        },
        get livenessFinalize() {
            return r("il2cpp_unity_liveness_finalize", "void", ["pointer"]);
        },
        get livenessFreeStruct() {
            return r("il2cpp_unity_liveness_free_struct", "void", ["pointer"]);
        },
        get memorySnapshotCapture() {
            return r("il2cpp_capture_memory_snapshot", "pointer", []);
        },
        get memorySnapshotFree() {
            return r("il2cpp_free_captured_memory_snapshot", "void", ["pointer"]);
        },
        get memorySnapshotGetClasses() {
            return r("il2cpp_memory_snapshot_get_classes", "pointer", ["pointer", "pointer"]);
        },
        get memorySnapshotGetObjects() {
            return r("il2cpp_memory_snapshot_get_objects", "pointer", ["pointer", "pointer"]);
        },
        get methodGetClass() {
            return r("il2cpp_method_get_class", "pointer", ["pointer"]);
        },
        get methodGetFlags() {
            return r("il2cpp_method_get_flags", "uint32", ["pointer", "pointer"]);
        },
        get methodGetName() {
            return r("il2cpp_method_get_name", "pointer", ["pointer"]);
        },
        get methodGetObject() {
            return r("il2cpp_method_get_object", "pointer", ["pointer", "pointer"]);
        },
        get methodGetParameterCount() {
            return r("il2cpp_method_get_param_count", "uint8", ["pointer"]);
        },
        get methodGetParameterName() {
            return r("il2cpp_method_get_param_name", "pointer", ["pointer", "uint32"]);
        },
        get methodGetParameters() {
            return r("il2cpp_method_get_parameters", "pointer", ["pointer", "pointer"]);
        },
        get methodGetParameterType() {
            return r("il2cpp_method_get_param", "pointer", ["pointer", "uint32"]);
        },
        get methodGetReturnType() {
            return r("il2cpp_method_get_return_type", "pointer", ["pointer"]);
        },
        get methodIsGeneric() {
            return r("il2cpp_method_is_generic", "bool", ["pointer"]);
        },
        get methodIsInflated() {
            return r("il2cpp_method_is_inflated", "bool", ["pointer"]);
        },
        get methodIsInstance() {
            return r("il2cpp_method_is_instance", "bool", ["pointer"]);
        },
        get monitorEnter() {
            return r("il2cpp_monitor_enter", "void", ["pointer"]);
        },
        get monitorExit() {
            return r("il2cpp_monitor_exit", "void", ["pointer"]);
        },
        get monitorPulse() {
            return r("il2cpp_monitor_pulse", "void", ["pointer"]);
        },
        get monitorPulseAll() {
            return r("il2cpp_monitor_pulse_all", "void", ["pointer"]);
        },
        get monitorTryEnter() {
            return r("il2cpp_monitor_try_enter", "bool", ["pointer", "uint32"]);
        },
        get monitorTryWait() {
            return r("il2cpp_monitor_try_wait", "bool", ["pointer", "uint32"]);
        },
        get monitorWait() {
            return r("il2cpp_monitor_wait", "void", ["pointer"]);
        },
        get objectGetClass() {
            return r("il2cpp_object_get_class", "pointer", ["pointer"]);
        },
        get objectGetVirtualMethod() {
            return r("il2cpp_object_get_virtual_method", "pointer", ["pointer", "pointer"]);
        },
        get objectInitialize() {
            return r("il2cpp_runtime_object_init_exception", "void", ["pointer", "pointer"]);
        },
        get objectNew() {
            return r("il2cpp_object_new", "pointer", ["pointer"]);
        },
        get objectGetSize() {
            return r("il2cpp_object_get_size", "uint32", ["pointer"]);
        },
        get objectUnbox() {
            return r("il2cpp_object_unbox", "pointer", ["pointer"]);
        },
        get resolveInternalCall() {
            return r("il2cpp_resolve_icall", "pointer", ["pointer"]);
        },
        get stringGetChars() {
            return r("il2cpp_string_chars", "pointer", ["pointer"]);
        },
        get stringGetLength() {
            return r("il2cpp_string_length", "int32", ["pointer"]);
        },
        get stringNew() {
            return r("il2cpp_string_new", "pointer", ["pointer"]);
        },
        get valueTypeBox() {
            return r("il2cpp_value_box", "pointer", ["pointer", "pointer"]);
        },
        get threadAttach() {
            return r("il2cpp_thread_attach", "pointer", ["pointer"]);
        },
        get threadDetach() {
            return r("il2cpp_thread_detach", "void", ["pointer"]);
        },
        get threadGetAttachedThreads() {
            return r("il2cpp_thread_get_all_attached_threads", "pointer", ["pointer"]);
        },
        get threadGetCurrent() {
            return r("il2cpp_thread_current", "pointer", []);
        },
        get threadIsVm() {
            return r("il2cpp_is_vm_thread", "bool", ["pointer"]);
        },
        get typeGetClass() {
            return r("il2cpp_class_from_type", "pointer", ["pointer"]);
        },
        get typeGetName() {
            return r("il2cpp_type_get_name", "pointer", ["pointer"]);
        },
        get typeGetObject() {
            return r("il2cpp_type_get_object", "pointer", ["pointer"]);
        },
        get typeGetTypeEnum() {
            return r("il2cpp_type_get_type", "int", ["pointer"]);
        }
    };
    decorate(Il2Cpp.api, lazy);
    getter(Il2Cpp, "memorySnapshotApi", () => new CModule("#include <stdint.h>\n#include <string.h>\n\ntypedef struct Il2CppManagedMemorySnapshot Il2CppManagedMemorySnapshot;\ntypedef struct Il2CppMetadataType Il2CppMetadataType;\n\nstruct Il2CppManagedMemorySnapshot\n{\n  struct Il2CppManagedHeap\n  {\n    uint32_t section_count;\n    void * sections;\n  } heap;\n  struct Il2CppStacks\n  {\n    uint32_t stack_count;\n    void * stacks;\n  } stacks;\n  struct Il2CppMetadataSnapshot\n  {\n    uint32_t type_count;\n    Il2CppMetadataType * types;\n  } metadata_snapshot;\n  struct Il2CppGCHandles\n  {\n    uint32_t tracked_object_count;\n    void ** pointers_to_objects;\n  } gc_handles;\n  struct Il2CppRuntimeInformation\n  {\n    uint32_t pointer_size;\n    uint32_t object_header_size;\n    uint32_t array_header_size;\n    uint32_t array_bounds_offset_in_header;\n    uint32_t array_size_offset_in_header;\n    uint32_t allocation_granularity;\n  } runtime_information;\n  void * additional_user_information;\n};\n\nstruct Il2CppMetadataType\n{\n  uint32_t flags;\n  void * fields;\n  uint32_t field_count;\n  uint32_t statics_size;\n  uint8_t * statics;\n  uint32_t base_or_element_type_index;\n  char * name;\n  const char * assembly_name;\n  uint64_t type_info_address;\n  uint32_t size;\n};\n\nuintptr_t\nil2cpp_memory_snapshot_get_classes (\n    const Il2CppManagedMemorySnapshot * snapshot, Il2CppMetadataType ** iter)\n{\n  const int zero = 0;\n  const void * null = 0;\n\n  if (iter != NULL && snapshot->metadata_snapshot.type_count > zero)\n  {\n    if (*iter == null)\n    {\n      *iter = snapshot->metadata_snapshot.types;\n      return (uintptr_t) (*iter)->type_info_address;\n    }\n    else\n    {\n      Il2CppMetadataType * metadata_type = *iter + 1;\n\n      if (metadata_type < snapshot->metadata_snapshot.types +\n                              snapshot->metadata_snapshot.type_count)\n      {\n        *iter = metadata_type;\n        return (uintptr_t) (*iter)->type_info_address;\n      }\n    }\n  }\n  return 0;\n}\n\nvoid **\nil2cpp_memory_snapshot_get_objects (\n    const Il2CppManagedMemorySnapshot * snapshot, uint32_t * size)\n{\n  *size = snapshot->gc_handles.tracked_object_count;\n  return snapshot->gc_handles.pointers_to_objects;\n}\n"), lazy);
    function r(exportName, retType, argTypes) {
        const handle = globalThis.IL2CPP_EXPORTS?.[exportName]?.() ?? Il2Cpp.module.findExportByName(exportName) ?? Il2Cpp.memorySnapshotApi[exportName];
        return new NativeFunction(handle ?? raise(`couldn't resolve export ${exportName}`), retType, argTypes);
    }
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /** */
    Il2Cpp.application = {
        /**
         * Gets the data path name of the current application, e.g.
         * `/data/emulated/0/Android/data/com.example.application/files`
         * on Android.
         *
         * **This information is not guaranteed to exist.**
         *
         * ```ts
         * Il2Cpp.perform(() => {
         *     // prints /data/emulated/0/Android/data/com.example.application/files
         *     console.log(Il2Cpp.application.dataPath);
         * });
         * ```
         */
        get dataPath() {
            return unityEngineCall("get_persistentDataPath");
        },
        /**
         * Gets the identifier name of the current application, e.g.
         * `com.example.application` on Android.
         *
         * **This information is not guaranteed to exist.**
         *
         * ```ts
         * Il2Cpp.perform(() => {
         *     // prints com.example.application
         *     console.log(Il2Cpp.application.identifier);
         * });
         * ```
         */
        get identifier() {
            return unityEngineCall("get_identifier") ?? unityEngineCall("get_bundleIdentifier");
        },
        /**
         * Gets the version name of the current application, e.g. `4.12.8`.
         *
         * **This information is not guaranteed to exist.**
         *
         * ```ts
         * Il2Cpp.perform(() => {
         *     // prints 4.12.8
         *     console.log(Il2Cpp.application.version);
         * });
         * ```
         */
        get version() {
            return unityEngineCall("get_version");
        }
    };
    // prettier-ignore
    getter(Il2Cpp, "unityVersion", () => {
        try {
            const unityVersion = globalThis.IL2CPP_UNITY_VERSION ?? unityEngineCall("get_unityVersion");
            if (unityVersion != null) {
                return unityVersion;
            }
        }
        catch (_) {
        }
        const searchPattern = "69 6c 32 63 70 70";
        for (const range of Il2Cpp.module.enumerateRanges("r--").concat(Process.getRangeByAddress(Il2Cpp.module.base))) {
            for (let { address } of Memory.scanSync(range.base, range.size, searchPattern)) {
                while (address.readU8() != 0) {
                    address = address.sub(1);
                }
                const match = UnityVersion.find(address.add(1).readCString());
                if (match != undefined) {
                    return match;
                }
            }
        }
        raise("couldn't determine the Unity version, please specify it manually");
    }, lazy);
    // prettier-ignore
    getter(Il2Cpp, "unityVersionIsBelow201830", () => {
        return UnityVersion.lt(Il2Cpp.unityVersion, "2018.3.0");
    }, lazy);
    // prettier-ignore
    getter(Il2Cpp, "unityVersionIsBelow202120", () => {
        return UnityVersion.lt(Il2Cpp.unityVersion, "2021.2.0");
    }, lazy);
    function unityEngineCall(method) {
        const handle = Il2Cpp.api.resolveInternalCall(Memory.allocUtf8String("UnityEngine.Application::" + method));
        const nativeFunction = new NativeFunction(handle, "pointer", []);
        return nativeFunction.isNull() ? null : new Il2Cpp.String(nativeFunction()).asNullable()?.content ?? null;
    }
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * Dumps the application, i.e. it creates a dummy `.cs` file that contains
     * all the class, field and method declarations.
     *
     * The dump is very useful when it comes to inspecting the application as
     * you can easily search for succulent members using a simple text search,
     * hence this is typically the very first thing it should be done when
     * working with a new application. \
     * Keep in mind the dump is version, platform and arch dependentend, so
     * it has to be re-genereated if any of these changes.
     *
     * The file is generated in the **target** device, so you might need to
     * pull it to the host device afterwards.
     *
     * Dumping *may* require a file name and a directory path (a place where the
     * application can write to). If not provided, the target path is generated
     * automatically using the information from {@link Il2Cpp.application}.
     *
     * ```ts
     * Il2Cpp.perform(() => {
     *     Il2Cpp.dump();
     * });
     * ```
     *
     * For instance, the dump resembles the following:
     * ```
     * class Mono.DataConverter.PackContext : System.Object
     * {
     *     System.Byte[] buffer; // 0x10
     *     System.Int32 next; // 0x18
     *     System.String description; // 0x20
     *     System.Int32 i; // 0x28
     *     Mono.DataConverter conv; // 0x30
     *     System.Int32 repeat; // 0x38
     *     System.Int32 align; // 0x3c
     *
     *     System.Void Add(System.Byte[] group); // 0x012ef4f0
     *     System.Byte[] Get(); // 0x012ef6ec
     *     System.Void .ctor(); // 0x012ef78c
     *   }
     * ```
     */
    function dump(fileName, path) {
        fileName = fileName ?? `${Il2Cpp.application.identifier ?? "unknown"}_${Il2Cpp.application.version ?? "unknown"}.cs`;
        const destination = `${path ?? Il2Cpp.application.dataPath}/${fileName}`;
        const file = new File(destination, "w");
        for (const assembly of Il2Cpp.domain.assemblies) {
            inform(`dumping ${assembly.name}...`);
            for (const klass of assembly.image.classes) {
                file.write(`${klass}\n\n`);
            }
        }
        file.flush();
        file.close();
        ok(`dump saved to ${destination}`);
    }
    Il2Cpp.dump = dump;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * Installs a listener to track any thrown (unrecoverable) C# exception. \
     * This may be useful when incurring in `abort was called` errors.
     *
     * By default, it only tracks exceptions that were thrown by the *caller*
     * thread.
     *
     * **It may not work for every platform.**
     *
     * ```ts
     * Il2Cpp.perform(() => {
     *     Il2Cpp.installExceptionListener("all");
     *
     *     // rest of the code
     * });
     * ```
     *
     * For instance, it may print something along:
     * ```
     * System.NullReferenceException: Object reference not set to an instance of an object.
     *   at AddressableLoadWrapper+<LoadGameObject>d__3[T].MoveNext () [0x00000] in <00000000000000000000000000000000>:0
     *   at UnityEngine.SetupCoroutine.InvokeMoveNext (System.Collections.IEnumerator enumerator, System.IntPtr returnValueAddress) [0x00000] in <00000000000000000000000000000000>:0
     * ```
     */
    function installExceptionListener(targetThread = "current") {
        const currentThread = Il2Cpp.api.threadGetCurrent();
        return Interceptor.attach(Il2Cpp.module.getExportByName("__cxa_throw"), function (args) {
            if (targetThread == "current" && !Il2Cpp.api.threadGetCurrent().equals(currentThread)) {
                return;
            }
            inform(new Il2Cpp.Object(args[0].readPointer()));
        });
    }
    Il2Cpp.installExceptionListener = installExceptionListener;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * Creates a filter to include elements whose type can be assigned to a
     * variable of the given class. \
     * It relies on {@link Il2Cpp.Class.isAssignableFrom}.
     *
     * ```ts
     * const IComparable = Il2Cpp.corlib.class("System.IComparable");
     *
     * const objects = [
     *     Il2Cpp.corlib.class("System.Object").new(),
     *     Il2Cpp.corlib.class("System.String").new()
     * ];
     *
     * const comparables = objects.filter(Il2Cpp.is(IComparable));
     * ```
     */
    function is(klass) {
        return (element) => {
            if (element instanceof Il2Cpp.Class) {
                return klass.isAssignableFrom(element);
            }
            else {
                return klass.isAssignableFrom(element.class);
            }
        };
    }
    Il2Cpp.is = is;
    /**
     * Creates a filter to include elements whose type can be corresponds to
     * the given class. \
     * It compares the native handle of the element classes.
     *
     * ```ts
     * const String = Il2Cpp.corlib.class("System.String");
     *
     * const objects = [
     *     Il2Cpp.corlib.class("System.Object").new(),
     *     Il2Cpp.corlib.class("System.String").new()
     * ];
     *
     * const strings = objects.filter(Il2Cpp.isExactly(String));
     * ```
     */
    function isExactly(klass) {
        return (element) => {
            if (element instanceof Il2Cpp.Class) {
                return element.equals(klass);
            }
            else {
                return element.class.equals(klass);
            }
        };
    }
    Il2Cpp.isExactly = isExactly;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * The object literal to interacts with the garbage collector.
     */
    Il2Cpp.gc = {
        /**
         * Gets the heap size in bytes.
         */
        get heapSize() {
            return Il2Cpp.api.gcGetHeapSize();
        },
        /**
         * Determines whether the garbage collector is enabled.
         */
        get isEnabled() {
            return !Il2Cpp.api.gcIsDisabled();
        },
        /**
         * Determines whether the garbage collector is incremental
         * ([source](https://docs.unity3d.com/Manual/performance-incremental-garbage-collection.html)).
         */
        get isIncremental() {
            return !!Il2Cpp.api.gcIsIncremental();
        },
        /**
         * Gets the number of nanoseconds the garbage collector can spend in a
         * collection step.
         */
        get maxTimeSlice() {
            return Il2Cpp.api.gcGetMaxTimeSlice();
        },
        /**
         * Gets the used heap size in bytes.
         */
        get usedHeapSize() {
            return Il2Cpp.api.gcGetUsedSize();
        },
        /**
         * Enables or disables the garbage collector.
         */
        set isEnabled(value) {
            value ? Il2Cpp.api.gcEnable() : Il2Cpp.api.gcDisable();
        },
        /**
         *  Sets the number of nanoseconds the garbage collector can spend in
         * a collection step.
         */
        set maxTimeSlice(nanoseconds) {
            Il2Cpp.api.gcSetMaxTimeSlice(nanoseconds);
        },
        /**
         * Returns the heap allocated objects of the specified class. \
         * This variant reads GC descriptors.
         */
        choose(klass) {
            const matches = [];
            const callback = (objects, size) => {
                for (let i = 0; i < size; i++) {
                    matches.push(new Il2Cpp.Object(objects.add(i * Process.pointerSize).readPointer()));
                }
            };
            const chooseCallback = new NativeCallback(callback, "void", ["pointer", "int", "pointer"]);
            if (Il2Cpp.unityVersionIsBelow202120) {
                const onWorld = new NativeCallback(() => { }, "void", []);
                const state = Il2Cpp.api.livenessCalculationBegin(klass, 0, chooseCallback, NULL, onWorld, onWorld);
                Il2Cpp.api.livenessCalculationFromStatics(state);
                Il2Cpp.api.livenessCalculationEnd(state);
            }
            else {
                const realloc = (handle, size) => {
                    if (!handle.isNull() && size.compare(0) == 0) {
                        Il2Cpp.free(handle);
                        return NULL;
                    }
                    else {
                        return Il2Cpp.alloc(size);
                    }
                };
                const reallocCallback = new NativeCallback(realloc, "pointer", ["pointer", "size_t", "pointer"]);
                this.stopWorld();
                const state = Il2Cpp.api.livenessAllocateStruct(klass, 0, chooseCallback, NULL, reallocCallback);
                Il2Cpp.api.livenessCalculationFromStatics(state);
                Il2Cpp.api.livenessFinalize(state);
                this.startWorld();
                Il2Cpp.api.livenessFreeStruct(state);
            }
            return matches;
        },
        /**
         * Forces a garbage collection of the specified generation.
         */
        collect(generation) {
            Il2Cpp.api.gcCollect(generation < 0 ? 0 : generation > 2 ? 2 : generation);
        },
        /**
         * Forces a garbage collection.
         */
        collectALittle() {
            Il2Cpp.api.gcCollectALittle();
        },
        /**
         *  Resumes all the previously stopped threads.
         */
        startWorld() {
            return Il2Cpp.api.gcStartWorld();
        },
        /**
         * Performs an incremental garbage collection.
         */
        startIncrementalCollection() {
            return Il2Cpp.api.gcStartIncrementalCollection();
        },
        /**
         * Stops all threads which may access the garbage collected heap, other
         * than the caller.
         */
        stopWorld() {
            return Il2Cpp.api.gcStopWorld();
        }
    };
})(Il2Cpp || (Il2Cpp = {}));
/** @internal */
var Android;
(function (Android) {
    // prettier-ignore
    getter(Android, "apiLevel", () => {
        const value = getProperty("ro.build.version.sdk");
        return value ? parseInt(value) : null;
    }, lazy);
    function getProperty(name) {
        const handle = Module.findExportByName("libc.so", "__system_property_get");
        if (handle) {
            const __system_property_get = new NativeFunction(handle, "void", ["pointer", "pointer"]);
            const value = Memory.alloc(92).writePointer(NULL);
            __system_property_get(Memory.allocUtf8String(name), value);
            return value.readCString() ?? undefined;
        }
    }
})(Android || (Android = {}));
/** @internal */
function raise(message) {
    const error = new Error(`\x1b[0m${message}`);
    error.name = `\x1b[0m\x1b[38;5;9mil2cpp\x1b[0m`;
    error.stack = error.stack
        ?.replace(/^Error/, error.name)
        ?.replace(/\n    at (.+) \((.+):(.+)\)/, "\x1b[3m\x1b[2m")
        ?.concat("\x1B[0m");
    throw error;
}
/** @internal */
function warn(message) {
    globalThis.console.log(`\x1b[38;5;11mil2cpp\x1b[0m: ${message}`);
}
/** @internal */
function ok(message) {
    globalThis.console.log(`\x1b[38;5;10mil2cpp\x1b[0m: ${message}`);
}
/** @internal */
function inform(message) {
    globalThis.console.log(`\x1b[38;5;12mil2cpp\x1b[0m: ${message}`);
}
/** @internal */
function decorate(target, decorator, descriptors = Object.getOwnPropertyDescriptors(target)) {
    for (const key in descriptors) {
        descriptors[key] = decorator(target, key, descriptors[key]);
    }
    Object.defineProperties(target, descriptors);
    return target;
}
/** @internal */
function getter(target, key, get, decorator) {
    globalThis.Object.defineProperty(target, key, decorator?.(target, key, { get, configurable: true }) ?? { get, configurable: true });
}
/** @internal */
function lazy(_, propertyKey, descriptor) {
    const getter = descriptor.get;
    if (!getter) {
        throw new Error("@lazy can only be applied to getter accessors");
    }
    descriptor.get = function () {
        const value = getter.call(this);
        Object.defineProperty(this, propertyKey, {
            value,
            configurable: descriptor.configurable,
            enumerable: descriptor.enumerable,
            writable: false
        });
        return value;
    };
    return descriptor;
}
/** Scaffold class. */
class NativeStruct {
    handle;
    constructor(handleOrWrapper) {
        if (handleOrWrapper instanceof NativePointer) {
            this.handle = handleOrWrapper;
        }
        else {
            this.handle = handleOrWrapper.handle;
        }
    }
    equals(other) {
        return this.handle.equals(other.handle);
    }
    isNull() {
        return this.handle.isNull();
    }
    asNullable() {
        return this.isNull() ? null : this;
    }
}
/** @internal */
function forModule(...moduleNames) {
    function find(moduleName, name, readString = _ => _.readUtf8String()) {
        const handle = Module.findExportByName(moduleName, name) ?? NULL;
        if (!handle.isNull()) {
            return { handle, readString };
        }
    }
    return new Promise(resolve => {
        for (const moduleName of moduleNames) {
            const module = Process.findModuleByName(moduleName);
            if (module != null) {
                resolve(module);
                return;
            }
        }
        let targets = [];
        switch (Process.platform) {
            case "linux":
                if (Android.apiLevel == null) {
                    targets = [find(null, "dlopen")];
                    break;
                }
                // A5: device reboot, can't hook symbols
                // A6, A7: __dl_open
                // A8, A8.1: __dl__Z8__dlopenPKciPKv
                // A9, A10, A12, A13: __dl___loader_dlopen
                targets = (Process.findModuleByName("linker64") ?? Process.getModuleByName("linker"))
                    .enumerateSymbols()
                    .filter(_ => ["__dl___loader_dlopen", "__dl__Z8__dlopenPKciPKv", "__dl_open"].includes(_.name))
                    .map(_ => ({ handle: _.address, readString: _ => _.readCString() }));
                break;
            case "darwin":
                targets = [find("libdyld.dylib", "dlopen")];
                break;
            case "windows":
                targets = [
                    find("kernel32.dll", "LoadLibraryW", _ => _.readUtf16String()),
                    find("kernel32.dll", "LoadLibraryExW", _ => _.readUtf16String()),
                    find("kernel32.dll", "LoadLibraryA", _ => _.readAnsiString()),
                    find("kernel32.dll", "LoadLibraryExA", _ => _.readAnsiString())
                ];
                break;
        }
        targets = targets.filter(_ => _);
        if (targets.length == 0) {
            raise(`there are no targets to hook the loading of \x1b[3m${moduleNames}\x1b[0m, please file a bug`);
        }
        const timeout = setTimeout(() => {
            for (const moduleName of moduleNames) {
                const module = Process.findModuleByName(moduleName);
                if (module != null) {
                    warn(`\x1b[3m${module.name}\x1b[0m has been loaded, but such event hasn't been detected - please file a bug`);
                    clearTimeout(timeout);
                    interceptors.forEach(_ => _.detach());
                    resolve(module);
                    return;
                }
            }
            warn(`10 seconds have passed and \x1b[3m${moduleNames}\x1b[0m has not been loaded yet, is the app running?`);
        }, 10000);
        const interceptors = targets.map(_ => Interceptor.attach(_.handle, {
            onEnter(args) {
                this.modulePath = _.readString(args[0]) ?? "";
            },
            onLeave(_) {
                for (const moduleName of moduleNames) {
                    if (this.modulePath.endsWith(moduleName)) {
                        // Adding a fallback in case Frida cannot find the module by its full path
                        // https://github.com/vfsfitvnm/frida-il2cpp-bridge/issues/547
                        const module = Process.findModuleByName(this.modulePath) ?? Process.findModuleByName(moduleName);
                        if (module != null) {
                            setImmediate(() => {
                                clearTimeout(timeout);
                                interceptors.forEach(_ => _.detach());
                            });
                            resolve(module);
                            break;
                        }
                    }
                }
            }
        }));
    });
}
NativePointer.prototype.offsetOf = function (condition, depth) {
    depth ??= 512;
    for (let i = 0; depth > 0 ? i < depth : i < -depth; i++) {
        if (condition(depth > 0 ? this.add(i) : this.sub(i))) {
            return i;
        }
    }
    return null;
};
/** @internal */
function readNativeIterator(block) {
    const array = [];
    const iterator = Memory.alloc(Process.pointerSize);
    let handle = block(iterator);
    while (!handle.isNull()) {
        array.push(handle);
        handle = block(iterator);
    }
    return array;
}
/** @internal */
function readNativeList(block) {
    const lengthPointer = Memory.alloc(Process.pointerSize);
    const startPointer = block(lengthPointer);
    if (startPointer.isNull()) {
        return [];
    }
    const array = new Array(lengthPointer.readInt());
    for (let i = 0; i < array.length; i++) {
        array[i] = startPointer.add(i * Process.pointerSize).readPointer();
    }
    return array;
}
/** @internal */
function recycle(Class) {
    return new Proxy(Class, {
        cache: new Map(),
        construct(Target, argArray) {
            const handle = argArray[0].toUInt32();
            if (!this.cache.has(handle)) {
                this.cache.set(handle, new Target(argArray[0]));
            }
            return this.cache.get(handle);
        }
    });
}
/** @internal */
var UnityVersion;
(function (UnityVersion) {
    const pattern = /(20\d{2}|\d)\.(\d)\.(\d{1,2})(?:[abcfp]|rc){0,2}\d?/;
    function find(string) {
        return string?.match(pattern)?.[0];
    }
    UnityVersion.find = find;
    function gte(a, b) {
        return compare(a, b) >= 0;
    }
    UnityVersion.gte = gte;
    function lt(a, b) {
        return compare(a, b) < 0;
    }
    UnityVersion.lt = lt;
    function compare(a, b) {
        const aMatches = a.match(pattern);
        const bMatches = b.match(pattern);
        for (let i = 1; i <= 3; i++) {
            const a = Number(aMatches?.[i] ?? -1);
            const b = Number(bMatches?.[i] ?? -1);
            if (a > b)
                return 1;
            else if (a < b)
                return -1;
        }
        return 0;
    }
})(UnityVersion || (UnityVersion = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /**
     * Allocates the given amount of bytes - it's equivalent to C's `malloc`. \
     * The allocated memory should be freed manually.
     */
    function alloc(size = Process.pointerSize) {
        return Il2Cpp.api.alloc(size);
    }
    Il2Cpp.alloc = alloc;
    /**
     * Frees a previously allocated memory using {@link Il2Cpp.alloc} - it's
     *  equivalent to C's `free`..
     *
     * ```ts
     * const handle = Il2Cpp.alloc(64);
     *
     * // ...
     *
     * Il2Cpp.free(handle);
     * ```
     */
    function free(pointer) {
        return Il2Cpp.api.free(pointer);
    }
    Il2Cpp.free = free;
    /** @internal */
    function read(pointer, type) {
        switch (type.typeEnum) {
            case Il2Cpp.Type.enum.boolean:
                return !!pointer.readS8();
            case Il2Cpp.Type.enum.byte:
                return pointer.readS8();
            case Il2Cpp.Type.enum.unsignedByte:
                return pointer.readU8();
            case Il2Cpp.Type.enum.short:
                return pointer.readS16();
            case Il2Cpp.Type.enum.unsignedShort:
                return pointer.readU16();
            case Il2Cpp.Type.enum.int:
                return pointer.readS32();
            case Il2Cpp.Type.enum.unsignedInt:
                return pointer.readU32();
            case Il2Cpp.Type.enum.char:
                return pointer.readU16();
            case Il2Cpp.Type.enum.long:
                return pointer.readS64();
            case Il2Cpp.Type.enum.unsignedLong:
                return pointer.readU64();
            case Il2Cpp.Type.enum.float:
                return pointer.readFloat();
            case Il2Cpp.Type.enum.double:
                return pointer.readDouble();
            case Il2Cpp.Type.enum.nativePointer:
            case Il2Cpp.Type.enum.unsignedNativePointer:
                return pointer.readPointer();
            case Il2Cpp.Type.enum.pointer:
                return new Il2Cpp.Pointer(pointer.readPointer(), type.class.baseType);
            case Il2Cpp.Type.enum.valueType:
                return new Il2Cpp.ValueType(pointer, type);
            case Il2Cpp.Type.enum.object:
            case Il2Cpp.Type.enum.class:
                return new Il2Cpp.Object(pointer.readPointer());
            case Il2Cpp.Type.enum.genericInstance:
                return type.class.isValueType ? new Il2Cpp.ValueType(pointer, type) : new Il2Cpp.Object(pointer.readPointer());
            case Il2Cpp.Type.enum.string:
                return new Il2Cpp.String(pointer.readPointer());
            case Il2Cpp.Type.enum.array:
            case Il2Cpp.Type.enum.multidimensionalArray:
                return new Il2Cpp.Array(pointer.readPointer());
        }
        raise(`couldn't read the value from ${pointer} using an unhandled or unknown type ${type.name} (${type.typeEnum}), please file an issue`);
    }
    Il2Cpp.read = read;
    /** @internal */
    function write(pointer, value, type) {
        switch (type.typeEnum) {
            case Il2Cpp.Type.enum.boolean:
                return pointer.writeS8(+value);
            case Il2Cpp.Type.enum.byte:
                return pointer.writeS8(value);
            case Il2Cpp.Type.enum.unsignedByte:
                return pointer.writeU8(value);
            case Il2Cpp.Type.enum.short:
                return pointer.writeS16(value);
            case Il2Cpp.Type.enum.unsignedShort:
                return pointer.writeU16(value);
            case Il2Cpp.Type.enum.int:
                return pointer.writeS32(value);
            case Il2Cpp.Type.enum.unsignedInt:
                return pointer.writeU32(value);
            case Il2Cpp.Type.enum.char:
                return pointer.writeU16(value);
            case Il2Cpp.Type.enum.long:
                return pointer.writeS64(value);
            case Il2Cpp.Type.enum.unsignedLong:
                return pointer.writeU64(value);
            case Il2Cpp.Type.enum.float:
                return pointer.writeFloat(value);
            case Il2Cpp.Type.enum.double:
                return pointer.writeDouble(value);
            case Il2Cpp.Type.enum.nativePointer:
            case Il2Cpp.Type.enum.unsignedNativePointer:
            case Il2Cpp.Type.enum.pointer:
            case Il2Cpp.Type.enum.string:
            case Il2Cpp.Type.enum.array:
            case Il2Cpp.Type.enum.multidimensionalArray:
                return pointer.writePointer(value);
            case Il2Cpp.Type.enum.valueType:
                return Memory.copy(pointer, value, type.class.valueTypeSize), pointer;
            case Il2Cpp.Type.enum.object:
            case Il2Cpp.Type.enum.class:
            case Il2Cpp.Type.enum.genericInstance:
                return value instanceof Il2Cpp.ValueType ? (Memory.copy(pointer, value, type.class.valueTypeSize), pointer) : pointer.writePointer(value);
        }
        raise(`couldn't write value ${value} to ${pointer} using an unhandled or unknown type ${type.name} (${type.typeEnum}), please file an issue`);
    }
    Il2Cpp.write = write;
    /** @internal */
    function fromFridaValue(value, type) {
        if (globalThis.Array.isArray(value)) {
            const handle = Memory.alloc(type.class.valueTypeSize);
            const fields = type.class.fields.filter(_ => !_.isStatic);
            for (let i = 0; i < fields.length; i++) {
                const convertedValue = fromFridaValue(value[i], fields[i].type);
                write(handle.add(fields[i].offset).sub(Il2Cpp.Object.headerSize), convertedValue, fields[i].type);
            }
            return new Il2Cpp.ValueType(handle, type);
        }
        else if (value instanceof NativePointer) {
            if (type.isByReference) {
                return new Il2Cpp.Reference(value, type);
            }
            switch (type.typeEnum) {
                case Il2Cpp.Type.enum.pointer:
                    return new Il2Cpp.Pointer(value, type.class.baseType);
                case Il2Cpp.Type.enum.string:
                    return new Il2Cpp.String(value);
                case Il2Cpp.Type.enum.class:
                case Il2Cpp.Type.enum.genericInstance:
                case Il2Cpp.Type.enum.object:
                    return new Il2Cpp.Object(value);
                case Il2Cpp.Type.enum.array:
                case Il2Cpp.Type.enum.multidimensionalArray:
                    return new Il2Cpp.Array(value);
                default:
                    return value;
            }
        }
        else if (type.typeEnum == Il2Cpp.Type.enum.boolean) {
            return !!value;
        }
        else if (type.typeEnum == Il2Cpp.Type.enum.valueType && type.class.isEnum) {
            return fromFridaValue([value], type);
        }
        else {
            return value;
        }
    }
    Il2Cpp.fromFridaValue = fromFridaValue;
    /** @internal */
    function toFridaValue(value) {
        if (typeof value == "boolean") {
            return +value;
        }
        else if (value instanceof Il2Cpp.ValueType) {
            if (value.type.class.isEnum) {
                return value.field("value__").value;
            }
            else {
                const _ = value.type.class.fields.filter(_ => !_.isStatic).map(_ => toFridaValue(_.withHolder(value).value));
                return _.length == 0 ? [0] : _;
            }
        }
        else {
            return value;
        }
    }
    Il2Cpp.toFridaValue = toFridaValue;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    getter(Il2Cpp, "module", () => {
        const [moduleName, fallback] = getExpectedModuleNames();
        return Process.findModuleByName(moduleName) ?? Process.getModuleByName(fallback);
    });
    /**
     * @internal
     * Waits for the IL2CPP native library to be loaded and initialized.
     */
    async function initialize(blocking = false) {
        Reflect.defineProperty(Il2Cpp, "module", {
            // prettier-ignore
            value: Process.platform == "darwin"
                ? Process.findModuleByAddress(DebugSymbol.fromName("il2cpp_init").address)
                    ?? await forModule(...getExpectedModuleNames())
                : await forModule(...getExpectedModuleNames())
        });
        // At this point, the IL2CPP native library has been loaded, but we
        // cannot interact with IL2CPP until `il2cpp_init` is done.
        // It looks like `il2cpp_get_corlib` returns NULL only when the
        // initialization is not completed yet.
        if (Il2Cpp.api.getCorlib().isNull()) {
            return await new Promise(resolve => {
                const interceptor = Interceptor.attach(Il2Cpp.api.initialize, {
                    onLeave() {
                        interceptor.detach();
                        blocking ? resolve(true) : setImmediate(() => resolve(false));
                    }
                });
            });
        }
        return false;
    }
    Il2Cpp.initialize = initialize;
    function getExpectedModuleNames() {
        if (globalThis.IL2CPP_MODULE_NAME) {
            return [globalThis.IL2CPP_MODULE_NAME];
        }
        switch (Process.platform) {
            case "linux":
                return [Android.apiLevel ? "libil2cpp.so" : "GameAssembly.so"];
            case "windows":
                return ["GameAssembly.dll"];
            case "darwin":
                return ["UnityFramework", "GameAssembly.dylib"];
        }
        raise(`${Process.platform} is not supported yet`);
    }
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /** Attaches the caller thread to Il2Cpp domain and executes the given block.  */
    async function perform(block, flag = "bind") {
        try {
            const isInMainThread = await Il2Cpp.initialize(flag == "main");
            if (flag == "main" && !isInMainThread) {
                return perform(() => Il2Cpp.mainThread.schedule(block), "free");
            }
            let thread = Il2Cpp.currentThread;
            const isForeignThread = thread == null;
            thread ??= Il2Cpp.domain.attach();
            const result = block();
            if (isForeignThread) {
                if (flag == "free") {
                    thread.detach();
                }
                else if (flag == "bind") {
                    Script.bindWeak(globalThis, () => thread.detach());
                }
            }
            return result instanceof Promise ? await result : result;
        }
        catch (error) {
            Script.nextTick(_ => { throw _; }, error); // prettier-ignore
            return Promise.reject(error);
        }
    }
    Il2Cpp.perform = perform;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Tracer {
        /** @internal */
        #state = {
            depth: 0,
            buffer: [],
            history: new Set(),
            flush: () => {
                if (this.#state.depth == 0) {
                    const message = `\n${this.#state.buffer.join("\n")}\n`;
                    if (this.#verbose) {
                        inform(message);
                    }
                    else {
                        const hash = cyrb53(message);
                        if (!this.#state.history.has(hash)) {
                            this.#state.history.add(hash);
                            inform(message);
                        }
                    }
                    this.#state.buffer.length = 0;
                }
            }
        };
        /** @internal */
        #threadId = Il2Cpp.mainThread.id;
        /** @internal */
        #verbose = false;
        /** @internal */
        #applier;
        /** @internal */
        #targets = [];
        /** @internal */
        #domain;
        /** @internal */
        #assemblies;
        /** @internal */
        #classes;
        /** @internal */
        #methods;
        /** @internal */
        #assemblyFilter;
        /** @internal */
        #classFilter;
        /** @internal */
        #methodFilter;
        /** @internal */
        #parameterFilter;
        constructor(applier) {
            this.#applier = applier;
        }
        /** */
        thread(thread) {
            this.#threadId = thread.id;
            return this;
        }
        /** Determines whether print duplicate logs. */
        verbose(value) {
            this.#verbose = value;
            return this;
        }
        /** Sets the application domain as the place where to find the target methods. */
        domain() {
            this.#domain = Il2Cpp.domain;
            return this;
        }
        /** Sets the passed `assemblies` as the place where to find the target methods. */
        assemblies(...assemblies) {
            this.#assemblies = assemblies;
            return this;
        }
        /** Sets the passed `classes` as the place where to find the target methods. */
        classes(...classes) {
            this.#classes = classes;
            return this;
        }
        /** Sets the passed `methods` as the target methods. */
        methods(...methods) {
            this.#methods = methods;
            return this;
        }
        /** Filters the assemblies where to find the target methods. */
        filterAssemblies(filter) {
            this.#assemblyFilter = filter;
            return this;
        }
        /** Filters the classes where to find the target methods. */
        filterClasses(filter) {
            this.#classFilter = filter;
            return this;
        }
        /** Filters the target methods. */
        filterMethods(filter) {
            this.#methodFilter = filter;
            return this;
        }
        /** Filters the target methods. */
        filterParameters(filter) {
            this.#parameterFilter = filter;
            return this;
        }
        /** Commits the current changes by finding the target methods. */
        and() {
            const filterMethod = (method) => {
                if (this.#parameterFilter == undefined) {
                    this.#targets.push(method);
                    return;
                }
                for (const parameter of method.parameters) {
                    if (this.#parameterFilter(parameter)) {
                        this.#targets.push(method);
                        break;
                    }
                }
            };
            const filterMethods = (values) => {
                for (const method of values) {
                    filterMethod(method);
                }
            };
            const filterClass = (klass) => {
                if (this.#methodFilter == undefined) {
                    filterMethods(klass.methods);
                    return;
                }
                for (const method of klass.methods) {
                    if (this.#methodFilter(method)) {
                        filterMethod(method);
                    }
                }
            };
            const filterClasses = (values) => {
                for (const klass of values) {
                    filterClass(klass);
                }
            };
            const filterAssembly = (assembly) => {
                if (this.#classFilter == undefined) {
                    filterClasses(assembly.image.classes);
                    return;
                }
                for (const klass of assembly.image.classes) {
                    if (this.#classFilter(klass)) {
                        filterClass(klass);
                    }
                }
            };
            const filterAssemblies = (assemblies) => {
                for (const assembly of assemblies) {
                    filterAssembly(assembly);
                }
            };
            const filterDomain = (domain) => {
                if (this.#assemblyFilter == undefined) {
                    filterAssemblies(domain.assemblies);
                    return;
                }
                for (const assembly of domain.assemblies) {
                    if (this.#assemblyFilter(assembly)) {
                        filterAssembly(assembly);
                    }
                }
            };
            this.#methods
                ? filterMethods(this.#methods)
                : this.#classes
                    ? filterClasses(this.#classes)
                    : this.#assemblies
                        ? filterAssemblies(this.#assemblies)
                        : this.#domain
                            ? filterDomain(this.#domain)
                            : undefined;
            this.#assemblies = undefined;
            this.#classes = undefined;
            this.#methods = undefined;
            this.#assemblyFilter = undefined;
            this.#classFilter = undefined;
            this.#methodFilter = undefined;
            this.#parameterFilter = undefined;
            return this;
        }
        /** Starts tracing. */
        attach() {
            for (const target of this.#targets) {
                if (!target.virtualAddress.isNull()) {
                    try {
                        this.#applier(target, this.#state, this.#threadId);
                    }
                    catch (e) {
                        switch (e.message) {
                            case /unable to intercept function at \w+; please file a bug/.exec(e.message)?.input:
                            case "already replaced this function":
                                break;
                            default:
                                throw e;
                        }
                    }
                }
            }
        }
    }
    Il2Cpp.Tracer = Tracer;
    /** */
    function trace(parameters = false) {
        const applier = () => (method, state, threadId) => {
            const paddedVirtualAddress = method.relativeVirtualAddress.toString(16).padStart(8, "0");
            Interceptor.attach(method.virtualAddress, {
                onEnter() {
                    if (this.threadId == threadId) {
                        // prettier-ignore
                        state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(state.depth++)}┌─\x1b[35m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m`);
                    }
                },
                onLeave() {
                    if (this.threadId == threadId) {
                        // prettier-ignore
                        state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(--state.depth)}└─\x1b[33m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m`);
                        state.flush();
                    }
                }
            });
        };
        const applierWithParameters = () => (method, state, threadId) => {
            const paddedVirtualAddress = method.relativeVirtualAddress.toString(16).padStart(8, "0");
            const startIndex = +!method.isStatic | +Il2Cpp.unityVersionIsBelow201830;
            const callback = function (...args) {
                if (this.threadId == threadId) {
                    const thisParameter = method.isStatic ? undefined : new Il2Cpp.Parameter("this", -1, method.class.type);
                    const parameters = thisParameter ? [thisParameter].concat(method.parameters) : method.parameters;
                    // prettier-ignore
                    state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(state.depth++)}┌─\x1b[35m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m(${parameters.map(e => `\x1b[32m${e.name}\x1b[0m = \x1b[31m${Il2Cpp.fromFridaValue(args[e.position + startIndex], e.type)}\x1b[0m`).join(", ")})`);
                }
                const returnValue = method.nativeFunction(...args);
                if (this.threadId == threadId) {
                    // prettier-ignore
                    state.buffer.push(`\x1b[2m0x${paddedVirtualAddress}\x1b[0m ${`│ `.repeat(--state.depth)}└─\x1b[33m${method.class.type.name}::\x1b[1m${method.name}\x1b[0m\x1b[0m${returnValue == undefined ? "" : ` = \x1b[36m${Il2Cpp.fromFridaValue(returnValue, method.returnType)}`}\x1b[0m`);
                    state.flush();
                }
                return returnValue;
            };
            method.revert();
            const nativeCallback = new NativeCallback(callback, method.returnType.fridaAlias, method.fridaSignature);
            Interceptor.replace(method.virtualAddress, nativeCallback);
        };
        return new Il2Cpp.Tracer(parameters ? applierWithParameters() : applier());
    }
    Il2Cpp.trace = trace;
    /** */
    function backtrace(mode) {
        const methods = Il2Cpp.domain.assemblies
            .flatMap(_ => _.image.classes.flatMap(_ => _.methods.filter(_ => !_.virtualAddress.isNull())))
            .sort((_, __) => _.virtualAddress.compare(__.virtualAddress));
        const searchInsert = (target) => {
            let left = 0;
            let right = methods.length - 1;
            while (left <= right) {
                const pivot = Math.floor((left + right) / 2);
                const comparison = methods[pivot].virtualAddress.compare(target);
                if (comparison == 0) {
                    return methods[pivot];
                }
                else if (comparison > 0) {
                    right = pivot - 1;
                }
                else {
                    left = pivot + 1;
                }
            }
            return methods[right];
        };
        const applier = () => (method, state, threadId) => {
            Interceptor.attach(method.virtualAddress, function () {
                if (this.threadId == threadId) {
                    const handles = globalThis.Thread.backtrace(this.context, mode);
                    handles.unshift(method.virtualAddress);
                    for (const handle of handles) {
                        if (handle.compare(Il2Cpp.module.base) > 0 && handle.compare(Il2Cpp.module.base.add(Il2Cpp.module.size)) < 0) {
                            const method = searchInsert(handle);
                            if (method) {
                                const offset = handle.sub(method.virtualAddress);
                                if (offset.compare(0xfff) < 0) {
                                    // prettier-ignore
                                    state.buffer.push(`\x1b[2m0x${method.relativeVirtualAddress.toString(16).padStart(8, "0")}\x1b[0m\x1b[2m+0x${offset.toString(16).padStart(3, `0`)}\x1b[0m ${method.class.type.name}::\x1b[1m${method.name}\x1b[0m`);
                                }
                            }
                        }
                    }
                    state.flush();
                }
            });
        };
        return new Il2Cpp.Tracer(applier());
    }
    Il2Cpp.backtrace = backtrace;
    /** https://stackoverflow.com/a/52171480/16885569 */
    function cyrb53(str) {
        let h1 = 0xdeadbeef;
        let h2 = 0x41c6ce57;
        for (let i = 0, ch; i < str.length; i++) {
            ch = str.charCodeAt(i);
            h1 = Math.imul(h1 ^ ch, 2654435761);
            h2 = Math.imul(h2 ^ ch, 1597334677);
        }
        h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
        h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
        h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
        h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
        return 4294967296 * (2097151 & h2) + (h1 >>> 0);
    }
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Array extends NativeStruct {
        /** Gets the Il2CppArray struct size, possibly equal to `Process.pointerSize * 4`. */
        static get headerSize() {
            return Il2Cpp.corlib.class("System.Array").instanceSize;
        }
        /** @internal Gets a pointer to the first element of the current array. */
        get elements() {
            // We previosly obtained an array whose content is known by calling
            // 'System.String::Split(NULL)' on a known string. However, that
            // method invocation somehow blows things up in Unity 2018.3.0f1.
            const array = Il2Cpp.string("v").object.method("ToCharArray", 0).invoke();
            // prettier-ignore
            const offset = array.handle.offsetOf(_ => _.readS16() == 118) ??
                raise("couldn't find the elements offset in the native array struct");
            // prettier-ignore
            getter(Il2Cpp.Array.prototype, "elements", function () {
                return new Il2Cpp.Pointer(this.handle.add(offset), this.elementType);
            }, lazy);
            return this.elements;
        }
        /** Gets the size of the object encompassed by the current array. */
        get elementSize() {
            return this.elementType.class.arrayElementSize;
        }
        /** Gets the type of the object encompassed by the current array. */
        get elementType() {
            return this.object.class.type.class.baseType;
        }
        /** Gets the total number of elements in all the dimensions of the current array. */
        get length() {
            return Il2Cpp.api.arrayGetLength(this);
        }
        /** Gets the encompassing object of the current array. */
        get object() {
            return new Il2Cpp.Object(this);
        }
        /** Gets the element at the specified index of the current array. */
        get(index) {
            if (index < 0 || index >= this.length) {
                raise(`cannot get element at index ${index} as the array length is ${this.length}`);
            }
            return this.elements.get(index);
        }
        /** Sets the element at the specified index of the current array. */
        set(index, value) {
            if (index < 0 || index >= this.length) {
                raise(`cannot set element at index ${index} as the array length is ${this.length}`);
            }
            this.elements.set(index, value);
        }
        /** */
        toString() {
            return this.isNull() ? "null" : `[${this.elements.read(this.length, 0)}]`;
        }
        /** Iterable. */
        *[Symbol.iterator]() {
            for (let i = 0; i < this.length; i++) {
                yield this.elements.get(i);
            }
        }
    }
    __decorate([
        lazy
    ], Array.prototype, "elementSize", null);
    __decorate([
        lazy
    ], Array.prototype, "elementType", null);
    __decorate([
        lazy
    ], Array.prototype, "length", null);
    __decorate([
        lazy
    ], Array.prototype, "object", null);
    __decorate([
        lazy
    ], Array, "headerSize", null);
    Il2Cpp.Array = Array;
    /** @internal */
    function array(klass, lengthOrElements) {
        const length = typeof lengthOrElements == "number" ? lengthOrElements : lengthOrElements.length;
        const array = new Il2Cpp.Array(Il2Cpp.api.arrayNew(klass, length));
        if (globalThis.Array.isArray(lengthOrElements)) {
            array.elements.write(lengthOrElements);
        }
        return array;
    }
    Il2Cpp.array = array;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    let Assembly = class Assembly extends NativeStruct {
        /** Gets the image of this assembly. */
        get image() {
            let get = function () {
                return new Il2Cpp.Image(Il2Cpp.api.assemblyGetImage(this));
            };
            try {
                Il2Cpp.api.assemblyGetImage;
            }
            catch (_) {
                get = function () {
                    // We need to get the System.Reflection.Module of the current assembly;
                    // System.Reflection.Assembly::GetModulesInternal, for some reason,
                    // throws a NullReferenceExceptionin Unity 5.3.8f1, so we must rely on
                    // System.Type::get_Module instead.
                    // Now we need to get any System.Type of this assembly.
                    // We cannot use System.Reflection.Assembly::GetTypes because it may
                    // return an empty array; hence we use System.Reflection.Assembly::GetType
                    // to retrieve <Module>, a class/type that seems to be always present
                    // (despite being excluded from System.Reflection.Assembly::GetTypes).
                    return new Il2Cpp.Image(this.object
                        .method("GetType", 1)
                        .invoke(Il2Cpp.string("<Module>"))
                        .method("get_Module")
                        .invoke()
                        .field("_impl").value);
                };
            }
            getter(Il2Cpp.Assembly.prototype, "image", get, lazy);
            return this.image;
        }
        /** Gets the name of this assembly. */
        get name() {
            return this.image.name.replace(".dll", "");
        }
        /** Gets the encompassing object of the current assembly. */
        get object() {
            for (const _ of Il2Cpp.domain.object.method("GetAssemblies", 1).invoke(false)) {
                if (_.field("_mono_assembly").value.equals(this)) {
                    return _;
                }
            }
            raise("couldn't find the object of the native assembly struct");
        }
    };
    __decorate([
        lazy
    ], Assembly.prototype, "name", null);
    __decorate([
        lazy
    ], Assembly.prototype, "object", null);
    Assembly = __decorate([
        recycle
    ], Assembly);
    Il2Cpp.Assembly = Assembly;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    let Class = class Class extends NativeStruct {
        /** Gets the actual size of the instance of the current class. */
        get actualInstanceSize() {
            const SystemString = Il2Cpp.corlib.class("System.String");
            // prettier-ignore
            const offset = SystemString.handle.offsetOf(_ => _.readInt() == SystemString.instanceSize - 2)
                ?? raise("couldn't find the actual instance size offset in the native class struct");
            // prettier-ignore
            getter(Il2Cpp.Class.prototype, "actualInstanceSize", function () {
                return this.handle.add(offset).readS32();
            }, lazy);
            return this.actualInstanceSize;
        }
        /** Gets the array class which encompass the current class. */
        get arrayClass() {
            return new Il2Cpp.Class(Il2Cpp.api.classGetArrayClass(this, 1));
        }
        /** Gets the size of the object encompassed by the current array class. */
        get arrayElementSize() {
            return Il2Cpp.api.classGetArrayElementSize(this);
        }
        /** Gets the name of the assembly in which the current class is defined. */
        get assemblyName() {
            return Il2Cpp.api.classGetAssemblyName(this).readUtf8String().replace(".dll", "");
        }
        /** Gets the class that declares the current nested class. */
        get declaringClass() {
            return new Il2Cpp.Class(Il2Cpp.api.classGetDeclaringType(this)).asNullable();
        }
        /** Gets the encompassed type of this array, reference, pointer or enum type. */
        get baseType() {
            return new Il2Cpp.Type(Il2Cpp.api.classGetBaseType(this)).asNullable();
        }
        /** Gets the class of the object encompassed or referred to by the current array, pointer or reference class. */
        get elementClass() {
            return new Il2Cpp.Class(Il2Cpp.api.classGetElementClass(this)).asNullable();
        }
        /** Gets the fields of the current class. */
        get fields() {
            return readNativeIterator(_ => Il2Cpp.api.classGetFields(this, _)).map(_ => new Il2Cpp.Field(_));
        }
        /** Gets the flags of the current class. */
        get flags() {
            return Il2Cpp.api.classGetFlags(this);
        }
        /** Gets the full name (namespace + name) of the current class. */
        get fullName() {
            return this.namespace ? `${this.namespace}.${this.name}` : this.name;
        }
        /** Gets the generics parameters of this generic class. */
        get generics() {
            if (!this.isGeneric && !this.isInflated) {
                return [];
            }
            const types = this.type.object.method("GetGenericArguments").invoke();
            return globalThis.Array.from(types).map(_ => new Il2Cpp.Class(Il2Cpp.api.classFromObject(_)));
        }
        /** Determines whether the GC has tracking references to the current class instances. */
        get hasReferences() {
            return !!Il2Cpp.api.classHasReferences(this);
        }
        /** Determines whether ther current class has a valid static constructor. */
        get hasStaticConstructor() {
            const staticConstructor = this.tryMethod(".cctor");
            return staticConstructor != null && !staticConstructor.virtualAddress.isNull();
        }
        /** Gets the image in which the current class is defined. */
        get image() {
            return new Il2Cpp.Image(Il2Cpp.api.classGetImage(this));
        }
        /** Gets the size of the instance of the current class. */
        get instanceSize() {
            return Il2Cpp.api.classGetInstanceSize(this);
        }
        /** Determines whether the current class is abstract. */
        get isAbstract() {
            return !!Il2Cpp.api.classIsAbstract(this);
        }
        /** Determines whether the current class is blittable. */
        get isBlittable() {
            return !!Il2Cpp.api.classIsBlittable(this);
        }
        /** Determines whether the current class is an enumeration. */
        get isEnum() {
            return !!Il2Cpp.api.classIsEnum(this);
        }
        /** Determines whether the current class is a generic one. */
        get isGeneric() {
            return !!Il2Cpp.api.classIsGeneric(this);
        }
        /** Determines whether the current class is inflated. */
        get isInflated() {
            return !!Il2Cpp.api.classIsInflated(this);
        }
        /** Determines whether the current class is an interface. */
        get isInterface() {
            return !!Il2Cpp.api.classIsInterface(this);
        }
        /** Determines whether the current class is a struct. */
        get isStruct() {
            return this.isValueType && !this.isEnum;
        }
        /** Determines whether the current class is a value type. */
        get isValueType() {
            return !!Il2Cpp.api.classIsValueType(this);
        }
        /** Gets the interfaces implemented or inherited by the current class. */
        get interfaces() {
            return readNativeIterator(_ => Il2Cpp.api.classGetInterfaces(this, _)).map(_ => new Il2Cpp.Class(_));
        }
        /** Gets the methods implemented by the current class. */
        get methods() {
            return readNativeIterator(_ => Il2Cpp.api.classGetMethods(this, _)).map(_ => new Il2Cpp.Method(_));
        }
        /** Gets the name of the current class. */
        get name() {
            return Il2Cpp.api.classGetName(this).readUtf8String();
        }
        /** Gets the namespace of the current class. */
        get namespace() {
            return Il2Cpp.api.classGetNamespace(this).readUtf8String();
        }
        /** Gets the classes nested inside the current class. */
        get nestedClasses() {
            return readNativeIterator(_ => Il2Cpp.api.classGetNestedClasses(this, _)).map(_ => new Il2Cpp.Class(_));
        }
        /** Gets the class from which the current class directly inherits. */
        get parent() {
            return new Il2Cpp.Class(Il2Cpp.api.classGetParent(this)).asNullable();
        }
        /** Gets the rank (number of dimensions) of the current array class. */
        get rank() {
            let rank = 0;
            const name = this.name;
            for (let i = this.name.length - 1; i > 0; i--) {
                const c = name[i];
                if (c == "]")
                    rank++;
                else if (c == "[" || rank == 0)
                    break;
                else if (c == ",")
                    rank++;
                else
                    break;
            }
            return rank;
        }
        /** Gets a pointer to the static fields of the current class. */
        get staticFieldsData() {
            return Il2Cpp.api.classGetStaticFieldData(this);
        }
        /** Gets the size of the instance - as a value type - of the current class. */
        get valueTypeSize() {
            return Il2Cpp.api.classGetValueTypeSize(this, NULL);
        }
        /** Gets the type of the current class. */
        get type() {
            return new Il2Cpp.Type(Il2Cpp.api.classGetType(this));
        }
        /** Allocates a new object of the current class. */
        alloc() {
            return new Il2Cpp.Object(Il2Cpp.api.objectNew(this));
        }
        /** Gets the field identified by the given name. */
        field(name) {
            return this.tryField(name) ?? raise(`couldn't find field ${name} in class ${this.type.name}`);
        }
        /** Builds a generic instance of the current generic class. */
        inflate(...classes) {
            if (!this.isGeneric) {
                raise(`cannot inflate class ${this.type.name} as it has no generic parameters`);
            }
            if (this.generics.length != classes.length) {
                raise(`cannot inflate class ${this.type.name} as it needs ${this.generics.length} generic parameter(s), not ${classes.length}`);
            }
            const types = classes.map(_ => _.type.object);
            const typeArray = Il2Cpp.array(Il2Cpp.corlib.class("System.Type"), types);
            const inflatedType = this.type.object.method("MakeGenericType", 1).invoke(typeArray);
            return new Il2Cpp.Class(Il2Cpp.api.classFromObject(inflatedType));
        }
        /** Calls the static constructor of the current class. */
        initialize() {
            Il2Cpp.api.classInitialize(this);
            return this;
        }
        /** Determines whether an instance of `other` class can be assigned to a variable of the current type. */
        isAssignableFrom(other) {
            return !!Il2Cpp.api.classIsAssignableFrom(this, other);
        }
        /** Determines whether the current class derives from `other` class. */
        isSubclassOf(other, checkInterfaces) {
            return !!Il2Cpp.api.classIsSubclassOf(this, other, +checkInterfaces);
        }
        /** Gets the method identified by the given name and parameter count. */
        method(name, parameterCount = -1) {
            return this.tryMethod(name, parameterCount) ?? raise(`couldn't find method ${name} in class ${this.type.name}`);
        }
        /** Gets the nested class with the given name. */
        nested(name) {
            return this.tryNested(name) ?? raise(`couldn't find nested class ${name} in class ${this.type.name}`);
        }
        /** Allocates a new object of the current class and calls its default constructor. */
        new() {
            const object = this.alloc();
            const exceptionArray = Memory.alloc(Process.pointerSize);
            Il2Cpp.api.objectInitialize(object, exceptionArray);
            const exception = exceptionArray.readPointer();
            if (!exception.isNull()) {
                raise(new Il2Cpp.Object(exception).toString());
            }
            return object;
        }
        /** Gets the field with the given name. */
        tryField(name) {
            return new Il2Cpp.Field(Il2Cpp.api.classGetFieldFromName(this, Memory.allocUtf8String(name))).asNullable();
        }
        /** Gets the method with the given name and parameter count. */
        tryMethod(name, parameterCount = -1) {
            return new Il2Cpp.Method(Il2Cpp.api.classGetMethodFromName(this, Memory.allocUtf8String(name), parameterCount)).asNullable();
        }
        /** Gets the nested class with the given name. */
        tryNested(name) {
            return this.nestedClasses.find(_ => _.name == name);
        }
        /** */
        toString() {
            const inherited = [this.parent].concat(this.interfaces);
            return `\
// ${this.assemblyName}
${this.isEnum ? `enum` : this.isStruct ? `struct` : this.isInterface ? `interface` : `class`} \
${this.type.name}\
${inherited ? ` : ${inherited.map(_ => _?.type.name).join(`, `)}` : ``}
{
    ${this.fields.join(`\n    `)}
    ${this.methods.join(`\n    `)}
}`;
        }
        /** Executes a callback for every defined class. */
        static enumerate(block) {
            const callback = new NativeCallback(_ => block(new Il2Cpp.Class(_)), "void", ["pointer", "pointer"]);
            return Il2Cpp.api.classForEach(callback, NULL);
        }
    };
    __decorate([
        lazy
    ], Class.prototype, "arrayClass", null);
    __decorate([
        lazy
    ], Class.prototype, "arrayElementSize", null);
    __decorate([
        lazy
    ], Class.prototype, "assemblyName", null);
    __decorate([
        lazy
    ], Class.prototype, "declaringClass", null);
    __decorate([
        lazy
    ], Class.prototype, "baseType", null);
    __decorate([
        lazy
    ], Class.prototype, "elementClass", null);
    __decorate([
        lazy
    ], Class.prototype, "fields", null);
    __decorate([
        lazy
    ], Class.prototype, "flags", null);
    __decorate([
        lazy
    ], Class.prototype, "fullName", null);
    __decorate([
        lazy
    ], Class.prototype, "generics", null);
    __decorate([
        lazy
    ], Class.prototype, "hasReferences", null);
    __decorate([
        lazy
    ], Class.prototype, "hasStaticConstructor", null);
    __decorate([
        lazy
    ], Class.prototype, "image", null);
    __decorate([
        lazy
    ], Class.prototype, "instanceSize", null);
    __decorate([
        lazy
    ], Class.prototype, "isAbstract", null);
    __decorate([
        lazy
    ], Class.prototype, "isBlittable", null);
    __decorate([
        lazy
    ], Class.prototype, "isEnum", null);
    __decorate([
        lazy
    ], Class.prototype, "isGeneric", null);
    __decorate([
        lazy
    ], Class.prototype, "isInflated", null);
    __decorate([
        lazy
    ], Class.prototype, "isInterface", null);
    __decorate([
        lazy
    ], Class.prototype, "isValueType", null);
    __decorate([
        lazy
    ], Class.prototype, "interfaces", null);
    __decorate([
        lazy
    ], Class.prototype, "methods", null);
    __decorate([
        lazy
    ], Class.prototype, "name", null);
    __decorate([
        lazy
    ], Class.prototype, "namespace", null);
    __decorate([
        lazy
    ], Class.prototype, "nestedClasses", null);
    __decorate([
        lazy
    ], Class.prototype, "parent", null);
    __decorate([
        lazy
    ], Class.prototype, "rank", null);
    __decorate([
        lazy
    ], Class.prototype, "staticFieldsData", null);
    __decorate([
        lazy
    ], Class.prototype, "valueTypeSize", null);
    __decorate([
        lazy
    ], Class.prototype, "type", null);
    Class = __decorate([
        recycle
    ], Class);
    Il2Cpp.Class = Class;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    /** Creates a delegate object of the given delegate class. */
    function delegate(klass, block) {
        const SystemDelegate = Il2Cpp.corlib.class("System.Delegate");
        const SystemMulticastDelegate = Il2Cpp.corlib.class("System.MulticastDelegate");
        if (!SystemDelegate.isAssignableFrom(klass)) {
            raise(`cannot create a delegate for ${klass.type.name} as it's a non-delegate class`);
        }
        if (klass.equals(SystemDelegate) || klass.equals(SystemMulticastDelegate)) {
            raise(`cannot create a delegate for neither ${SystemDelegate.type.name} nor ${SystemMulticastDelegate.type.name}, use a subclass instead`);
        }
        const delegate = klass.alloc();
        const key = delegate.handle.toString();
        const Invoke = delegate.tryMethod("Invoke") ?? raise(`cannot create a delegate for ${klass.type.name}, there is no Invoke method`);
        delegate.method(".ctor").invoke(delegate, Invoke.handle);
        const callback = Invoke.wrap(block);
        delegate.field("method_ptr").value = callback;
        delegate.field("invoke_impl").value = callback;
        Il2Cpp._callbacksToKeepAlive[key] = callback;
        return delegate;
    }
    Il2Cpp.delegate = delegate;
    /** @internal Used to prevent eager garbage collection against NativeCallbacks. */
    Il2Cpp._callbacksToKeepAlive = {};
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    let Domain = class Domain extends NativeStruct {
        /** Gets the assemblies that have been loaded into the execution context of the application domain. */
        get assemblies() {
            let handles = readNativeList(_ => Il2Cpp.api.domainGetAssemblies(this, _));
            if (handles.length == 0) {
                const assemblyObjects = this.object.method("GetAssemblies").overload().invoke();
                handles = globalThis.Array.from(assemblyObjects).map(_ => _.field("_mono_assembly").value);
            }
            return handles.map(_ => new Il2Cpp.Assembly(_));
        }
        /** Gets the encompassing object of the application domain. */
        get object() {
            return Il2Cpp.corlib.class("System.AppDomain").method("get_CurrentDomain").invoke();
        }
        /** Opens and loads the assembly with the given name. */
        assembly(name) {
            return this.tryAssembly(name) ?? raise(`couldn't find assembly ${name}`);
        }
        /** Attached a new thread to the application domain. */
        attach() {
            return new Il2Cpp.Thread(Il2Cpp.api.threadAttach(this));
        }
        /** Opens and loads the assembly with the given name. */
        tryAssembly(name) {
            return new Il2Cpp.Assembly(Il2Cpp.api.domainGetAssemblyFromName(this, Memory.allocUtf8String(name))).asNullable();
        }
    };
    __decorate([
        lazy
    ], Domain.prototype, "assemblies", null);
    __decorate([
        lazy
    ], Domain.prototype, "object", null);
    Domain = __decorate([
        recycle
    ], Domain);
    Il2Cpp.Domain = Domain;
    // prettier-ignore
    getter(Il2Cpp, "domain", () => {
        return new Il2Cpp.Domain(Il2Cpp.api.domainGet());
    }, lazy);
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Field extends NativeStruct {
        /** Gets the class in which this field is defined. */
        get class() {
            return new Il2Cpp.Class(Il2Cpp.api.fieldGetClass(this));
        }
        /** Gets the flags of the current field. */
        get flags() {
            return Il2Cpp.api.fieldGetFlags(this);
        }
        /** Determines whether this field value is known at compile time. */
        get isLiteral() {
            return (this.flags & 64 /* Il2Cpp.Field.Attributes.Literal */) != 0;
        }
        /** Determines whether this field is static. */
        get isStatic() {
            return (this.flags & 16 /* Il2Cpp.Field.Attributes.Static */) != 0;
        }
        /** Determines whether this field is thread static. */
        get isThreadStatic() {
            const offset = Il2Cpp.corlib.class("System.AppDomain").field("type_resolve_in_progress").offset;
            // prettier-ignore
            getter(Il2Cpp.Field.prototype, "isThreadStatic", function () {
                return this.offset == offset;
            }, lazy);
            return this.isThreadStatic;
        }
        /** Gets the access modifier of this field. */
        get modifier() {
            switch (this.flags & 7 /* Il2Cpp.Field.Attributes.FieldAccessMask */) {
                case 1 /* Il2Cpp.Field.Attributes.Private */:
                    return "private";
                case 2 /* Il2Cpp.Field.Attributes.FamilyAndAssembly */:
                    return "private protected";
                case 3 /* Il2Cpp.Field.Attributes.Assembly */:
                    return "internal";
                case 4 /* Il2Cpp.Field.Attributes.Family */:
                    return "protected";
                case 5 /* Il2Cpp.Field.Attributes.FamilyOrAssembly */:
                    return "protected internal";
                case 6 /* Il2Cpp.Field.Attributes.Public */:
                    return "public";
            }
        }
        /** Gets the name of this field. */
        get name() {
            return Il2Cpp.api.fieldGetName(this).readUtf8String();
        }
        /** Gets the offset of this field, calculated as the difference with its owner virtual address. */
        get offset() {
            return Il2Cpp.api.fieldGetOffset(this);
        }
        /** Gets the type of this field. */
        get type() {
            return new Il2Cpp.Type(Il2Cpp.api.fieldGetType(this));
        }
        /** Gets the value of this field. */
        get value() {
            if (!this.isStatic) {
                raise(`cannot access instance field ${this.class.type.name}::${this.name} from a class, use an object instead`);
            }
            const handle = Memory.alloc(Process.pointerSize);
            Il2Cpp.api.fieldGetStaticValue(this.handle, handle);
            return Il2Cpp.read(handle, this.type);
        }
        /** Sets the value of this field. Thread static or literal values cannot be altered yet. */
        set value(value) {
            if (!this.isStatic) {
                raise(`cannot access instance field ${this.class.type.name}::${this.name} from a class, use an object instead`);
            }
            if (this.isThreadStatic || this.isLiteral) {
                raise(`cannot write the value of field ${this.name} as it's thread static or literal`);
            }
            const handle = 
            // pointer-like values should be passed as-is, but boxed
            // value types (primitives included) must be unboxed first
            value instanceof Il2Cpp.Object && this.type.class.isValueType
                ? value.unbox()
                : value instanceof NativeStruct
                    ? value.handle
                    : value instanceof NativePointer
                        ? value
                        : Il2Cpp.write(Memory.alloc(this.type.class.valueTypeSize), value, this.type);
            Il2Cpp.api.fieldSetStaticValue(this.handle, handle);
        }
        /** */
        toString() {
            return `\
${this.isThreadStatic ? `[ThreadStatic] ` : ``}\
${this.isStatic ? `static ` : ``}\
${this.type.name} \
${this.name}\
${this.isLiteral ? ` = ${this.type.class.isEnum ? Il2Cpp.read(this.value.handle, this.type.class.baseType) : this.value}` : ``};\
${this.isThreadStatic || this.isLiteral ? `` : ` // 0x${this.offset.toString(16)}`}`;
        }
        /** @internal */
        withHolder(instance) {
            if (this.isStatic) {
                raise(`cannot access static field ${this.class.type.name}::${this.name} from an object, use a class instead`);
            }
            const valueHandle = instance.handle.add(this.offset - (instance instanceof Il2Cpp.ValueType ? Il2Cpp.Object.headerSize : 0));
            return new Proxy(this, {
                get(target, property) {
                    if (property == "value") {
                        return Il2Cpp.read(valueHandle, target.type);
                    }
                    return Reflect.get(target, property);
                },
                set(target, property, value) {
                    if (property == "value") {
                        Il2Cpp.write(valueHandle, value, target.type);
                        return true;
                    }
                    return Reflect.set(target, property, value);
                }
            });
        }
    }
    __decorate([
        lazy
    ], Field.prototype, "class", null);
    __decorate([
        lazy
    ], Field.prototype, "flags", null);
    __decorate([
        lazy
    ], Field.prototype, "isLiteral", null);
    __decorate([
        lazy
    ], Field.prototype, "isStatic", null);
    __decorate([
        lazy
    ], Field.prototype, "isThreadStatic", null);
    __decorate([
        lazy
    ], Field.prototype, "modifier", null);
    __decorate([
        lazy
    ], Field.prototype, "name", null);
    __decorate([
        lazy
    ], Field.prototype, "offset", null);
    __decorate([
        lazy
    ], Field.prototype, "type", null);
    Il2Cpp.Field = Field;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class GCHandle {
        handle;
        /** @internal */
        constructor(handle) {
            this.handle = handle;
        }
        /** Gets the object associated to this handle. */
        get target() {
            return new Il2Cpp.Object(Il2Cpp.api.gcHandleGetTarget(this.handle)).asNullable();
        }
        /** Frees this handle. */
        free() {
            return Il2Cpp.api.gcHandleFree(this.handle);
        }
    }
    Il2Cpp.GCHandle = GCHandle;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    let Image = class Image extends NativeStruct {
        /** Gets the assembly in which the current image is defined. */
        get assembly() {
            return new Il2Cpp.Assembly(Il2Cpp.api.imageGetAssembly(this));
        }
        /** Gets the amount of classes defined in this image. */
        get classCount() {
            if (Il2Cpp.unityVersionIsBelow201830) {
                return this.classes.length;
            }
            else {
                return Il2Cpp.api.imageGetClassCount(this);
            }
        }
        /** Gets the classes defined in this image. */
        get classes() {
            if (Il2Cpp.unityVersionIsBelow201830) {
                const types = this.assembly.object.method("GetTypes").invoke(false);
                // In Unity 5.3.8f1, getting System.Reflection.Emit.OpCodes type name
                // without iterating all the classes first somehow blows things up at
                // app startup, hence the `Array.from`.
                const classes = globalThis.Array.from(types, _ => new Il2Cpp.Class(Il2Cpp.api.classFromObject(_)));
                classes.unshift(this.class("<Module>"));
                return classes;
            }
            else {
                return globalThis.Array.from(globalThis.Array(this.classCount), (_, i) => new Il2Cpp.Class(Il2Cpp.api.imageGetClass(this, i)));
            }
        }
        /** Gets the name of this image. */
        get name() {
            return Il2Cpp.api.imageGetName(this).readUtf8String();
        }
        /** Gets the class with the specified name defined in this image. */
        class(name) {
            return this.tryClass(name) ?? raise(`couldn't find class ${name} in assembly ${this.name}`);
        }
        /** Gets the class with the specified name defined in this image. */
        tryClass(name) {
            const dotIndex = name.lastIndexOf(".");
            const classNamespace = Memory.allocUtf8String(dotIndex == -1 ? "" : name.slice(0, dotIndex));
            const className = Memory.allocUtf8String(name.slice(dotIndex + 1));
            return new Il2Cpp.Class(Il2Cpp.api.classFromName(this, classNamespace, className)).asNullable();
        }
    };
    __decorate([
        lazy
    ], Image.prototype, "assembly", null);
    __decorate([
        lazy
    ], Image.prototype, "classCount", null);
    __decorate([
        lazy
    ], Image.prototype, "classes", null);
    __decorate([
        lazy
    ], Image.prototype, "name", null);
    Image = __decorate([
        recycle
    ], Image);
    Il2Cpp.Image = Image;
    // prettier-ignore
    getter(Il2Cpp, "corlib", () => {
        return new Il2Cpp.Image(Il2Cpp.api.getCorlib());
    }, lazy);
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class MemorySnapshot extends NativeStruct {
        /** Captures a memory snapshot. */
        static capture() {
            return new Il2Cpp.MemorySnapshot();
        }
        /** Creates a memory snapshot with the given handle. */
        constructor(handle = Il2Cpp.api.memorySnapshotCapture()) {
            super(handle);
        }
        /** Gets any initialized class. */
        get classes() {
            return readNativeIterator(_ => Il2Cpp.api.memorySnapshotGetClasses(this, _)).map(_ => new Il2Cpp.Class(_));
        }
        /** Gets the objects tracked by this memory snapshot. */
        get objects() {
            // prettier-ignore
            return readNativeList(_ => Il2Cpp.api.memorySnapshotGetObjects(this, _)).filter(_ => !_.isNull()).map(_ => new Il2Cpp.Object(_));
        }
        /** Frees this memory snapshot. */
        free() {
            Il2Cpp.api.memorySnapshotFree(this);
        }
    }
    __decorate([
        lazy
    ], MemorySnapshot.prototype, "classes", null);
    __decorate([
        lazy
    ], MemorySnapshot.prototype, "objects", null);
    Il2Cpp.MemorySnapshot = MemorySnapshot;
    /** */
    function memorySnapshot(block) {
        const memorySnapshot = Il2Cpp.MemorySnapshot.capture();
        const result = block(memorySnapshot);
        memorySnapshot.free();
        return result;
    }
    Il2Cpp.memorySnapshot = memorySnapshot;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Method extends NativeStruct {
        /** Gets the class in which this method is defined. */
        get class() {
            return new Il2Cpp.Class(Il2Cpp.api.methodGetClass(this));
        }
        /** Gets the flags of the current method. */
        get flags() {
            return Il2Cpp.api.methodGetFlags(this, NULL);
        }
        /** Gets the implementation flags of the current method. */
        get implementationFlags() {
            const implementationFlagsPointer = Memory.alloc(Process.pointerSize);
            Il2Cpp.api.methodGetFlags(this, implementationFlagsPointer);
            return implementationFlagsPointer.readU32();
        }
        /** */
        get fridaSignature() {
            const types = [];
            for (const parameter of this.parameters) {
                types.push(parameter.type.fridaAlias);
            }
            if (!this.isStatic || Il2Cpp.unityVersionIsBelow201830) {
                types.unshift("pointer");
            }
            if (this.isInflated) {
                types.push("pointer");
            }
            return types;
        }
        /** Gets the generic parameters of this generic method. */
        get generics() {
            if (!this.isGeneric && !this.isInflated) {
                return [];
            }
            const types = this.object.method("GetGenericArguments").invoke();
            return globalThis.Array.from(types).map(_ => new Il2Cpp.Class(Il2Cpp.api.classFromObject(_)));
        }
        /** Determines whether this method is external. */
        get isExternal() {
            return (this.implementationFlags & 4096 /* Il2Cpp.Method.ImplementationAttribute.InternalCall */) != 0;
        }
        /** Determines whether this method is generic. */
        get isGeneric() {
            return !!Il2Cpp.api.methodIsGeneric(this);
        }
        /** Determines whether this method is inflated (generic with a concrete type parameter). */
        get isInflated() {
            return !!Il2Cpp.api.methodIsInflated(this);
        }
        /** Determines whether this method is static. */
        get isStatic() {
            return !Il2Cpp.api.methodIsInstance(this);
        }
        /** Determines whether this method is synchronized. */
        get isSynchronized() {
            return (this.implementationFlags & 32 /* Il2Cpp.Method.ImplementationAttribute.Synchronized */) != 0;
        }
        /** Gets the access modifier of this method. */
        get modifier() {
            switch (this.flags & 7 /* Il2Cpp.Method.Attributes.MemberAccessMask */) {
                case 1 /* Il2Cpp.Method.Attributes.Private */:
                    return "private";
                case 2 /* Il2Cpp.Method.Attributes.FamilyAndAssembly */:
                    return "private protected";
                case 3 /* Il2Cpp.Method.Attributes.Assembly */:
                    return "internal";
                case 4 /* Il2Cpp.Method.Attributes.Family */:
                    return "protected";
                case 5 /* Il2Cpp.Method.Attributes.FamilyOrAssembly */:
                    return "protected internal";
                case 6 /* Il2Cpp.Method.Attributes.Public */:
                    return "public";
            }
        }
        /** Gets the name of this method. */
        get name() {
            return Il2Cpp.api.methodGetName(this).readUtf8String();
        }
        /** @internal */
        get nativeFunction() {
            return new NativeFunction(this.virtualAddress, this.returnType.fridaAlias, this.fridaSignature);
        }
        /** Gets the encompassing object of the current method. */
        get object() {
            return new Il2Cpp.Object(Il2Cpp.api.methodGetObject(this, NULL));
        }
        /** Gets the amount of parameters of this method. */
        get parameterCount() {
            return Il2Cpp.api.methodGetParameterCount(this);
        }
        /** Gets the parameters of this method. */
        get parameters() {
            return globalThis.Array.from(globalThis.Array(this.parameterCount), (_, i) => {
                const parameterName = Il2Cpp.api.methodGetParameterName(this, i).readUtf8String();
                const parameterType = Il2Cpp.api.methodGetParameterType(this, i);
                return new Il2Cpp.Parameter(parameterName, i, new Il2Cpp.Type(parameterType));
            });
        }
        /** Gets the relative virtual address (RVA) of this method. */
        get relativeVirtualAddress() {
            return this.virtualAddress.sub(Il2Cpp.module.base);
        }
        /** Gets the return type of this method. */
        get returnType() {
            return new Il2Cpp.Type(Il2Cpp.api.methodGetReturnType(this));
        }
        /** Gets the virtual address (VA) of this method. */
        get virtualAddress() {
            const FilterTypeName = Il2Cpp.corlib.class("System.Reflection.Module").initialize().field("FilterTypeName").value;
            const FilterTypeNameMethodPointer = FilterTypeName.field("method_ptr").value;
            const FilterTypeNameMethod = FilterTypeName.field("method").value;
            // prettier-ignore
            const offset = FilterTypeNameMethod.offsetOf(_ => _.readPointer().equals(FilterTypeNameMethodPointer))
                ?? raise("couldn't find the virtual address offset in the native method struct");
            // prettier-ignore
            getter(Il2Cpp.Method.prototype, "virtualAddress", function () {
                return this.handle.add(offset).readPointer();
            }, lazy);
            // In Unity 2017.4.40f1 (don't know about others),
            // `Il2Cpp.Class::initialize` somehow triggers a nasty bug during
            // early instrumentation, so that we aren't able to obtain the
            // offset to get the virtual address of a method when the script
            // is reloaded. A workaround consists in manually re-invoking the
            // static constructor.
            Il2Cpp.corlib.class("System.Reflection.Module").method(".cctor").invoke();
            return this.virtualAddress;
        }
        /** Replaces the body of this method. */
        set implementation(block) {
            try {
                Interceptor.replace(this.virtualAddress, this.wrap(block));
            }
            catch (e) {
                switch (e.message) {
                    case "access violation accessing 0x0":
                        raise(`couldn't set implementation for method ${this.name} as it has a NULL virtual address`);
                    case /unable to intercept function at \w+; please file a bug/.exec(e.message)?.input:
                        warn(`couldn't set implementation for method ${this.name} as it may be a thunk`);
                        break;
                    case "already replaced this function":
                        warn(`couldn't set implementation for method ${this.name} as it has already been replaced by a thunk`);
                        break;
                    default:
                        throw e;
                }
            }
        }
        /** Creates a generic instance of the current generic method. */
        inflate(...classes) {
            if (!this.isGeneric) {
                raise(`cannot inflate method ${this.name} as it has no generic parameters`);
            }
            if (this.generics.length != classes.length) {
                raise(`cannot inflate method ${this.name} as it needs ${this.generics.length} generic parameter(s), not ${classes.length}`);
            }
            const types = classes.map(_ => _.type.object);
            const typeArray = Il2Cpp.array(Il2Cpp.corlib.class("System.Type"), types);
            const inflatedMethodObject = this.object.method("MakeGenericMethod", 1).invoke(typeArray);
            return new Il2Cpp.Method(inflatedMethodObject.field("mhandle").value);
        }
        /** Invokes this method. */
        invoke(...parameters) {
            if (!this.isStatic) {
                raise(`cannot invoke non-static method ${this.name} as it must be invoked throught a Il2Cpp.Object, not a Il2Cpp.Class`);
            }
            return this.invokeRaw(NULL, ...parameters);
        }
        /** @internal */
        invokeRaw(instance, ...parameters) {
            const allocatedParameters = parameters.map(Il2Cpp.toFridaValue);
            if (!this.isStatic || Il2Cpp.unityVersionIsBelow201830) {
                allocatedParameters.unshift(instance);
            }
            if (this.isInflated) {
                allocatedParameters.push(this.handle);
            }
            try {
                const returnValue = this.nativeFunction(...allocatedParameters);
                return Il2Cpp.fromFridaValue(returnValue, this.returnType);
            }
            catch (e) {
                if (e == null) {
                    raise("an unexpected native invocation exception occurred, this is due to parameter types mismatch");
                }
                switch (e.message) {
                    case "bad argument count":
                        raise(`couldn't invoke method ${this.name} as it needs ${this.parameterCount} parameter(s), not ${parameters.length}`);
                    case "expected a pointer":
                    case "expected number":
                    case "expected array with fields":
                        raise(`couldn't invoke method ${this.name} using incorrect parameter types`);
                }
                throw e;
            }
        }
        /** Gets the overloaded method with the given parameter types. */
        overload(...parameterTypes) {
            const result = this.tryOverload(...parameterTypes);
            if (result != undefined)
                return result;
            raise(`couldn't find overloaded method ${this.name}(${parameterTypes})`);
        }
        /** Gets the parameter with the given name. */
        parameter(name) {
            return this.tryParameter(name) ?? raise(`couldn't find parameter ${name} in method ${this.name}`);
        }
        /** Restore the original method implementation. */
        revert() {
            Interceptor.revert(this.virtualAddress);
            Interceptor.flush();
        }
        /** Gets the overloaded method with the given parameter types. */
        tryOverload(...parameterTypes) {
            let klass = this.class;
            while (klass) {
                const method = klass.methods.find(method => {
                    return (method.name == this.name &&
                        method.parameterCount == parameterTypes.length &&
                        method.parameters.every((e, i) => e.type.name == parameterTypes[i]));
                });
                if (method) {
                    return method;
                }
                klass = klass.parent;
            }
            return undefined;
        }
        /** Gets the parameter with the given name. */
        tryParameter(name) {
            return this.parameters.find(_ => _.name == name);
        }
        /** */
        toString() {
            return `\
${this.isStatic ? `static ` : ``}\
${this.returnType.name} \
${this.name}\
(${this.parameters.join(`, `)});\
${this.virtualAddress.isNull() ? `` : ` // 0x${this.relativeVirtualAddress.toString(16).padStart(8, `0`)}`}`;
        }
        /** @internal */
        withHolder(instance) {
            if (this.isStatic) {
                raise(`cannot access static method ${this.class.type.name}::${this.name} from an object, use a class instead`);
            }
            return new Proxy(this, {
                get(target, property) {
                    switch (property) {
                        case "invoke":
                            // In Unity 5.3.5f1 and >= 2021.2.0f1, value types
                            // methods may assume their `this` parameter is a
                            // pointer to raw data (that is how value types are
                            // layed out in memory) instead of a pointer to an
                            // object (that is object header + raw data).
                            // In any case, they also don't use whatever there
                            // is in the object header, so we can safely "skip"
                            // the object header by adding the object header
                            // size to the object (a boxed value type) handle.
                            const handle = instance instanceof Il2Cpp.ValueType
                                ? target.class.isValueType
                                    ? instance.handle.add(maybeObjectHeaderSize() - Il2Cpp.Object.headerSize)
                                    : raise(`cannot invoke method ${target.class.type.name}::${target.name} against a value type, you must box it first`)
                                : target.class.isValueType
                                    ? instance.handle.add(maybeObjectHeaderSize())
                                    : instance.handle;
                            return target.invokeRaw.bind(target, handle);
                        case "inflate":
                        case "overload":
                        case "tryOverload":
                            return function (...args) {
                                return target[property](...args)?.withHolder(instance);
                            };
                    }
                    return Reflect.get(target, property);
                }
            });
        }
        /** @internal */
        wrap(block) {
            const startIndex = +!this.isStatic | +Il2Cpp.unityVersionIsBelow201830;
            return new NativeCallback((...args) => {
                const thisObject = this.isStatic
                    ? this.class
                    : this.class.isValueType
                        ? new Il2Cpp.ValueType(args[0].add(Il2Cpp.Object.headerSize - maybeObjectHeaderSize()), this.class.type)
                        : new Il2Cpp.Object(args[0]);
                const parameters = this.parameters.map((_, i) => Il2Cpp.fromFridaValue(args[i + startIndex], _.type));
                const result = block.call(thisObject, ...parameters);
                return Il2Cpp.toFridaValue(result);
            }, this.returnType.fridaAlias, this.fridaSignature);
        }
    }
    __decorate([
        lazy
    ], Method.prototype, "class", null);
    __decorate([
        lazy
    ], Method.prototype, "flags", null);
    __decorate([
        lazy
    ], Method.prototype, "implementationFlags", null);
    __decorate([
        lazy
    ], Method.prototype, "fridaSignature", null);
    __decorate([
        lazy
    ], Method.prototype, "generics", null);
    __decorate([
        lazy
    ], Method.prototype, "isExternal", null);
    __decorate([
        lazy
    ], Method.prototype, "isGeneric", null);
    __decorate([
        lazy
    ], Method.prototype, "isInflated", null);
    __decorate([
        lazy
    ], Method.prototype, "isStatic", null);
    __decorate([
        lazy
    ], Method.prototype, "isSynchronized", null);
    __decorate([
        lazy
    ], Method.prototype, "modifier", null);
    __decorate([
        lazy
    ], Method.prototype, "name", null);
    __decorate([
        lazy
    ], Method.prototype, "nativeFunction", null);
    __decorate([
        lazy
    ], Method.prototype, "object", null);
    __decorate([
        lazy
    ], Method.prototype, "parameterCount", null);
    __decorate([
        lazy
    ], Method.prototype, "parameters", null);
    __decorate([
        lazy
    ], Method.prototype, "relativeVirtualAddress", null);
    __decorate([
        lazy
    ], Method.prototype, "returnType", null);
    Il2Cpp.Method = Method;
    let maybeObjectHeaderSize = () => {
        const struct = Il2Cpp.corlib.class("System.RuntimeTypeHandle").initialize().alloc();
        struct.method(".ctor").invokeRaw(struct, ptr(0xdeadbeef));
        // Here we check where the sentinel value is
        // if it's not where it is supposed to be, it means struct methods
        // assume they are receiving value types (that is a pointer to raw data)
        // hence, we must "skip" the object header when invoking such methods.
        const offset = struct.field("value").value.equals(ptr(0xdeadbeef)) ? 0 : Il2Cpp.Object.headerSize;
        return (maybeObjectHeaderSize = () => offset)();
    };
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Object extends NativeStruct {
        /** Gets the Il2CppObject struct size, possibly equal to `Process.pointerSize * 2`. */
        static get headerSize() {
            return Il2Cpp.corlib.class("System.Object").instanceSize;
        }
        /** Gets the class of this object. */
        get class() {
            return new Il2Cpp.Class(Il2Cpp.api.objectGetClass(this));
        }
        /** Returns a monitor for this object. */
        get monitor() {
            return new Il2Cpp.Object.Monitor(this);
        }
        /** Gets the size of the current object. */
        get size() {
            return Il2Cpp.api.objectGetSize(this);
        }
        /** Gets the field with the given name. */
        field(name) {
            return this.class.field(name).withHolder(this);
        }
        /** Gets the method with the given name. */
        method(name, parameterCount = -1) {
            return this.class.method(name, parameterCount).withHolder(this);
        }
        /** Creates a reference to this object. */
        ref(pin) {
            return new Il2Cpp.GCHandle(Il2Cpp.api.gcHandleNew(this, +pin));
        }
        /** Gets the correct virtual method from the given virtual method. */
        virtualMethod(method) {
            return new Il2Cpp.Method(Il2Cpp.api.objectGetVirtualMethod(this, method)).withHolder(this);
        }
        /** Gets the field with the given name. */
        tryField(name) {
            return this.class.tryField(name)?.withHolder(this);
        }
        /** Gets the field with the given name. */
        tryMethod(name, parameterCount = -1) {
            return this.class.tryMethod(name, parameterCount)?.withHolder(this);
        }
        /** */
        toString() {
            return this.isNull() ? "null" : this.method("ToString", 0).invoke().content ?? "null";
        }
        /** Unboxes the value type (either a primitive, a struct or an enum) out of this object. */
        unbox() {
            return this.class.isValueType
                ? new Il2Cpp.ValueType(Il2Cpp.api.objectUnbox(this), this.class.type)
                : raise(`couldn't unbox instances of ${this.class.type.name} as they are not value types`);
        }
        /** Creates a weak reference to this object. */
        weakRef(trackResurrection) {
            return new Il2Cpp.GCHandle(Il2Cpp.api.gcHandleNewWeakRef(this, +trackResurrection));
        }
    }
    __decorate([
        lazy
    ], Object.prototype, "class", null);
    __decorate([
        lazy
    ], Object.prototype, "size", null);
    __decorate([
        lazy
    ], Object, "headerSize", null);
    Il2Cpp.Object = Object;
    (function (Object) {
        class Monitor {
            handle;
            /** @internal */
            constructor(/** @internal */ handle) {
                this.handle = handle;
            }
            /** Acquires an exclusive lock on the current object. */
            enter() {
                return Il2Cpp.api.monitorEnter(this.handle);
            }
            /** Release an exclusive lock on the current object. */
            exit() {
                return Il2Cpp.api.monitorExit(this.handle);
            }
            /** Notifies a thread in the waiting queue of a change in the locked object's state. */
            pulse() {
                return Il2Cpp.api.monitorPulse(this.handle);
            }
            /** Notifies all waiting threads of a change in the object's state. */
            pulseAll() {
                return Il2Cpp.api.monitorPulseAll(this.handle);
            }
            /** Attempts to acquire an exclusive lock on the current object. */
            tryEnter(timeout) {
                return !!Il2Cpp.api.monitorTryEnter(this.handle, timeout);
            }
            /** Releases the lock on an object and attempts to block the current thread until it reacquires the lock. */
            tryWait(timeout) {
                return !!Il2Cpp.api.monitorTryWait(this.handle, timeout);
            }
            /** Releases the lock on an object and blocks the current thread until it reacquires the lock. */
            wait() {
                return Il2Cpp.api.monitorWait(this.handle);
            }
        }
        Object.Monitor = Monitor;
    })(Object = Il2Cpp.Object || (Il2Cpp.Object = {}));
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Parameter {
        /** Name of this parameter. */
        name;
        /** Position of this parameter. */
        position;
        /** Type of this parameter. */
        type;
        constructor(name, position, type) {
            this.name = name;
            this.position = position;
            this.type = type;
        }
        /** */
        toString() {
            return `${this.type.name} ${this.name}`;
        }
    }
    Il2Cpp.Parameter = Parameter;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Pointer extends NativeStruct {
        type;
        constructor(handle, type) {
            super(handle);
            this.type = type;
        }
        /** Gets the element at the given index. */
        get(index) {
            return Il2Cpp.read(this.handle.add(index * this.type.class.arrayElementSize), this.type);
        }
        /** Reads the given amount of elements starting at the given offset. */
        read(length, offset = 0) {
            const values = new globalThis.Array(length);
            for (let i = 0; i < length; i++) {
                values[i] = this.get(i + offset);
            }
            return values;
        }
        /** Sets the given element at the given index */
        set(index, value) {
            Il2Cpp.write(this.handle.add(index * this.type.class.arrayElementSize), value, this.type);
        }
        /** */
        toString() {
            return this.handle.toString();
        }
        /** Writes the given elements starting at the given index. */
        write(values, offset = 0) {
            for (let i = 0; i < values.length; i++) {
                this.set(i + offset, values[i]);
            }
        }
    }
    Il2Cpp.Pointer = Pointer;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Reference extends NativeStruct {
        type;
        constructor(handle, type) {
            super(handle);
            this.type = type;
        }
        /** Gets the element referenced by the current reference. */
        get value() {
            return Il2Cpp.read(this.handle, this.type);
        }
        /** Sets the element referenced by the current reference. */
        set value(value) {
            Il2Cpp.write(this.handle, value, this.type);
        }
        /** */
        toString() {
            return this.isNull() ? "null" : `->${this.value}`;
        }
    }
    Il2Cpp.Reference = Reference;
    /** Creates a reference to the specified value. */
    function reference(value, type) {
        const handle = Memory.alloc(Process.pointerSize);
        switch (typeof value) {
            case "boolean":
                return new Il2Cpp.Reference(handle.writeS8(+value), Il2Cpp.corlib.class("System.Boolean").type);
            case "number":
                switch (type?.typeEnum) {
                    case Il2Cpp.Type.enum.unsignedByte:
                        return new Il2Cpp.Reference(handle.writeU8(value), type);
                    case Il2Cpp.Type.enum.byte:
                        return new Il2Cpp.Reference(handle.writeS8(value), type);
                    case Il2Cpp.Type.enum.char:
                    case Il2Cpp.Type.enum.unsignedShort:
                        return new Il2Cpp.Reference(handle.writeU16(value), type);
                    case Il2Cpp.Type.enum.short:
                        return new Il2Cpp.Reference(handle.writeS16(value), type);
                    case Il2Cpp.Type.enum.unsignedInt:
                        return new Il2Cpp.Reference(handle.writeU32(value), type);
                    case Il2Cpp.Type.enum.int:
                        return new Il2Cpp.Reference(handle.writeS32(value), type);
                    case Il2Cpp.Type.enum.unsignedLong:
                        return new Il2Cpp.Reference(handle.writeU64(value), type);
                    case Il2Cpp.Type.enum.long:
                        return new Il2Cpp.Reference(handle.writeS64(value), type);
                    case Il2Cpp.Type.enum.float:
                        return new Il2Cpp.Reference(handle.writeFloat(value), type);
                    case Il2Cpp.Type.enum.double:
                        return new Il2Cpp.Reference(handle.writeDouble(value), type);
                }
            case "object":
                if (value instanceof Il2Cpp.ValueType || value instanceof Il2Cpp.Pointer) {
                    return new Il2Cpp.Reference(value.handle, value.type);
                }
                else if (value instanceof Il2Cpp.Object) {
                    return new Il2Cpp.Reference(handle.writePointer(value), value.class.type);
                }
                else if (value instanceof Il2Cpp.String || value instanceof Il2Cpp.Array) {
                    return new Il2Cpp.Reference(handle.writePointer(value), value.object.class.type);
                }
                else if (value instanceof NativePointer) {
                    switch (type?.typeEnum) {
                        case Il2Cpp.Type.enum.unsignedNativePointer:
                        case Il2Cpp.Type.enum.nativePointer:
                            return new Il2Cpp.Reference(handle.writePointer(value), type);
                    }
                }
                else if (value instanceof Int64) {
                    return new Il2Cpp.Reference(handle.writeS64(value), Il2Cpp.corlib.class("System.Int64").type);
                }
                else if (value instanceof UInt64) {
                    return new Il2Cpp.Reference(handle.writeU64(value), Il2Cpp.corlib.class("System.UInt64").type);
                }
            default:
                raise(`couldn't create a reference to ${value} using an unhandled type ${type?.name}`);
        }
    }
    Il2Cpp.reference = reference;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class String extends NativeStruct {
        /** Gets the content of this string. */
        get content() {
            return Il2Cpp.api.stringGetChars(this).readUtf16String(this.length);
        }
        /** @unsafe Sets the content of this string - it may write out of bounds! */
        set content(value) {
            // prettier-ignore
            const offset = Il2Cpp.string("vfsfitvnm").handle.offsetOf(_ => _.readInt() == 9)
                ?? raise("couldn't find the length offset in the native string struct");
            globalThis.Object.defineProperty(Il2Cpp.String.prototype, "content", {
                set(value) {
                    Il2Cpp.api.stringGetChars(this).writeUtf16String(value ?? "");
                    this.handle.add(offset).writeS32(value?.length ?? 0);
                }
            });
            this.content = value;
        }
        /** Gets the length of this string. */
        get length() {
            return Il2Cpp.api.stringGetLength(this);
        }
        /** Gets the encompassing object of the current string. */
        get object() {
            return new Il2Cpp.Object(this);
        }
        /** */
        toString() {
            return this.isNull() ? "null" : `"${this.content}"`;
        }
    }
    Il2Cpp.String = String;
    /** Creates a new string with the specified content. */
    function string(content) {
        return new Il2Cpp.String(Il2Cpp.api.stringNew(Memory.allocUtf8String(content ?? "")));
    }
    Il2Cpp.string = string;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class Thread extends NativeStruct {
        /** Gets the native id of the current thread. */
        get id() {
            let get = function () {
                return this.internal.field("thread_id").value.toNumber();
            };
            // https://github.com/mono/linux-packaging-mono/blob/d586f84dfea30217f34b076a616a098518aa72cd/mono/utils/mono-threads.h#L642
            if (Process.platform != "windows") {
                const currentThreadId = Process.getCurrentThreadId();
                const currentPosixThread = ptr(get.apply(Il2Cpp.currentThread));
                // prettier-ignore
                const offset = currentPosixThread.offsetOf(_ => _.readS32() == currentThreadId, 1024) ??
                    raise(`couldn't find the offset for determining the kernel id of a posix thread`);
                const _get = get;
                get = function () {
                    return ptr(_get.apply(this)).add(offset).readS32();
                };
            }
            getter(Il2Cpp.Thread.prototype, "id", get, lazy);
            return this.id;
        }
        /** Gets the encompassing internal object (System.Threding.InternalThreead) of the current thread. */
        get internal() {
            return this.object.tryField("internal_thread")?.value ?? this.object;
        }
        /** Determines whether the current thread is the garbage collector finalizer one. */
        get isFinalizer() {
            return !Il2Cpp.api.threadIsVm(this);
        }
        /** Gets the managed id of the current thread. */
        get managedId() {
            return this.object.method("get_ManagedThreadId").invoke();
        }
        /** Gets the encompassing object of the current thread. */
        get object() {
            return new Il2Cpp.Object(this);
        }
        /** @internal */
        get staticData() {
            return this.internal.field("static_data").value;
        }
        /** @internal */
        get synchronizationContext() {
            const get_ExecutionContext = this.object.tryMethod("GetMutableExecutionContext") ?? this.object.method("get_ExecutionContext");
            const executionContext = get_ExecutionContext.invoke();
            let synchronizationContext = executionContext.tryField("_syncContext")?.value ??
                executionContext.tryMethod("get_SynchronizationContext")?.invoke() ??
                this.tryLocalValue(Il2Cpp.corlib.class("System.Threading.SynchronizationContext"));
            if (synchronizationContext == null || synchronizationContext.isNull()) {
                if (this.handle.equals(Il2Cpp.mainThread.handle)) {
                    raise(`couldn't find the synchronization context of the main thread, perhaps this is early instrumentation?`);
                }
                else {
                    raise(`couldn't find the synchronization context of thread #${this.managedId}, only the main thread is expected to have one`);
                }
            }
            return synchronizationContext;
        }
        /** Detaches the thread from the application domain. */
        detach() {
            return Il2Cpp.api.threadDetach(this);
        }
        /** Schedules a callback on the current thread. */
        schedule(block) {
            const Post = this.synchronizationContext.method("Post");
            return new Promise(resolve => {
                const delegate = Il2Cpp.delegate(Il2Cpp.corlib.class("System.Threading.SendOrPostCallback"), () => {
                    const result = block();
                    setImmediate(() => resolve(result));
                });
                // This is to replace pending scheduled callbacks when the script is about to get unlaoded.
                // If we skip this cleanup, Frida's native callbacks will point to invalid memory, making
                // the application crash as soon as the IL2CPP runtime tries to execute such callbacks.
                // For instance, without the following code, this is how you can trigger a crash:
                // 1) unfocus the application;
                // 2) schedule a callback;
                // 3) reload the script;
                // 4) focus application.
                //
                // The "proper" solution consists in removing our delegates from the Unity synchroniztion
                // context, but the interface is not consisent across Unity versions - e.g. 2017.4.40f1 uses
                // a queue instead of a list, whereas newer versions do not allow null work requests.
                // The following solution, which basically redirects the invocation to a native function that
                // survives the script reloading, is much simpler, honestly.
                Script.bindWeak(globalThis, () => {
                    delegate.field("method_ptr").value = delegate.field("invoke_impl").value = Il2Cpp.api.domainGet;
                });
                Post.invoke(delegate, NULL);
            });
        }
        /** @internal */
        tryLocalValue(klass) {
            for (let i = 0; i < 16; i++) {
                const base = this.staticData.add(i * Process.pointerSize).readPointer();
                if (!base.isNull()) {
                    const object = new Il2Cpp.Object(base.readPointer()).asNullable();
                    if (object?.class?.isSubclassOf(klass, false)) {
                        return object;
                    }
                }
            }
        }
    }
    __decorate([
        lazy
    ], Thread.prototype, "internal", null);
    __decorate([
        lazy
    ], Thread.prototype, "isFinalizer", null);
    __decorate([
        lazy
    ], Thread.prototype, "managedId", null);
    __decorate([
        lazy
    ], Thread.prototype, "object", null);
    __decorate([
        lazy
    ], Thread.prototype, "staticData", null);
    __decorate([
        lazy
    ], Thread.prototype, "synchronizationContext", null);
    Il2Cpp.Thread = Thread;
    getter(Il2Cpp, "attachedThreads", () => {
        return readNativeList(Il2Cpp.api.threadGetAttachedThreads).map(_ => new Il2Cpp.Thread(_));
    });
    getter(Il2Cpp, "currentThread", () => {
        return new Il2Cpp.Thread(Il2Cpp.api.threadGetCurrent()).asNullable();
    });
    getter(Il2Cpp, "mainThread", () => {
        // I'm not sure if this is always the case. Typically, the main
        // thread managed id is 1, but this isn't always true: spawning
        // an Android application with Unity 5.3.8f1 will cause the Frida
        // thread to have the managed id equal to 1, whereas the main thread
        // managed id is 2.
        return Il2Cpp.attachedThreads[0];
    });
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    let Type = class Type extends NativeStruct {
        /** */
        static get enum() {
            const _ = (_, block = (_) => _) => block(Il2Cpp.corlib.class(_)).type.typeEnum;
            return {
                void: _("System.Void"),
                boolean: _("System.Boolean"),
                char: _("System.Char"),
                byte: _("System.SByte"),
                unsignedByte: _("System.Byte"),
                short: _("System.Int16"),
                unsignedShort: _("System.UInt16"),
                int: _("System.Int32"),
                unsignedInt: _("System.UInt32"),
                long: _("System.Int64"),
                unsignedLong: _("System.UInt64"),
                nativePointer: _("System.IntPtr"),
                unsignedNativePointer: _("System.UIntPtr"),
                float: _("System.Single"),
                double: _("System.Double"),
                pointer: _("System.IntPtr", _ => _.field("m_value")),
                valueType: _("System.Decimal"),
                object: _("System.Object"),
                string: _("System.String"),
                class: _("System.Array"),
                array: _("System.Void", _ => _.arrayClass),
                multidimensionalArray: _("System.Void", _ => new Il2Cpp.Class(Il2Cpp.api.classGetArrayClass(_, 2))),
                genericInstance: _("System.Int32", _ => _.interfaces.find(_ => _.name.endsWith("`1")))
            };
        }
        /** Gets the class of this type. */
        get class() {
            return new Il2Cpp.Class(Il2Cpp.api.typeGetClass(this));
        }
        /** */
        get fridaAlias() {
            function getValueTypeFields(type) {
                const instanceFields = type.class.fields.filter(_ => !_.isStatic);
                return instanceFields.length == 0 ? ["char"] : instanceFields.map(_ => _.type.fridaAlias);
            }
            if (this.isByReference) {
                return "pointer";
            }
            switch (this.typeEnum) {
                case Il2Cpp.Type.enum.void:
                    return "void";
                case Il2Cpp.Type.enum.boolean:
                    return "bool";
                case Il2Cpp.Type.enum.char:
                    return "uchar";
                case Il2Cpp.Type.enum.byte:
                    return "int8";
                case Il2Cpp.Type.enum.unsignedByte:
                    return "uint8";
                case Il2Cpp.Type.enum.short:
                    return "int16";
                case Il2Cpp.Type.enum.unsignedShort:
                    return "uint16";
                case Il2Cpp.Type.enum.int:
                    return "int32";
                case Il2Cpp.Type.enum.unsignedInt:
                    return "uint32";
                case Il2Cpp.Type.enum.long:
                    return "int64";
                case Il2Cpp.Type.enum.unsignedLong:
                    return "uint64";
                case Il2Cpp.Type.enum.float:
                    return "float";
                case Il2Cpp.Type.enum.double:
                    return "double";
                case Il2Cpp.Type.enum.nativePointer:
                case Il2Cpp.Type.enum.unsignedNativePointer:
                case Il2Cpp.Type.enum.pointer:
                case Il2Cpp.Type.enum.string:
                case Il2Cpp.Type.enum.array:
                case Il2Cpp.Type.enum.multidimensionalArray:
                    return "pointer";
                case Il2Cpp.Type.enum.valueType:
                    return this.class.isEnum ? this.class.baseType.fridaAlias : getValueTypeFields(this);
                case Il2Cpp.Type.enum.class:
                case Il2Cpp.Type.enum.object:
                case Il2Cpp.Type.enum.genericInstance:
                    return this.class.isStruct ? getValueTypeFields(this) : this.class.isEnum ? this.class.baseType.fridaAlias : "pointer";
                default:
                    return "pointer";
            }
        }
        /** Determines whether this type is passed by reference. */
        get isByReference() {
            return this.name.endsWith("&");
        }
        /** Determines whether this type is primitive. */
        get isPrimitive() {
            switch (this.typeEnum) {
                case Il2Cpp.Type.enum.boolean:
                case Il2Cpp.Type.enum.char:
                case Il2Cpp.Type.enum.byte:
                case Il2Cpp.Type.enum.unsignedByte:
                case Il2Cpp.Type.enum.short:
                case Il2Cpp.Type.enum.unsignedShort:
                case Il2Cpp.Type.enum.int:
                case Il2Cpp.Type.enum.unsignedInt:
                case Il2Cpp.Type.enum.long:
                case Il2Cpp.Type.enum.unsignedLong:
                case Il2Cpp.Type.enum.float:
                case Il2Cpp.Type.enum.double:
                case Il2Cpp.Type.enum.nativePointer:
                case Il2Cpp.Type.enum.unsignedNativePointer:
                    return true;
                default:
                    return false;
            }
        }
        /** Gets the name of this type. */
        get name() {
            const handle = Il2Cpp.api.typeGetName(this);
            try {
                return handle.readUtf8String();
            }
            finally {
                Il2Cpp.free(handle);
            }
        }
        /** Gets the encompassing object of the current type. */
        get object() {
            return new Il2Cpp.Object(Il2Cpp.api.typeGetObject(this));
        }
        /** Gets the type enum of the current type. */
        get typeEnum() {
            return Il2Cpp.api.typeGetTypeEnum(this);
        }
        /** */
        toString() {
            return this.name;
        }
    };
    __decorate([
        lazy
    ], Type.prototype, "class", null);
    __decorate([
        lazy
    ], Type.prototype, "fridaAlias", null);
    __decorate([
        lazy
    ], Type.prototype, "isByReference", null);
    __decorate([
        lazy
    ], Type.prototype, "isPrimitive", null);
    __decorate([
        lazy
    ], Type.prototype, "name", null);
    __decorate([
        lazy
    ], Type.prototype, "object", null);
    __decorate([
        lazy
    ], Type.prototype, "typeEnum", null);
    __decorate([
        lazy
    ], Type, "enum", null);
    Type = __decorate([
        recycle
    ], Type);
    Il2Cpp.Type = Type;
})(Il2Cpp || (Il2Cpp = {}));
var Il2Cpp;
(function (Il2Cpp) {
    class ValueType extends NativeStruct {
        type;
        constructor(handle, type) {
            super(handle);
            this.type = type;
        }
        /** Boxes the current value type in a object. */
        box() {
            return new Il2Cpp.Object(Il2Cpp.api.valueTypeBox(this.type.class, this));
        }
        /** Gets the field with the given name. */
        field(name) {
            return this.type.class.field(name).withHolder(this);
        }
        /** Gets the method with the given name. */
        method(name, parameterCount = -1) {
            return this.type.class.method(name, parameterCount).withHolder(this);
        }
        /** Gets the field with the given name. */
        tryField(name) {
            return this.type.class.tryField(name)?.withHolder(this);
        }
        /** Gets the field with the given name. */
        tryMethod(name, parameterCount = -1) {
            return this.type.class.tryMethod(name, parameterCount)?.withHolder(this);
        }
        /** */
        toString() {
            const ToString = this.method("ToString", 0);
            return this.isNull()
                ? "null"
                : // If ToString is defined within a value type class, we can
                    // avoid a boxing operation.
                    ToString.class.isValueType
                        ? ToString.invoke().content ?? "null"
                        : this.box().toString() ?? "null";
        }
    }
    Il2Cpp.ValueType = ValueType;
})(Il2Cpp || (Il2Cpp = {}));
/// <reference path="./utils/android.ts">/>
/// <reference path="./utils/console.ts">/>
/// <reference path="./utils/decorate.ts">/>
/// <reference path="./utils/getter.ts">/>
/// <reference path="./utils/lazy.ts">/>
/// <reference path="./utils/native-struct.ts">/>
/// <reference path="./utils/native-wait.ts">/>
/// <reference path="./utils/offset-of.ts">/>
/// <reference path="./utils/read-native-iterator.ts">/>
/// <reference path="./utils/read-native-list.ts">/>
/// <reference path="./utils/recycle.ts">/>
/// <reference path="./utils/unity-version.ts">/>
/// <reference path="./api.ts">/>
/// <reference path="./application.ts">/>
/// <reference path="./dump.ts">/>
/// <reference path="./exception-listener.ts">/>
/// <reference path="./filters.ts">/>
/// <reference path="./gc.ts">/>
/// <reference path="./memory.ts">/>
/// <reference path="./module.ts">/>
/// <reference path="./perform.ts">/>
/// <reference path="./tracer.ts">/>
/// <reference path="./structs/array.ts">/>
/// <reference path="./structs/assembly.ts">/>
/// <reference path="./structs/class.ts">/>
/// <reference path="./structs/delegate.ts">/>
/// <reference path="./structs/domain.ts">/>
/// <reference path="./structs/field.ts">/>
/// <reference path="./structs/gc-handle.ts">/>
/// <reference path="./structs/image.ts">/>
/// <reference path="./structs/memory-snapshot.ts">/>
/// <reference path="./structs/method.ts">/>
/// <reference path="./structs/object.ts">/>
/// <reference path="./structs/parameter.ts">/>
/// <reference path="./structs/pointer.ts">/>
/// <reference path="./structs/reference.ts">/>
/// <reference path="./structs/string.ts">/>
/// <reference path="./structs/thread.ts">/>
/// <reference path="./structs/type.ts">/>
/// <reference path="./structs/value-type.ts">/>
globalThis.Il2Cpp = Il2Cpp;
//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./packages/anticloak/dist/buildprop.js":
/*!**********************************************!*\
  !*** ./packages/anticloak/dist/buildprop.js ***!
  \**********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   buildMapper: () => (/* binding */ buildMapper),
/* harmony export */   propMapper: () => (/* binding */ propMapper),
/* harmony export */   systemMapper: () => (/* binding */ systemMapper)
/* harmony export */ });
function propMapper(key) {
    if (key.includes('qemu') || key.includes('goldfish') || key.includes('ranchu'))
        return '';
    switch (key) {
        case 'ro.arch':
            return 'arm64';
        case 'ro.secure':
            return '1';
        case 'ro.debuggable':
            return '0';
        case 'ro.build.characteristics':
            return 'default';
        case 'ro.build.id':
            return 'SQ1D.220205.003';
        case 'ro.build.type':
            return 'release';
        case 'ro.build.tags':
            return 'release-keys';
        case 'ro.build.flavor':
            return 'raven-release';
        case 'ro.product.model':
        case 'ro.product.name':
            return 'Raven';
        case 'ro.product.manufacturer':
        case 'ro.product.brand':
            return 'Xiaomi';
        case 'ro.hardware':
        case 'ro.product.board':
        case 'ro.board.platform':
        case 'ro.product.device':
        case 'ro.soc.model':
            return 'hi6250';
        case 'ro.hardware.egl':
            // return 'emulation';
            return 'qcom';
        case 'ro.build.product':
            return 'nya64a';
        case 'ro.bootloader':
        case 'ro.bootmode':
            return 'secure';
        case 'gsm.version.baseband':
            return '4.0.2.c8-00047-0722+1520_40cbe21,4.0.2.c8-00047-0722_1520_40cbe21';
        case 'ro.build.fingerprint':
            return 'Xiaomi/raven/raven:14/SQ1D.220205.003/8069835:user/release-keys';
        case 'ro.build.description':
        case 'ro.build.display.id':
            return 'xiaomi-raven 14 SQ1D.220205.003 8069835 release-keys';
        case 'persist.sys.timezone':
        case 'ro.hardware.power':
        case 'init.svc.adbd':
        case 'sys.usb.controller':
        case 'sys.usb.state':
            return '';
    }
}
function buildMapper(key) {
    switch (key) {
        case 'MODEL':
            return 'Go 6 Pro';
        case 'BRAND':
        case 'MANUFACTURER':
        case 'SOC_MANUFACTURER':
            return 'Xiaomi';
        // case 'DEVICE':
        // case 'PRODUCT': // this can be problematic for EGLConfig
        //     return 'nya_arm64';
        case 'HARDWARE':
            return 'qcom';
        case 'BOARD':
            return 'hi6250';
        case 'FINGERPRINT':
            return 'Xiaomi/raven/raven:14/SQ1D.220205.003/8069835:user/release-keys';
        case 'DISPLAY':
            return 'SQ1D.220205.003';
        case 'BOOTLOADER':
            return 'locked';
        case 'HOST':
            return 'HOST Co';
        case 'TAGS':
            return 'release-keys';
        case 'SERIAL':
            return 'deadbeef';
        case 'TYPE':
            return 'Production build';
        case 'USER':
            return 'LINUX General';
        case 'UNKNOWN':
            return 'KGTT General';
        case 'ANDROID_ID':
            return 'b6932a00c88d8b50';
        case 'IS_EMULATOR':
        case 'IS_USERDEBUG':
        case 'IS_DEBUGGABLE':
            return 'false';
    }
}
function systemMapper(key) {
    switch (key) {
        case 'http.agent':
            return 'Mozilla/5.0 (Linux; Android 14; Go 6 Pro Build/SQ1D.220205.003) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.66.Mobile Safari/537.36';
    }
}

//# sourceMappingURL=buildprop.js.map

/***/ }),

/***/ "./packages/anticloak/dist/country.js":
/*!********************************************!*\
  !*** ./packages/anticloak/dist/country.js ***!
  \********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   mock: () => (/* binding */ mock)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/hooks */ "./packages/hooks/dist/index.js");


const Configurations = {
    BR: {
        timezoneId: 'America/Sao_Paulo',
        mcc: '724',
        mnc: '10',
        code: '55',
        mccmnc: `${724}${10}`,
        locale: ['BR', 'pt'],
        country: 'br',
        operator: 'Vivo',
    },
    IN: {
        timezoneId: 'Asia/Kolkata',
        mcc: '404',
        mnc: '299',
        code: '91',
        mccmnc: `${404}${299}`,
        locale: ['IN', 'in'],
        country: 'in',
        operator: 'Failed Calls',
    },
    VI: {
        timezoneId: 'America/St_Thomas',
        mcc: '376',
        mnc: '999',
        code: '1340',
        mccmnc: `${999}${1340}`,
        locale: ['VI', 'vi'],
        country: 'vi',
        operator: 'Fix Line',
    },
    VN: {
        timezoneId: 'Asia/Ho_Chi_Minh',
        mcc: '452',
        mnc: '01',
        code: '84',
        mccmnc: `${452}${1}`,
        locale: ['VN', 'vn'],
        country: 'vn',
        operator: 'MobiFone',
    },
    RU: {
        timezoneId: 'Europe/Moscow',
        mcc: '255',
        mnc: '999',
        code: '79',
        mccmnc: `${255}${999}`,
        locale: ['RU', 'ru'],
        country: 'ru',
        operator: 'Fix Line',
    },
    ID: {
        timezoneId: 'Asia/Jakarta',
        mcc: '510',
        mnc: '11',
        code: '62',
        mccmnc: `${510}${11}`,
        locale: ['ID', 'id'],
        country: 'id',
        operator: 'XL',
    },
    PH: {
        timezoneId: 'Asia/Manila',
        mcc: '515',
        mnc: '03',
        code: '63',
        mccmnc: `${515}${3}`,
        locale: ['PH', 'fil'],
        country: 'ph',
        operator: 'Smart',
    },
};
function mock(keyOrConfig) {
    const config = typeof keyOrConfig === 'object' ? keyOrConfig : Configurations[keyOrConfig];
    const number = `${config.code}${_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.stringNumber(10)}`;
    const subscriber = `${config.mccmnc}${_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.stringNumber(15 - config.mccmnc.length)}`;
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.TelephonyManager, 'getLine1Number', { replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(number) });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.TelephonyManager, 'getSimOperator', {
        replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(config.mccmnc),
    });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.TelephonyManager, 'getSimOperatorName', {
        replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(config.operator),
    });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.TelephonyManager, 'getNetworkOperator', {
        replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(config.mccmnc),
    });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.TelephonyManager, 'getNetworkOperatorName', {
        replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(config.operator),
    });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.TelephonyManager, 'getSimCountryIso', {
        replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(config.country),
    });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.TelephonyManager, 'getNetworkCountryIso', {
        replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(config.country),
    });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.TelephonyManager, 'getSubscriberId', {
        replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(subscriber),
    });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.TimeZone, 'getID', { replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(config.timezoneId) });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Locale, 'getDefault', {
        replace: () => _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Locale.$new(config.locale[1], config.locale[0]),
        logging: { call: false, return: false },
    });
    // hook(Classes.Locale, 'getCountry', { replace: always('BR'), logging: { call: false, return: false } });
    // hook(Classes.Locale, 'getLanguage', { replace: always('pt'), logging: { call: false, return: false } });
    // hook(Classes.Locale, 'getDisplayCountry', { replace: always('Brazil'), logging: { call: false, return: false } });
    // hook(Classes.Locale, 'toString', { replace: always('pt_BR'), logging: { call: false, return: false } });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Resources, 'getConfiguration', {
        after(method, returnValue, ...args) {
            returnValue.mcc.value = Number(config.mcc);
            returnValue.mnc.value = Number(config.mnc);
            returnValue.setLocale(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Locale.$new(config.locale[1], config.locale[0]));
        },
        logging: { call: false, return: false },
    });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Date, 'getTime', {
        loggingPredicate: _clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.Filter.date,
        // replace(method, ...args) {
        //     const calendar = Classes.Calendar.getInstance(Classes.TimeZone.getTimeZone('UTC'));
        //     const zdt = Classes.ZonedDateTime.ofInstant(
        //         Classes.Instant.ofEpochMilli(this.getTime()),
        //         Classes.ZoneId.of(config.timezoneId),
        //     );
        //     calendar.set(1, zdt.getYear());
        //     calendar.set(2, zdt.getMonthValue() - 1);
        //     calendar.set(5, zdt.getDayOfMonth());
        //     calendar.set(11, zdt.getHour());
        //     calendar.set(12, zdt.getMinute());
        //     calendar.set(13, zdt.getSecond());
        //     calendar.set(14, zdt.getNano() / 1_000_000);
        //     return calendar.getTimeInMillis();
        // },
    });
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Calendar, 'getInstance', {
        logging: { call: false, return: false },
        loggingPredicate: _clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.Filter.date,
        replace(method, ...args) {
            const returnValue = method.call(this, ...args);
            returnValue.setTimeZone(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.TimeZone.getTimeZone(config.timezoneId));
            return returnValue;
        },
    });
}

//# sourceMappingURL=country.js.map

/***/ }),

/***/ "./packages/anticloak/dist/debug.js":
/*!******************************************!*\
  !*** ./packages/anticloak/dist/debug.js ***!
  \******************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   hookDigestEquals: () => (/* binding */ hookDigestEquals),
/* harmony export */   hookPtrace: () => (/* binding */ hookPtrace),
/* harmony export */   hookVMDebug: () => (/* binding */ hookVMDebug),
/* harmony export */   hookVerify: () => (/* binding */ hookVerify)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/hooks */ "./packages/hooks/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _clockwork_native__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @clockwork/native */ "./packages/native/dist/index.js");




function hookPtrace() {
    const replace = Interceptor.replaceFast(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.ptrace, new NativeCallback(function (request, pid, addr, data) {
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.logger.info({ tag: 'ptrace' }, `${request} ${pid} ${addr} ${data} ${(0,_clockwork_native__WEBPACK_IMPORTED_MODULE_3__.traceInModules)(this.returnAddress)}`);
        return 0;
    }, 'long', ['int', 'int', 'pointer', 'pointer']));
}
function hookVMDebug() {
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(Classes.VMDebug, 'isDebuggerConnected', { replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(false) });
}
function hookDigestEquals() {
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(Classes.MessageDigest, 'equals', {
        replace(method, ...args) {
            return ((0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.tryNull)(() => {
                const thisClazz = Reflect.get(this, '$className');
                const otherClazz = Reflect.get(args[0], '$className');
                return thisClazz === otherClazz;
            }) ?? false);
        },
    });
}
function hookVerify() {
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(Classes.Signature, 'verify', { replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(true) });
}

//# sourceMappingURL=debug.js.map

/***/ }),

/***/ "./packages/anticloak/dist/index.js":
/*!******************************************!*\
  !*** ./packages/anticloak/dist/index.js ***!
  \******************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   BuildProp: () => (/* reexport module object */ _buildprop_js__WEBPACK_IMPORTED_MODULE_2__),
/* harmony export */   Country: () => (/* reexport module object */ _country_js__WEBPACK_IMPORTED_MODULE_3__),
/* harmony export */   Debug: () => (/* reexport module object */ _debug_js__WEBPACK_IMPORTED_MODULE_4__),
/* harmony export */   InstallReferrer: () => (/* reexport module object */ _installReferrer_js__WEBPACK_IMPORTED_MODULE_5__),
/* harmony export */   Jigau: () => (/* reexport module object */ _jigau_js__WEBPACK_IMPORTED_MODULE_6__),
/* harmony export */   generic: () => (/* binding */ generic),
/* harmony export */   hookAdId: () => (/* binding */ hookAdId),
/* harmony export */   hookDevice: () => (/* binding */ hookDevice),
/* harmony export */   hookInstallerPackage: () => (/* binding */ hookInstallerPackage),
/* harmony export */   hookSettings: () => (/* binding */ hookSettings)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/hooks */ "./packages/hooks/dist/index.js");
/* harmony import */ var _buildprop_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./buildprop.js */ "./packages/anticloak/dist/buildprop.js");
/* harmony import */ var _country_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./country.js */ "./packages/anticloak/dist/country.js");
/* harmony import */ var _debug_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./debug.js */ "./packages/anticloak/dist/debug.js");
/* harmony import */ var _installReferrer_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./installReferrer.js */ "./packages/anticloak/dist/installReferrer.js");
/* harmony import */ var _jigau_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./jigau.js */ "./packages/anticloak/dist/jigau.js");








function hookDevice(fn) {
    (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.enumerateMembers)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Build, {
        onMatchField(clazz, member) {
            const field = clazz[member];
            const mapped = fn?.(member) ?? (0,_buildprop_js__WEBPACK_IMPORTED_MODULE_2__.buildMapper)(member);
            if (field && mapped) {
                let casted = mapped;
                if (field.fieldReturnType.className === 'boolean') {
                    casted = Boolean(mapped);
                }
                field.value = casted;
            }
        },
    });
}
function hookSettings(fn) {
    const mapper = (key) => {
        switch (key) {
            case 'development_settings_enabled':
            case 'adb_enabled':
            case 'install_non_market_apps':
                return 0;
            case 'play_protect_enabled':
                return 1;
        }
    };
    for (const clazz of [_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Settings$Secure, _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Settings$Global]) {
        (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(clazz, 'getInt', {
            loggingPredicate: _clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.Filter.settings,
            logging: { multiline: false, short: true },
            replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.ifKey)((key) => fn?.(key) ?? mapper(key), 1),
        });
    }
}
function hookAdId(id = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.uuid()) {
    const uniqFind = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.getFindUnique)(false);
    _clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.ClassLoader.perform(() => {
        uniqFind('com.google.android.gms.ads.identifier.AdvertisingIdClient$Info', (clazz) => {
            'getId' in clazz && (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(clazz, 'getId', { replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)(id) });
        });
    });
}
function hookInstallerPackage() {
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.ApplicationPackageManager, 'getInstallerPackageName', {
        replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)('com.android.vending'),
        logging: {
            short: true,
            multiline: false,
        },
    });
}
function hookLocationHardware() {
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.LocationManager, 'getGnssHardwareModelName', {
        replace: (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.always)('Model Name Nya'),
    });
}
function hookSensor() {
    const params = {
        replace(method, ...args) {
            const value = `${method.call(this, ...args)}`;
            return value.replace(/x86|sdk|open|source|emulator|google|aosp|ranchu|goldfish|cuttlefish|generic|unknown/gi, 'nya');
        },
        logging: {
            short: true,
            multiline: false,
        },
    };
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Sensor, 'getVendor', params);
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Sensor, 'getName', params);
}
function hookVerify() {
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Signature, 'verify', {
        replace: () => true,
    });
}
function hookHasFeature() {
    const HARDWARE_FEATURES = ['android.hardware.camera.flash', 'android.hardware.nfc'];
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.ApplicationPackageManager, 'hasSystemFeature', {
        logging: { short: true, multiline: false },
        predicate(_, i) { return i !== 0; },
        replace(method, ...args) {
            const feature = `${args[0]}`;
            for (const key of HARDWARE_FEATURES) {
                if (feature.startsWith(key)) {
                    return true;
                }
            }
            return method.call(this, ...args);
        },
    });
}
function generic() {
    hookInstallerPackage();
    hookLocationHardware();
    hookSensor();
    hookVerify();
    hookHasFeature();
}

//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./packages/anticloak/dist/installReferrer.js":
/*!****************************************************!*\
  !*** ./packages/anticloak/dist/installReferrer.js ***!
  \****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   createInstallReferrer: () => (/* binding */ createInstallReferrer),
/* harmony export */   replace: () => (/* binding */ replace)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/hooks */ "./packages/hooks/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");



const logger = (0,_clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.subLogger)('installreferrer');
function createInstallReferrer(classWrapper, details) {
    const now = Date.now() / 1000;
    const off = (int) => Math.round(Math.random() * int);
    const bundle = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Bundle.$new();
    bundle.putBoolean('google_play_instant', details?.google_play_instant ?? true);
    bundle.putLong('install_begin_timestamp_seconds', details?.install_begin_timestamp_seconds ?? now - off(30));
    bundle.putLong('install_begin_timestamp_server_seconds', details?.install_begin_timestamp_server_seconds ?? now - off(30));
    bundle.putString('install_referrer', details?.install_referrer ?? 'utm_medium=Non-Organic');
    bundle.putString('install_version', details?.install_version ?? '1.0.0');
    bundle.putLong('referrer_click_timestamp_seconds', details?.referrer_click_timestamp_seconds ?? now - off(65));
    bundle.putLong('referrer_click_timestamp_server_seconds', details?.referrer_click_timestamp_server_seconds ?? now - off(65));
    return classWrapper.$new(bundle);
}
function replace(details = {}) {
    let isHooked = false;
    _clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.ClassLoader.perform((_) => {
        if (isHooked)
            return;
        const client = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.findClass)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.InstallReferrerClient);
        if (!client)
            return;
        isHooked = true;
        const [startMethod, getMethod] = matchReferrerClientMethods(client);
        performReplace(details, client, startMethod, getMethod);
    });
}
function performReplace(details, client, startMethod, getMethod) {
    const beforeInit = function () {
        const paretnClass = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.findClass)(this.$className);
        if (!paretnClass) {
            logger.warn(`missing parent class: ${this.$className}`);
            return;
        }
        (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(paretnClass, startMethod, {
            predicate: startConnectionPredicate,
            replace(method, listener) {
                const baseClass = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.findClass)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.InstallReferrerStateListener);
                if (!baseClass) {
                    logger.warn(`missing base class: ${_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.InstallReferrerStateListener}`);
                    return method.call(this, listener);
                }
                const onFinishedMethod = matchStateListenerMethod(baseClass);
                let msg = _clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.Color.method(startMethod);
                msg += _clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.Color.bracket('(');
                msg += _clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.Color.className(listener?.$className);
                msg += _clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.Color.bracket(')');
                msg += ' -> ';
                msg += _clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.Color.method(onFinishedMethod);
                msg += `${_clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.Color.bracket('(')}${_clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.Color.number('0')}${_clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.Color.bracket(')')}`;
                logger.info(msg);
                listener?.[onFinishedMethod]?.(0);
            },
        });
        (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(paretnClass, getMethod, {
            predicate: getInstallReferrerPredicate,
            replace(method) {
                const referrerDetails = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.findClass)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.ReferrerDetails);
                if (!referrerDetails) {
                    logger.warn(`missing referrer class: ${_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.ReferrerDetails}`);
                    return method.call(this);
                }
                (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.enumerateMembers)(referrerDetails, {
                    onMatchMethod(clazz, member) {
                        (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(clazz, member);
                    },
                }, 1);
                return createInstallReferrer(referrerDetails, details);
            },
        });
    };
    (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_1__.hook)(client, '$init', { before: beforeInit });
}
function matchReferrerClientMethods(clazz) {
    let startMethod = null;
    let getMethod = null;
    (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.enumerateMembers)(clazz, {
        onMatchMethod(clazz, member) {
            const def = clazz[member];
            if (!def)
                return;
            for (const [i, overload] of def.overloads.entries()) {
                if (startConnectionPredicate(overload, i)) {
                    startMethod ??= member;
                    continue;
                }
                if (getInstallReferrerPredicate(overload, i)) {
                    getMethod ??= member;
                }
            }
        },
    }, 1);
    return [startMethod ?? 'startConnection', getMethod ?? 'getInstallReferrer'];
}
function matchStateListenerMethod(clazz) {
    let found = null;
    (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.enumerateMembers)(clazz, {
        onMatchMethod(clazz, member) {
            const def = clazz[member];
            if (!def)
                return;
            for (const [i, overload] of def.overloads.entries()) {
                if (onInstallReferrerSetupFinishedPredicate(overload, i)) {
                    found ??= member;
                    return;
                }
            }
        },
    }, 1);
    return found ?? 'onInstallReferrerSetupFinished';
}
const startConnectionPredicate = ({ returnType, argumentTypes }) => {
    return (returnType.className === 'void' &&
        argumentTypes.length === 1 &&
        argumentTypes[0].className === _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.InstallReferrerStateListener);
};
const getInstallReferrerPredicate = ({ returnType, argumentTypes }) => {
    return returnType.className === _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.ReferrerDetails && argumentTypes.length === 0;
};
const onInstallReferrerSetupFinishedPredicate = ({ returnType, argumentTypes }) => {
    return (returnType.className === 'void' && argumentTypes.length === 1 && argumentTypes[0].className === 'int');
};

//# sourceMappingURL=installReferrer.js.map

/***/ }),

/***/ "./packages/anticloak/dist/jigau.js":
/*!******************************************!*\
  !*** ./packages/anticloak/dist/jigau.js ***!
  \******************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   memoryPatch: () => (/* binding */ memoryPatch)
/* harmony export */ });
/* harmony import */ var _clockwork_native__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/native */ "./packages/native/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");


const NativeLibName = 'libjiagu_64.so';
const Arm64Pattern = '00 03 3f d6 a0 06 00 a9';
/** can be super finniky about other native functions hooked befor it patches the memory */
function memoryPatch(name = NativeLibName) {
    let hookNow = false;
    _clockwork_native__WEBPACK_IMPORTED_MODULE_0__.Inject.afterInitArray((name) => {
        if (name?.includes(NativeLibName)) {
            hookNow = true;
        }
        if (hookNow) {
            let module = null;
            if (hookNow && (module = Process.findModuleByName(NativeLibName))) {
                Memory.scan(module.base, module.size, Arm64Pattern, {
                    onMatch: (found) => {
                        Interceptor.attach(found, (args) => {
                            Memory.protect(args[0], Process.pointerSize, 'rwx');
                            try {
                                const arg0 = args[0].readCString();
                                if (arg0?.includes('/proc/') && arg0?.includes('/maps')) {
                                    args[0].writeUtf8String('/proc/self/cmdline');
                                }
                            }
                            catch (e) { }
                        });
                    },
                    onComplete: () => {
                        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'jigau' }, 'frida detection nypassed');
                    },
                });
            }
        }
    });
}

//# sourceMappingURL=jigau.js.map

/***/ }),

/***/ "./packages/cocos2dx/dist/dump.js":
/*!****************************************!*\
  !*** ./packages/cocos2dx/dist/dump.js ***!
  \****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   dump: () => (/* binding */ dump)
/* harmony export */ });
/* harmony import */ var crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! crypto */ "./node_modules/@frida/crypto/dist/index.js");
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _clockwork_native__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @clockwork/native */ "./packages/native/dist/index.js");




const { dim } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.Color.use();
const logger = (0,_clockwork_logging__WEBPACK_IMPORTED_MODULE_2__.subLogger)('cocos2dx');
function hookLegacy() {
    //@ts-ignore
    const array = Module.enumerateExportsSync(libname).filter(({ name }) => name.includes( true && name.includes('ScriptEngine')));
    return array;
}
/**
 *  __int64 __fastcall se::ScriptEngine::evalString(
 *         se::ScriptEngine *this,
 *         const char *scripts,
 *         unsigned __int64 len,
 *         se::Value *a4,
 *         const char *filename)
 * */
const hookEvalString = {
    onEnter(args) {
        const [_, scripts, len, , filename] = [args[0], args[1], args[2], args[3], args[4]];
        let length = null;
        let path = null;
        let data = null;
        if (filename && (path = filename.readCString())) {
            length = len.toUInt32();
        }
        else if ((data = scripts.readCString())) {
            path = `${(0,crypto__WEBPACK_IMPORTED_MODULE_0__.createHash)('sha256').update(data).digest('hex')}.js`;
            length = data.length;
        }
        if (!length || !path)
            return;
        const result = (0,_clockwork_native__WEBPACK_IMPORTED_MODULE_3__.dumpFile)(scripts, length, path, 'cocos2dx');
        logger.info(`${path} ${result ? dim(_clockwork_common__WEBPACK_IMPORTED_MODULE_1__.Text.toByteSize(length)) : 'error'}`);
    },
    onLeave() { },
};
const hookLuaLLoadbuffer = {
    onEnter(args) {
        const [scripts, len, filename] = [args[1], args[2], args[3]];
        let length = null;
        let path = null;
        let data = null;
        if (filename && `${scripts}` !== `${filename}` && (path = filename.readCString())) {
            length = len.toUInt32();
        }
        else if ((data = scripts.readCString())) {
            path = `${(0,crypto__WEBPACK_IMPORTED_MODULE_0__.createHash)('sha256').update(data).digest('hex')}.lua`;
            length = data.length;
        }
        if (!length || !path)
            return;
        const result = (0,_clockwork_native__WEBPACK_IMPORTED_MODULE_3__.dumpFile)(scripts, length, path, 'cocos2dx');
        logger.info(`${path} ${result ? dim(_clockwork_common__WEBPACK_IMPORTED_MODULE_1__.Text.toByteSize(length)) : 'error'}`);
    },
    onLeave() { },
};
function dump(...targets) {
    const notFoundId = setTimeout(() => logger.warn('10 seconds have passed and no cocos2dx methods were called yet'), 10000);
    _clockwork_native__WEBPACK_IMPORTED_MODULE_3__.Inject.afterInitArrayModule((module) => {
        const evalStringAddresses = [];
        const xxteaAddresses = [];
        const setXxteaAdresses = [];
        for (const { name, fn_dump, fn_key, fn_set } of targets) {
            if (name === module.name) {
                if (fn_dump)
                    evalStringAddresses.push(module.base.add(fn_dump));
                if (fn_key)
                    xxteaAddresses.push(module.base.add(fn_key));
                if (fn_set)
                    setXxteaAdresses.push(module.base.add(fn_set));
            }
        }
        if (Number.parseInt(Frida.version.split('.')[0]) <= 15) {
            evalStringAddresses.push(...hookLegacy());
        }
        else {
            let hookTemp = module.findExportByName('_ZN2se12ScriptEngine10evalStringEPKclPNS_5ValueES2_');
            hookTemp ??= module.findExportByName('_ZN2se12ScriptEngine10evalStringEPKcjPNS_5ValueES2_');
            hookTemp ??= module.findExportByName('_ZN2se12ScriptEngine10evalStringEPKciPNS_5ValueES2_');
            hookTemp && evalStringAddresses.push(hookTemp);
        }
        for (const address of evalStringAddresses) {
            logger.info(`evalString: ${module.name} ${DebugSymbol.fromAddress(address)}`);
            Interceptor.attach(address, hookEvalString);
        }
        // luad load buffer
        const lual = module.findExportByName('luaL_loadbuffer');
        if (lual) {
            logger.info(`luaL_loadbuffer: ${module.name} ${DebugSymbol.fromAddress(lual)}`);
            Interceptor.attach(lual, hookLuaLLoadbuffer);
        }
        // xxtea decrypt
        // Lua key+sig pair
        let realKeySize = 0;
        let signSize = 0;
        const xxteaCryptDecrypt = module.findExportByName('_ZNK10XXTeaCrypt7decryptERKN7cocos2d4DataEPS1_');
        if (xxteaCryptDecrypt) {
            logger.info(`xxtea_crypt_decrypt: ${module.name} ${DebugSymbol.fromAddress(xxteaCryptDecrypt)}`);
            Interceptor.attach(xxteaCryptDecrypt, {
                onEnter(args) {
                    const key = args[0].add(Process.pointerSize === 4 ? 0x4 : 0x8).readCString();
                    const sign = args[0].add(Process.pointerSize === 4 ? 0x10 : 0x20).readCString();
                    logger.info({ id: 'xxtea_crypt_decrypt' }, `key -> ${key} sign -> ${sign}`);
                    realKeySize = `${key}`.length - 1;
                    signSize = `${sign}`.length - 1;
                },
            });
        }
        const xxteaKeyAndSign = module.findExportByName('_ZN7cocos2d8LuaStack18setXXTEAKeyAndSignEPKciS2_i');
        if (xxteaKeyAndSign) {
            logger.info(`xxtea_key_and_sign: ${module.name} ${DebugSymbol.fromAddress(xxteaKeyAndSign)}`);
            Interceptor.attach(xxteaKeyAndSign, {
                onEnter(args) {
                    const keylen = Math.min(args[2].toUInt32(), 16);
                    const siglen = args[4].toUInt32();
                    logger.info({ id: 'xxtea_key_and_sign' }, `key -> ${args[1].readCString(keylen)} sign -> ${args[3].readCString(siglen)}`);
                    signSize = siglen;
                },
            });
        }
        const xxteaKeyAndSign1 = module.findExportByName('_ZN7cocos2d5extra6Crypto12decryptXXTEAEPhiS2_iPi');
        if (xxteaKeyAndSign1) {
            logger.info(`xxtea_key_and_sign1: ${module.name} ${DebugSymbol.fromAddress(xxteaKeyAndSign1)}`);
            Interceptor.attach(xxteaKeyAndSign1, {
                onEnter(args) {
                    const key = args[1].readCString();
                    const sign = args[2].readCString();
                    logger.info({ id: 'xxtea_key_and_sign1' }, `key -> ${key} sign -> ${sign}`);
                    signSize = `${sign}`.length - 1;
                },
            });
        }
        const xxteaKeyAndSign2 = module.findExportByName('_ZN7cocos2d8LuaStack18setXXTEAKeyAndSignEPKcS2_');
        if (xxteaKeyAndSign2) {
            logger.info(`xxtea_key_and_sign2: ${module.name} ${DebugSymbol.fromAddress(xxteaKeyAndSign2)}`);
            Interceptor.attach(xxteaKeyAndSign2, {
                onEnter(args) {
                    const key = args[0].readCString();
                    const sign = args[1].readCString();
                    logger.info({ id: 'xxtea_key_and_sign2' }, `key -> ${key} sign -> ${sign}`);
                    signSize = `${sign}`.length - 1;
                },
            });
        }
        const xxteaKeyAndSign3 = module.findExportByName('_ZN7cocos2d5extra6Crypto15decryptXXTEALuaEPKciS3_i');
        if (xxteaKeyAndSign3) {
            logger.info(`xxtea_key_and_sign3: ${module.name} ${DebugSymbol.fromAddress(xxteaKeyAndSign3)}`);
            Interceptor.attach(xxteaKeyAndSign3, {
                onEnter(args) {
                    const key = args[0].readCString();
                    const sign = args[1].readCString();
                    logger.info({ id: 'xxtea_key_and_sign3' }, `key -> ${key} sign -> ${sign}`);
                    signSize = `${sign}`.length - 1;
                },
            });
        }
        const xxteaResourcesDecode = module.findExportByName('_ZN15ResourcesDecode11setXXTeaKeyEPKciS1_i');
        if (xxteaResourcesDecode) {
            logger.info(`xxtea_resources_decode: ${module.name} ${DebugSymbol.fromAddress(xxteaResourcesDecode)}`);
            Interceptor.attach(xxteaResourcesDecode, {
                onEnter(args) {
                    const keylen = Math.min(args[2].toUInt32(), 16);
                    const siglen = Math.min(args[4].toUInt32(), 16);
                    logger.info({ id: 'xxtea_resources_decode' }, `key -> ${args[1].readCString(keylen)} sign -> ${args[3].readCString(siglen)}`);
                },
                onLeave() { },
            });
        }
        let xxtea_decrypt = module.findExportByName('_Z13xxtea_decryptPhjS_jPj');
        xxtea_decrypt && xxteaAddresses.push(xxtea_decrypt);
        xxtea_decrypt = module.findExportByName('xxtea_decrypt');
        xxtea_decrypt && xxteaAddresses.push(xxtea_decrypt);
        for (const address of xxteaAddresses) {
            logger.info(`xxtea_decrypt: ${module.name} ${DebugSymbol.fromAddress(address)}`);
            // no idea why this often crashes
            try {
                Interceptor.attach(address, {
                    onEnter: (args) => {
                        logger.info({ id: 'xxtea_decrypt' }, `key -> ${args[2].readCString(Math.min(args[3].toUInt32(), 16))}`);
                    },
                    onLeave: () => { },
                });
            }
            catch (e) {
                logger.warn(`could not attach to xxtea_decrypt at ${address}`);
            }
        }
        // New methods for hooking
        const getLuaStack = module.findExportByName('_ZN7cocos2d9LuaEngine11getLuaStackEv');
        if (getLuaStack) {
            logger.info(`get_lua_stack: ${module.name} ${DebugSymbol.fromAddress(getLuaStack)}`);
            let isHooked = false;
            Interceptor.attach(getLuaStack, {
                onLeave: (retval) => {
                    if (!isHooked) {
                        isHooked = true;
                        const nextAddr = retval.readPointer().add(0xe8).readPointer();
                        Interceptor.attach(nextAddr, {
                            onEnter: (args) => {
                                const key = args[1].readCString(Math.min(args[2].toUInt32(), 16));
                                const sign = args[3].readCString(args[4].toUInt32());
                                logger.info({ id: 'get_lua_stack' }, `key -> ${key} sign -> ${sign}`);
                            },
                        });
                    }
                },
            });
        }
        const getLuaEngine = module.findExportByName('_ZN7cocos2d9LuaEngine11getInstanceEv');
        if (getLuaEngine) {
            logger.info(`get_lua_engine: ${module.name} ${DebugSymbol.fromAddress(getLuaEngine)}`);
            let isHooked = false;
            Interceptor.attach(getLuaEngine, {
                onLeave: (retval) => {
                    if (!isHooked) {
                        isHooked = true;
                        logger.info({ id: 'get_lua_engine' }, `return -> ${retval}`);
                        // const nextAddr = retval.add(0x4).readPointer().readPointer().add(0x74).readPointer();
                        // Interceptor.attach(nextAddr, {
                        //     onEnter: function (args) {
                        //         logger.info({ id: 'get_lua_engine' }, `key -> ${args[1].readCString()} sign -> ${args[2].readCString()}`);
                        //     },
                        // });
                    }
                },
            });
        }
        // AES  encryption
        const setEncryption = module.findExportByName('_ZN14EncryptManager17setEncryptEnabledEbN5cxx1717basic_string_viewIcNSt6__ndk111char_traitsIcEEEES5_i');
        setEncryption &&
            Interceptor.attach(setEncryption, {
                onEnter: (args) => {
                    logger.info('AES Encryption');
                    logger.info('Key:');
                    logger.info(hexdump(args[0].add(Process.pointerSize === 4 ? 0x10 : 0x20), {
                        length: 32,
                        ansi: true,
                    }));
                    logger.info('IV:');
                    logger.info(hexdump(args[4], { length: 16, ansi: true }));
                    logger.info(`Flags -> ${args[5]}`);
                },
            });
        // TODO refactor this
        for (const offset of setXxteaAdresses) {
            let ptr = null;
            let addr = null;
            try {
                ptr = module.base.add(offset);
                addr = ptr.readPointer();
                logger.info(`set_xxtea_key: ${module.name} ${DebugSymbol.fromAddress(addr)}`);
                Interceptor.attach(addr, {
                    onEnter(args) {
                        logger.info({ id: 'set_xxtea_key' }, new _clockwork_common__WEBPACK_IMPORTED_MODULE_1__.Std.String(args[1]).disposeToString());
                    },
                });
            }
            catch (e) {
                logger.warn(`could not attach to set_xxtea_key at ${ptr} -> ${addr}`);
            }
        }
        if (evalStringAddresses.length > 0 || lual || xxteaAddresses.length > 0) {
            clearTimeout(notFoundId);
        }
    });
}

//# sourceMappingURL=dump.js.map

/***/ }),

/***/ "./packages/cocos2dx/dist/index.js":
/*!*****************************************!*\
  !*** ./packages/cocos2dx/dist/index.js ***!
  \*****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   dump: () => (/* reexport safe */ _dump_js__WEBPACK_IMPORTED_MODULE_1__.dump),
/* harmony export */   hookLocalStorage: () => (/* binding */ hookLocalStorage)
/* harmony export */ });
/* harmony import */ var _clockwork_hooks__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/hooks */ "./packages/hooks/dist/index.js");
/* harmony import */ var _dump_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./dump.js */ "./packages/cocos2dx/dist/dump.js");


function hookLocalStorage(fn) {
    let Cocos2dxLocalStorage;
    _clockwork_hooks__WEBPACK_IMPORTED_MODULE_0__.ClassLoader.perform(() => {
        if (!Cocos2dxLocalStorage &&
            (Cocos2dxLocalStorage = findClass('org.cocos2dx.lib.Cocos2dxLocalStorage'))) {
            (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_0__.hook)(Cocos2dxLocalStorage, 'getItem', {
                replace: fn ? (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_0__.ifKey)(fn) : undefined,
                logging: { multiline: false },
            });
        }
    });
}

//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./packages/common/dist/define/enum.js":
/*!*********************************************!*\
  !*** ./packages/common/dist/define/enum.js ***!
  \*********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   a_type: () => (/* binding */ a_type),
/* harmony export */   mode: () => (/* binding */ mode)
/* harmony export */ });
var mode;
(function (mode) {
    mode[mode["F_OK"] = 0] = "F_OK";
    mode[mode["X_OK"] = 1] = "X_OK";
    mode[mode["W_OK"] = 2] = "W_OK";
    mode[mode["R_OK"] = 4] = "R_OK";
})(mode || (mode = {}));
var a_type;
(function (a_type) {
    a_type[a_type["AT_NULL"] = 0] = "AT_NULL";
    a_type[a_type["AT_IGNORE"] = 1] = "AT_IGNORE";
    a_type[a_type["AT_EXECFD"] = 2] = "AT_EXECFD";
    a_type[a_type["AT_PHDR"] = 3] = "AT_PHDR";
    a_type[a_type["AT_PHENT"] = 4] = "AT_PHENT";
    a_type[a_type["AT_PHNUM"] = 5] = "AT_PHNUM";
    a_type[a_type["AT_PAGESZ"] = 6] = "AT_PAGESZ";
    a_type[a_type["AT_BASE"] = 7] = "AT_BASE";
    a_type[a_type["AT_FLAGS"] = 8] = "AT_FLAGS";
    a_type[a_type["AT_ENTRY"] = 9] = "AT_ENTRY";
    a_type[a_type["AT_NOTELF"] = 10] = "AT_NOTELF";
    a_type[a_type["AT_UID"] = 11] = "AT_UID";
    a_type[a_type["AT_EUID"] = 12] = "AT_EUID";
    a_type[a_type["AT_GID"] = 13] = "AT_GID";
    a_type[a_type["AT_EGID"] = 14] = "AT_EGID";
    a_type[a_type["AT_PLATFORM"] = 15] = "AT_PLATFORM";
    a_type[a_type["AT_HWCAP"] = 16] = "AT_HWCAP";
    a_type[a_type["AT_CLKTCK"] = 17] = "AT_CLKTCK";
    a_type[a_type["AT_SECURE"] = 23] = "AT_SECURE";
    a_type[a_type["AT_BASE_PLATFORM"] = 24] = "AT_BASE_PLATFORM";
    a_type[a_type["AT_RANDOM"] = 25] = "AT_RANDOM";
    a_type[a_type["AT_HWCAP2"] = 26] = "AT_HWCAP2";
    a_type[a_type["AT_RSEQ_FEATURE_SIZE"] = 27] = "AT_RSEQ_FEATURE_SIZE";
    a_type[a_type["AT_RSEQ_ALIGN"] = 28] = "AT_RSEQ_ALIGN";
    a_type[a_type["AT_EXECFN"] = 31] = "AT_EXECFN";
    a_type[a_type["AT_MINSIGSTKSZ"] = 51] = "AT_MINSIGSTKSZ";
})(a_type || (a_type = {}));

//# sourceMappingURL=enum.js.map

/***/ }),

/***/ "./packages/common/dist/define/java.js":
/*!*********************************************!*\
  !*** ./packages/common/dist/define/java.js ***!
  \*********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ClassesProxy: () => (/* binding */ ClassesProxy),
/* harmony export */   ClassesString: () => (/* binding */ ClassesString)
/* harmony export */ });
/* harmony import */ var _internal_proxy_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../internal/proxy.js */ "./packages/common/dist/internal/proxy.js");

const ClassesString = {
    String: 'java.lang.String',
    Long: 'java.lang.Long',
    Boolean: 'java.lang.Boolean',
    ArrayList: 'java.util.ArrayList',
    System: 'java.lang.System',
    Exception: 'java.lang.Exception',
    StringBuilder: 'java.lang.StringBuilder',
    Class: 'java.lang.Class',
    URL: 'java.net.URL',
    Cipher: 'javax.crypto.Cipher',
    SecretKeySpec: 'javax.crypto.spec.SecretKeySpec',
    Object: 'java.lang.Object',
    ClassLoader: 'java.lang.ClassLoader',
    BaseDexClassLoader: 'dalvik.system.BaseDexClassLoader',
    DexClassLoader: 'dalvik.system.DexClassLoader',
    InMemoryDexClassLoader: 'dalvik.system.InMemoryDexClassLoader',
    PathClassLoader: 'dalvik.system.PathClassLoader',
    Date: 'java.util.Date',
    Integer: 'java.lang.Integer',
    Method: 'java.lang.reflect.Method',
    Runtime: 'java.lang.Runtime',
    Map$Entry: 'java.util.Map$Entry',
    Locale: 'java.util.Locale',
    TimeZone: 'java.util.TimeZone',
    Thread: 'java.lang.Thread',
    Arrays: 'java.util.Arrays',
    Math: 'java.lang.Math',
    DexPathList: 'dalvik.system.DexPathList',
    PendingIntent: 'android.app.PendingIntent',
    ZonedDateTime: 'java.time.ZonedDateTime',
    ZoneId: 'java.time.ZoneId',
    Instant: 'java.time.Instant',
    Calendar: 'java.util.Calendar',
    Thread$UncaughtExceptionHandler: 'java.lang.Thread$UncaughtExceptionHandler',
    Application: 'android.app.Application',
    Settings$Secure: 'android.provider.Settings$Secure',
    Settings$Global: 'android.provider.Settings$Global',
    WebView: 'android.webkit.WebView',
    ContentResolver: 'android.content.ContentResolver',
    WebChromeClient: 'android.webkit.WebChromeClient',
    Log: 'android.util.Log',
    JSONObject: 'org.json.JSONObject',
    JSONArray: 'org.json.JSONArray',
    Bundle: 'android.os.Bundle',
    Intent: 'android.content.Intent',
    Activity: 'android.app.Activity',
    SharedPreferences: 'android.content.SharedPreferences',
    SharedPreferencesImpl: 'android.app.SharedPreferencesImpl',
    PackageManager: 'android.content.pm.PackageManager',
    TelephonyManager: 'android.telephony.TelephonyManager',
    Build: 'android.os.Build',
    Build$VERSION: 'android.os.Build$VERSION',
    Build$VERSION_CODES: 'android.os.Build$VERSION_CODES',
    InstallReferrerClient: 'com.android.installreferrer.api.InstallReferrerClient',
    InstallReferrerStateListener: 'com.android.installreferrer.api.InstallReferrerStateListener',
    ReferrerDetails: 'com.android.installreferrer.api.ReferrerDetails',
    ApplicationPackageManager: 'android.app.ApplicationPackageManager',
    LocationManager: 'android.location.LocationManager',
    Sensor: 'android.hardware.Sensor',
    SystemProperties: 'android.os.SystemProperties',
    Process: 'android.os.Process',
    ProcessBuilder: 'java.lang.ProcessBuilder',
    File: 'java.io.File',
    InetSocketAddress: 'java.net.InetSocketAddress',
    SocketChannel: 'java.nio.channels.SocketChannel',
    Socket: 'java.net.Socket',
    Throwable: 'java.lang.Throwable',
    ActivityManager: 'android.app.ActivityManager',
    ActivityManager$RunningAppProcessInfo: 'android.app.ActivityManager$RunningAppProcessInfo',
    ActivityThread: 'android.app.ActivityThread',
    IoBridge: 'libcore.io.IoBridge',
    Linux: 'libcore.io.Linux',
    ByteArrayInputStream: 'java.io.ByteArrayInputStream',
    StandardCharsets: 'java.nio.charset.StandardCharsets',
    HttpURLConnectionImpl: 'com.android.okhttp.internal.huc.HttpURLConnectionImpl',
    SimpleDateFormat: 'java.text.SimpleDateFormat',
    Resources: 'android.content.res.Resources',
    Preferences: 'androidx.datastore.preferences.core.Preferences',
    Preferences$Key: 'androidx.datastore.preferences.core.Preferences$Key',
    ByteBuffer: 'java.nio.ByteBuffer',
    KeyguardManager: 'android.app.KeyguardManager',
    ContextImpl: 'android.app.ContextImpl',
    Context: 'android.content.Context',
    ContextCompat: 'androidx.core.content.ContextCompat',
    Executable: 'java.lang.reflect.Executable',
    VMDebug: 'dalvik.system.VMDebug',
    Constructor: 'java.lang.reflect.Constructor',
    DisplayManager: 'android.hardware.display.DisplayManager',
    Signature: 'java.security.Signature',
    MessageDigest: 'java.security.MessageDigest',
    Base64: 'java.util.Base64',
    DatagramChannelImpl: 'sun.nio.ch.DatagramChannelImpl',
    InputDevice: 'android.view.InputDevice',
    WindowInsets: 'android.view.WindowInsets',
    OpenSSLX509Certificate: 'com.android.org.conscrypt.OpenSSLX509Certificate',
    Certificate: 'java.security.cert.Certificate',
    UUID: 'java.util.UUID',
};
const ClassesProxy = (0,_internal_proxy_js__WEBPACK_IMPORTED_MODULE_0__.proxyJavaUse)(ClassesString);

//# sourceMappingURL=java.js.map

/***/ }),

/***/ "./packages/common/dist/define/libc.js":
/*!*********************************************!*\
  !*** ./packages/common/dist/define/libc.js ***!
  \*********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   LibcFinderProxy: () => (/* binding */ LibcFinderProxy)
/* harmony export */ });
/* harmony import */ var _internal_proxy_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../internal/proxy.js */ "./packages/common/dist/internal/proxy.js");

const LibcFinder = {
    // int open(const char *pathname, int flags);
    open: () => {
        const ptr = Module.getExportByName('libc.so', 'open');
        return new SystemFunction(ptr, 'int', ['pointer', 'int']);
    },
    // int creat(const char *pathname, mode_t mode);
    creat: () => {
        const ptr = Module.getExportByName('libc.so', 'creat');
        return new NativeFunction(ptr, 'int', ['pointer', 'int']);
    },
    // int openat(int dirfd, const char *pathname, int flags);
    openat: () => {
        const ptr = Module.getExportByName('libc.so', 'openat');
        return new NativeFunction(ptr, 'int', ['int', 'pointer', 'int', '...']);
    },
    // int close(int fd);
    close: () => {
        const ptr = Module.getExportByName('libc.so', 'close');
        return new NativeFunction(ptr, 'int', ['int']);
    },
    // int close(int fd);
    fclose: () => {
        const ptr = Module.getExportByName('libc.so', 'fclose');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int shutdown(int sockfd, int how);
    shutdown: () => {
        const ptr = Module.getExportByName('libc.so', 'shutdown');
        return new NativeFunction(ptr, 'int', ['int', 'int']);
    },
    mkdir: () => {
        const ptr = Module.getExportByName('libc.so', 'mkdir');
        return new NativeFunction(ptr, 'int', ['pointer', 'int']);
    },
    // DIR *opendir(const char *name);
    opendir: () => {
        const ptr = Module.getExportByName('libc.so', 'opendir');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    // DIR *fdopendir(int fd);
    fdopendir: () => {
        const ptr = Module.getExportByName('libc.so', 'fdopendir');
        return new NativeFunction(ptr, 'pointer', ['int']);
    },
    // struct dirent *readdir(DIR *dirp);
    readdir: () => {
        const ptr = Module.getExportByName('libc.so', 'readdir');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    closedir: () => {
        const ptr = Module.getExportByName('libc.so', 'closedir');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // ssize_t readlink(const char *path, char *buf, size_t bufsiz);
    readlink: () => {
        const ptr = Module.getExportByName('libc.so', 'readlink');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'int']);
    },
    read: () => {
        const ptr = Module.getExportByName('libc.so', 'read');
        return new NativeFunction(ptr, 'int', ['int', 'pointer', 'int']);
    },
    // off_t lseek(int fd, off_t offset, int whence);
    lseek: () => {
        const ptr = Module.getExportByName('libc.so', 'lseek');
        return new NativeFunction(ptr, 'pointer', ['int', 'pointer', 'int']);
    },
    // FILE *fopen(const char *restrict pathname, const char *restrict mode);
    fopen: () => {
        const ptr = Module.getExportByName('libc.so', 'fopen');
        return new SystemFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // FILE *fdopen(int fd, const char *mode);
    fdopen: () => {
        const ptr = Module.getExportByName('libc.so', 'fdopen');
        return new SystemFunction(ptr, 'pointer', ['int', 'pointer']);
    },
    // FILE *freopen(const char *restrict pathname, const char *restrict mode, FILE *restrict stream);
    freopen: () => {
        const ptr = Module.getExportByName('libc.so', 'freopen');
        return new SystemFunction(ptr, 'pointer', ['pointer', 'pointer', 'pointer']);
    },
    chmod: () => {
        const ptr = Module.getExportByName('libc.so', 'chmod');
        return new NativeFunction(ptr, 'int', ['pointer', 'int']);
    },
    // int access(const char *pathname, int mode);
    access: () => {
        const ptr = Module.getExportByName('libc.so', 'access');
        return new NativeFunction(ptr, 'int', ['pointer', 'int']);
    },
    // int faccessat(int fd, const char *path, int amode, int flag);
    faccessat: () => {
        const ptr = Module.getExportByName('libc.so', 'faccessat');
        return new NativeFunction(ptr, 'int', ['int', 'pointer', 'int', 'int']);
    },
    // int pthread_create(pthread_t *restrict thread, const pthread_attr_t *restrict attr, void *(*start_routine)(void *), void *restrict arg);
    pthread_create: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_create');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
    },
    // pthread_t pthread_self(void);
    pthread_self: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_self');
        return new NativeFunction(ptr, 'pointer', []);
    },
    // int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr);
    pthread_getattr_np: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_getattr_np');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // double difftime(time_t __time1, time_t __time0)
    difftime: () => {
        const ptr = Module.getExportByName('libc.so', 'difftime');
        return new NativeFunction(ptr, 'double', ['pointer', 'pointer']);
    },
    // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    connect: () => {
        const ptr = Module.getExportByName('libc.so', 'connect');
        return new NativeFunction(ptr, 'int', ['int', 'pointer', 'pointer']);
    },
    // int __system_property_get(const char *name, char *value);
    __system_property_get: () => {
        const ptr = Module.getExportByName('libc.so', '__system_property_get');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int __system_property_read( const prop_info *pi, char *name, char * value);
    __system_property_read: () => {
        const ptr = Module.getExportByName('libc.so', '__system_property_read');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'pointer']);
    },
    // struct hostent *gethostbyname(const char *name);
    gethostbyname: () => {
        const ptr = Module.getExportByName('libc.so', 'gethostbyname');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    // int getaddrinfo(const char *restrict node,
    //                const char *restrict service,
    //                const struct addrinfo *restrict hints,
    //                struct addrinfo **restrict res);
    getaddrinfo: () => {
        const ptr = Module.getExportByName('libc.so', 'getaddrinfo');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
    },
    // int inet_aton(const char *cp, struct in_addr *addr);
    inet_aton: () => {
        const ptr = Module.getExportByName('libc.so', 'inet_aton');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // pid_t fork(void);
    fork: () => {
        const ptr = Module.getExportByName('libc.so', 'fork');
        return new NativeFunction(ptr, 'int', []);
    },
    // int execv(const char *path, char *const argv[]);
    execv: () => {
        const ptr = Module.getExportByName('libc.so', 'execv');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int gettimeofday(struct timeval *restrict tv, struct timezone *_Nullable restrict tz);
    gettimeofday: () => {
        const ptr = Module.getExportByName('libc.so', 'gettimeofday');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
    pthread_mutex_init: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_mutex_init');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int pthread_mutex_lock(pthread_mutex_t *mutex);
    pthread_mutex_lock: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_mutex_lock');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int pthread_mutex_unlock(pthread_mutex_t *mutex);
    pthread_mutex_unlock: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_mutex_unlock');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int pthread_detach(pthread_t thread);
    pthread_detach: () => {
        const ptr = Module.getExportByName('libc.so', 'pthread_detach');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // char *strstr(const char *haystack, const char *needle);
    strstr: () => {
        const ptr = Module.getExportByName('libc.so', 'strstr');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // char *strcasestr(const char *haystack, const char *needle);
    strcasestr: () => {
        const ptr = Module.getExportByName('libc.so', 'strcasestr');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // size_t *strlen(const char *str);
    strlen: () => {
        const ptr = Module.getExportByName('libc.so', 'strlen');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int strcmp(const char *s1, const char *s2);
    strcmp: () => {
        const ptr = Module.getExportByName('libc.so', 'strcmp');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int strncmp(const char *s1, const char *s2);
    strncmp: () => {
        const ptr = Module.getExportByName('libc.so', 'strncmp');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // char *stpcpy(char *restrict dst, const char *restrict src);
    stpcpy: () => {
        const ptr = Module.getExportByName('libc.so', 'stpcpy');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // char *strcpy(char *restrict dst, const char *restrict src);
    strcpy: () => {
        const ptr = Module.getExportByName('libc.so', 'strcpy');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // char *strcat(char *restrict dst, const char *restrict src);
    strcat: () => {
        const ptr = Module.getExportByName('libc.so', 'strcat');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    //  char *fgets(char *restrict s, int n, FILE *restrict stream);
    fgets: () => {
        const ptr = Module.getExportByName('libc.so', 'fgets');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'int', 'pointer']);
    },
    //  int fstat(int fd, struct stat *statbuf);
    stat: () => {
        const ptr = Module.getExportByName('libc.so', 'stat');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    //  int fstat(int fd, struct stat *statbuf);
    fstat: () => {
        const ptr = Module.getExportByName('libc.so', 'fstat');
        return new NativeFunction(ptr, 'int', ['int', 'pointer']);
    },
    //  int fstat(int fd, struct stat *statbuf);
    lstat: () => {
        const ptr = Module.getExportByName('libc.so', 'lstat');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer']);
    },
    // int __statfs64(const char *, size_t, struct statfs *);
    __statfs64: () => {
        const ptr = Module.getExportByName('libc.so', '__statfs64');
        return new NativeFunction(ptr, 'int', ['pointer', 'int', 'pointer']);
    },
    // time_t time(time_t *t);
    time: () => {
        const ptr = Module.getExportByName('libc.so', 'time');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    // struct tm *localtime(const time_t *timep);
    localtime: () => {
        const ptr = Module.getExportByName('libc.so', 'localtime');
        return new NativeFunction(ptr, 'pointer', ['pointer']);
    },
    // ssize_t getline(char **restrict lineptr, size_t *restrict n, FILE *restrict stream);
    getline: () => {
        const ptr = Module.getExportByName('libc.so', 'getline');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'int']);
    },
    // int sscanf(const char *restrict str, const char *restrict format, ...);
    sscanf: () => {
        const ptr = Module.getExportByName('libc.so', 'sscanf');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', '...']);
    },
    // FILE *popen(const char *command, const char *type);
    popen: () => {
        const ptr = Module.getExportByName('libc.so', 'popen');
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer']);
    },
    // FILE *pclose(FD);
    pclose: () => {
        const ptr = Module.getExportByName('libc.so', 'pclose');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // pid_t getpid(void);
    getpid: () => {
        const ptr = Module.getExportByName('libc.so', 'getpid');
        return new NativeFunction(ptr, 'pointer', []);
    },
    // int remove(const char *pathname);
    remove: () => {
        const ptr = Module.getExportByName('libc.so', 'remove');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int remove(const char *pathname);
    unlink: () => {
        const ptr = Module.getExportByName('libc.so', 'unlink');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // [[noretunr]] void exit(int status);
    exit: () => {
        const ptr = Module.getExportByName('libc.so', 'exit');
        return new NativeFunction(ptr, 'void', ['int']);
    },
    // [[noretunr]] void exit(int status);
    _exit: () => {
        const ptr = Module.getExportByName('libc.so', '_exit');
        return new NativeFunction(ptr, 'void', ['int']);
    },
    // [[noretunr]] void abort(int status);
    abort: () => {
        const ptr = Module.getExportByName('libc.so', 'abort');
        return new NativeFunction(ptr, 'void', ['int']);
    },
    // [[noretunr]] void abort(int status);
    raise: () => {
        const ptr = Module.getExportByName('libc.so', 'raise');
        return new NativeFunction(ptr, 'int', ['int']);
    },
    // int rcx(pid_t pid, int sig);
    kill: () => {
        const ptr = Module.getExportByName('libc.so', 'kill');
        return new NativeFunction(ptr, 'int', ['pointer', 'int']);
    },
    // long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
    ptrace: () => {
        const ptr = Module.getExportByName('libc.so', 'ptrace');
        return new NativeFunction(ptr, 'long', ['int', 'int', 'pointer', 'pointer']);
    },
    // int system(const char *command);
    system: () => {
        const ptr = Module.getExportByName('libc.so', 'system');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // int system(const char *command);
    strerror: () => {
        const ptr = Module.getExportByName('libc.so', 'strerror');
        return new NativeFunction(ptr, 'pointer', ['int']);
    },
    // int sprintf ( char * str, const char * format, ... );
    sprintf: () => {
        const ptr = Module.getExportByName('libc.so', 'sprintf');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', '...']);
    },
    // long int atol ( const char * str );
    atoi: () => {
        const ptr = Module.getExportByName('libc.so', 'atol');
        return new NativeFunction(ptr, 'long', ['pointer']);
    },
    // int atoi (const char * str);
    atol: () => {
        const ptr = Module.getExportByName('libc.so', 'atoi');
        return new NativeFunction(ptr, 'int', ['pointer']);
    },
    // long int strtol (const char* str, char** endptr, int base);
    strtol: () => {
        const ptr = Module.getExportByName('libc.so', 'strtol');
        return new NativeFunction(ptr, 'int32', ['pointer', 'pointer', 'int']);
    },
    // unsigned long int strtoul (const char* str, char** endptr, int base);
    strtoul: () => {
        const ptr = Module.getExportByName('libc.so', 'strtoul');
        return new NativeFunction(ptr, 'uint32', ['pointer', 'pointer', 'int']);
    },
    // long long int strtoll (const char* str, char** endptr, int base);
    strtoll: () => {
        const ptr = Module.getExportByName('libc.so', 'strtoll');
        return new NativeFunction(ptr, 'int64', ['pointer', 'pointer', 'int']);
    },
    // unsigned long long int strtoull (const char* str, char** endptr, int base);
    strtoull: () => {
        const ptr = Module.getExportByName('libc.so', 'strtoull');
        return new NativeFunction(ptr, 'uint64', ['pointer', 'pointer', 'int']);
    },
    // int memcmp (const void * ptr1, const void * ptr2, size_t num);
    memcmp: () => {
        const ptr = Module.getExportByName('libc.so', 'memcmp');
        return new NativeFunction(ptr, 'int', ['pointer', 'pointer', 'int']);
    },
    // unsigned long getauxval(unsigned long type);
    getauxval: () => {
        const ptr = Module.getExportByName('libc.so', 'getauxval');
        return new NativeFunction(ptr, 'uint32', ['uint32']);
    },
    // int posix_spawn(pid_t *restrict pid, const char *restrict path,
    //                 const posix_spawn_file_actions_t *restrict file_actions,
    //                 const po six_spawnattr_t *restrict attrp, 
    //                 char *const argv[restrict], 
    //                 char *const envp[restrict]);
    posix_spawn: () => {
        const ptr = Module.getExportByName('libc.so', 'posix_spawn');
        return new NativeFunction(ptr, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']);
    },
    // long syscall(long number, ...);
    syscall: () => {
        const ptr = Module.getExportByName('libc.so', 'syscall');
        return new NativeFunction(ptr, 'int32', ['int32', '...']);
    },
    // char * __cxa_demangle (const char *mangled_name, char *output_buffer, size_t *length, int *status)
    __cxa_demangle: () => {
        // const pt  = Module.getExportByName('libunwindstack.so', '__cxa_demangle');
        const ptr = DebugSymbol.fromName('__cxa_demangle').address;
        return new NativeFunction(ptr, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
    },
};
const LibcFinderProxy = (0,_internal_proxy_js__WEBPACK_IMPORTED_MODULE_0__.proxyCallback)(LibcFinder);

`
  #include <gum/guminterceptor.h>
  #include <stdio.h>
  #include <stdarg.h>

  void init() {
    printf("hi")
  }
`;
//# sourceMappingURL=libc.js.map

/***/ }),

/***/ "./packages/common/dist/define/std.js":
/*!********************************************!*\
  !*** ./packages/common/dist/define/std.js ***!
  \********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   String: () => (/* binding */ StdString)
/* harmony export */ });
class StdString {
    static #STD_STRING_SIZE = 3 * Process.pointerSize;
    handle;
    constructor(ptr = Memory.alloc(StdString.#STD_STRING_SIZE)) {
        this.handle = ptr;
    }
    dispose() {
        const [data, isTiny] = this._getData();
        if (!isTiny) {
            //@ts-ignore
            Java.api.$delete(data);
        }
    }
    disposeToString() {
        const result = this.toString();
        this.dispose();
        return result;
    }
    toString() {
        const [data] = this._getData();
        //@ts-ignore
        return data.readUtf8String();
    }
    _getData() {
        const str = this.handle;
        const isTiny = (str.readU8() & 1) === 0;
        const data = isTiny ? str.add(1) : str.add(2 * Process.pointerSize).readPointer();
        return [data, isTiny];
    }
}

//# sourceMappingURL=std.js.map

/***/ }),

/***/ "./packages/common/dist/define/struct.js":
/*!***********************************************!*\
  !*** ./packages/common/dist/define/struct.js ***!
  \***********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Stat: () => (/* binding */ Stat),
/* harmony export */   Time: () => (/* binding */ Time),
/* harmony export */   Unity: () => (/* binding */ Unity),
/* harmony export */   malloc: () => (/* binding */ malloc),
/* harmony export */   toObject: () => (/* binding */ toObject)
/* harmony export */ });
/* harmony import */ var _internal_proxy_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../internal/proxy.js */ "./packages/common/dist/internal/proxy.js");

const Time = {
    tm: (0,_internal_proxy_js__WEBPACK_IMPORTED_MODULE_0__.proxyStruct)({
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
    timeval: (0,_internal_proxy_js__WEBPACK_IMPORTED_MODULE_0__.proxyStruct)({
        tv_sec: 'int',
        tv_usec: 'int',
    }),
    timezone: (0,_internal_proxy_js__WEBPACK_IMPORTED_MODULE_0__.proxyStruct)({
        tz_minuteswest: 'int',
        tz_dsttime: 'int',
    }),
};
const Stat = {
    timespec: (0,_internal_proxy_js__WEBPACK_IMPORTED_MODULE_0__.proxyStruct)({
        tv_sec: 'long',
        tv_nsec: 'long',
    }),
    stat: (0,_internal_proxy_js__WEBPACK_IMPORTED_MODULE_0__.proxyStruct)({
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
    Il2CppClass: (0,_internal_proxy_js__WEBPACK_IMPORTED_MODULE_0__.proxyStruct)({
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
function malloc(struct) {
    return struct(Memory.alloc(struct.size));
}
function toObject(struct) {
    return Object.assign({}, ...Reflect.ownKeys(struct).map((k) => {
        const { value } = struct[k];
        return { [k]: value };
    }));
}

//# sourceMappingURL=struct.js.map

/***/ }),

/***/ "./packages/common/dist/index.js":
/*!***************************************!*\
  !*** ./packages/common/dist/index.js ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Classes: () => (/* reexport safe */ _define_java_js__WEBPACK_IMPORTED_MODULE_1__.ClassesProxy),
/* harmony export */   ClassesString: () => (/* reexport safe */ _define_java_js__WEBPACK_IMPORTED_MODULE_1__.ClassesString),
/* harmony export */   Enum: () => (/* reexport module object */ _define_enum_js__WEBPACK_IMPORTED_MODULE_4__),
/* harmony export */   Libc: () => (/* reexport safe */ _define_libc_js__WEBPACK_IMPORTED_MODULE_2__.LibcFinderProxy),
/* harmony export */   Std: () => (/* reexport module object */ _define_std_js__WEBPACK_IMPORTED_MODULE_5__),
/* harmony export */   Struct: () => (/* reexport module object */ _define_struct_js__WEBPACK_IMPORTED_MODULE_6__),
/* harmony export */   Text: () => (/* reexport module object */ _text_js__WEBPACK_IMPORTED_MODULE_7__),
/* harmony export */   emitter: () => (/* binding */ emitter),
/* harmony export */   enumerateMembers: () => (/* reexport safe */ _search_js__WEBPACK_IMPORTED_MODULE_3__.enumerateMembers),
/* harmony export */   findClass: () => (/* reexport safe */ _search_js__WEBPACK_IMPORTED_MODULE_3__.findClass),
/* harmony export */   getApplicationContext: () => (/* binding */ getApplicationContext),
/* harmony export */   getFindUnique: () => (/* reexport safe */ _search_js__WEBPACK_IMPORTED_MODULE_3__.getFindUnique),
/* harmony export */   isJWrapper: () => (/* binding */ isJWrapper),
/* harmony export */   isNully: () => (/* binding */ isNully),
/* harmony export */   stacktrace: () => (/* binding */ stacktrace),
/* harmony export */   stacktraceList: () => (/* binding */ stacktraceList),
/* harmony export */   tryNull: () => (/* binding */ tryNull),
/* harmony export */   visualObject: () => (/* reexport safe */ _visualize_js__WEBPACK_IMPORTED_MODULE_9__.visualObject),
/* harmony export */   vs: () => (/* reexport safe */ _visualize_js__WEBPACK_IMPORTED_MODULE_9__.vs)
/* harmony export */ });
/* harmony import */ var events__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! events */ "./node_modules/events/events.js");
/* harmony import */ var _define_java_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./define/java.js */ "./packages/common/dist/define/java.js");
/* harmony import */ var _define_libc_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./define/libc.js */ "./packages/common/dist/define/libc.js");
/* harmony import */ var _search_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./search.js */ "./packages/common/dist/search.js");
/* harmony import */ var _define_enum_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./define/enum.js */ "./packages/common/dist/define/enum.js");
/* harmony import */ var _define_std_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./define/std.js */ "./packages/common/dist/define/std.js");
/* harmony import */ var _define_struct_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./define/struct.js */ "./packages/common/dist/define/struct.js");
/* harmony import */ var _text_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./text.js */ "./packages/common/dist/text.js");
/* harmony import */ var _types_js__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./types.js */ "./packages/common/dist/types.js");
/* harmony import */ var _visualize_js__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./visualize.js */ "./packages/common/dist/visualize.js");










function tryNull(fn) {
    try {
        return fn();
    }
    catch (_) { }
    return null;
}
function isJWrapper(clazzOrName) {
    return typeof clazzOrName === 'object' ? Reflect.has(clazzOrName, '$className') : false;
}
function stacktrace(e) {
    e ??= Classes.Exception.$new();
    return Classes.Log.getStackTraceString(e).split('\n').slice(1).join('\n');
}
function stacktraceList(e) {
    e ??= Classes.Exception.$new();
    const stack = Classes.Log.getStackTraceString(e);
    return `${stack}`
        .split('\n')
        .slice(1)
        .map((s) => s.substring(s.indexOf('at ') + 3).trim());
}
function getApplicationContext() {
    return Classes.ActivityThread.currentApplication().getApplicationContext();
}
const isNully = (ptr) => !ptr || ptr == NULL || `${ptr}` === '0x0';
const emitter = new events__WEBPACK_IMPORTED_MODULE_0__.EventEmitter();
Object.defineProperties(global, {
    Classes: {
        value: _define_java_js__WEBPACK_IMPORTED_MODULE_1__.ClassesProxy,
        writable: false,
    },
    Libc: {
        value: _define_libc_js__WEBPACK_IMPORTED_MODULE_2__.LibcFinderProxy,
        writable: false,
    },
    findClass: {
        value: _search_js__WEBPACK_IMPORTED_MODULE_3__.findClass,
    },
    findChoose: {
        value: _search_js__WEBPACK_IMPORTED_MODULE_3__.findChoose,
    },
    emitter: {
        value: emitter,
    },
});

//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./packages/common/dist/internal/proxy.js":
/*!************************************************!*\
  !*** ./packages/common/dist/internal/proxy.js ***!
  \************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   proxyCallback: () => (/* binding */ proxyCallback),
/* harmony export */   proxyJavaUse: () => (/* binding */ proxyJavaUse),
/* harmony export */   proxyStruct: () => (/* binding */ proxyStruct)
/* harmony export */ });
function mock() {
    return () => {
        throw new Error('Stub');
    };
}
function proxyJavaUse(data) {
    const init = (key) => Java.use(key);
    const cache = {};
    return new Proxy({}, {
        get: (_, name) => {
            const key = data[name];
            return cache[name] || (cache[name] ??= init(key));
        },
        apply: (_, thisArg, argArray) => {
            return thisArg;
        },
    });
}
function proxyCallback(data) {
    const cache = {};
    return new Proxy({}, {
        get: (_, name) => {
            if (name === 'toJSON') {
                return data;
            }
            const init = data[name];
            return cache[name] || (cache[name] ??= init());
        },
        has(_, key) {
            return data.has(key);
        },
        ownKeys(_) {
            return Reflect.ownKeys(data);
        },
        apply: (_, thisArg, argArray) => {
            return thisArg;
        },
    });
}
function proxyStruct(data) {
    const creator = (ptr) => {
        const cache = {};
        let offset = 0x0;
        for (const key in data) {
            const crnt = ptr.add(offset);
            switch (data[key]) {
                case 'string':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readCString();
                        },
                    };
                    offset += Process.pointerSize;
                    break;
                case 'string*':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readPointer().readCString();
                        },
                    };
                    offset += Process.pointerSize;
                    break;
                case 'pointer':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readPointer();
                        },
                    };
                    offset += Process.pointerSize;
                    break;
                case 'int':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readInt();
                        },
                    };
                    offset += 0x4;
                    break;
                case 'long':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readLong();
                        },
                    };
                    offset += 0x8;
                    break;
                case 'short':
                    cache[key] = {
                        ptr: crnt,
                        get value() {
                            return crnt.readShort();
                        },
                    };
                    offset += 0x2;
                    break;
            }
        }
        return new Proxy({}, {
            get: (_, name) => {
                if (name === 'ptr') {
                    return ptr;
                }
                return cache[name];
            },
            has(_, key) {
                return Reflect.has(data, key);
            },
            ownKeys(_) {
                return Reflect.ownKeys(data);
            },
            apply: (_, thisArg, _argArray) => {
                return thisArg;
            },
        });
    };
    let size = 0x0;
    for (const key in data) {
        switch (data[key]) {
            case 'string':
                size += Process.pointerSize;
                break;
            case 'pointer':
                size += Process.pointerSize;
                break;
            case 'int':
                size += 0x4;
                break;
            case 'long':
                size += 0x8;
                break;
            case 'short':
                size += 0x2;
                break;
        }
    }
    size += size % Process.pointerSize;
    creator.size = size;
    return creator;
}

//# sourceMappingURL=proxy.js.map

/***/ }),

/***/ "./packages/common/dist/search.js":
/*!****************************************!*\
  !*** ./packages/common/dist/search.js ***!
  \****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   enumerateMembers: () => (/* binding */ enumerateMembers),
/* harmony export */   findChoose: () => (/* binding */ findChoose),
/* harmony export */   findClass: () => (/* binding */ findClass),
/* harmony export */   getFindUnique: () => (/* binding */ getFindUnique)
/* harmony export */ });
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");

function enumerateMembers(clazz, callback, maxDepth = Number.POSITIVE_INFINITY) {
    let current = clazz;
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
function findClass(className, ...loaders) {
    try {
        const mLoaders = [...(loaders ??= []), ...Java.enumerateClassLoadersSync()];
        for (const loader of mLoaders) {
            try {
                if (loader.loadClass(className)) {
                    const factory = Java.ClassFactory.get(loader);
                    const cls = factory.use(className);
                    return cls;
                }
            }
            catch (notFound) { }
        }
    }
    catch (err) {
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.logger.error({ tag: 'findClass' }, JSON.stringify(err));
    }
    return null;
}
function getFindUnique(logging = true) {
    const found = new Set();
    return (clazzName, fn) => {
        const clazz = findClass(clazzName);
        if (!clazz) {
            logging && _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.logger.info({ tag: 'findUnique' }, `class ${clazzName} not found !`);
            return;
        }
        const ptr = `${clazz.$l.handle}`;
        if (!found.has(ptr)) {
            found.add(ptr);
            fn(clazz);
        }
    };
}
function findChoose(className, callback, ...loaders) {
    const hashes = new Set();
    const results = [];
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
                    if (stop)
                        return results;
                }
            }
            catch (notFound) { }
        }
    }
    catch (err) {
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.logger.error({ tag: 'findChoose' }, JSON.stringify(err));
    }
    return results;
}

//# sourceMappingURL=search.js.map

/***/ }),

/***/ "./packages/common/dist/text.js":
/*!**************************************!*\
  !*** ./packages/common/dist/text.js ***!
  \**************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   base64: () => (/* binding */ base64),
/* harmony export */   maxLengh: () => (/* binding */ maxLengh),
/* harmony export */   noLines: () => (/* binding */ noLines),
/* harmony export */   stringNumber: () => (/* binding */ stringNumber),
/* harmony export */   toByteSize: () => (/* binding */ toByteSize),
/* harmony export */   toHex: () => (/* binding */ toHex),
/* harmony export */   toPrettyType: () => (/* binding */ toPrettyType),
/* harmony export */   uuid: () => (/* binding */ uuid)
/* harmony export */ });
function maxLengh(message, length) {
    const msgString = `${message}`;
    return msgString.substring(0, Math.min(msgString.length, length));
}
function noLines(message) {
    return `${message}`.replaceAll('\n', '\\n');
}
function toHex(decimal, length = 2) {
    return `${'0'.repeat(length - 1)}${Number(decimal).toString(16)}`.slice(-length);
}
function toByteSize(size) {
    const i = size === 0 ? 0 : Math.floor(Math.log(size) / Math.log(1024));
    return `${Number((size / 1024 ** i).toFixed(2)) * 1} ${['B', 'kB', 'MB', 'GB', 'TB'][i]}`;
}
function stringNumber(length) {
    let text = '';
    for (let i = 0; i < length; i++) {
        text += `${Math.floor(Math.random() * 10) % 10}`;
    }
    return text;
}
function uuid() {
    const range = '0123456789abcdefghijklmnopqrstuvwxyz';
    const rnd = () => range.charAt(Math.round(Math.random() * (range.length - 1)));
    const len = (n) => {
        const arr = Array(n);
        for (let i = 0; i < n; i += 1) {
            arr.push(rnd());
        }
        return arr.join('');
    };
    return Array(len(8), len(4), len(4), len(4), len(12)).join('-');
}
const PRIMITIVE_TYPE = {
    Z: 'boolean',
    B: 'byte',
    C: 'char',
    D: 'double',
    F: 'float',
    I: 'int',
    J: 'long',
    S: 'short',
    V: 'void',
};
function toPrettyType(type) {
    const len = type.length;
    for (; type.charAt(0) === '['; type = type.substring(1))
        ;
    const depth = len - type.length;
    if (type.charAt(0) === 'L' && type.charAt(type.length - 1) === ';')
        return type.substring(1, type.length - 1).replaceAll('/', '.') + '[]'.repeat(depth);
    return (PRIMITIVE_TYPE[type] ?? type) + '[]'.repeat(depth);
}
function base64(input) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let output = '';
    let i = 0;
    while (i < input.length) {
        const a = input.charCodeAt(i++);
        const b = input.charCodeAt(i++);
        const c = input.charCodeAt(i++);
        const index1 = a >> 2;
        const index2 = ((a & 3) << 4) | (b >> 4);
        const index3 = Number.isNaN(b) ? 64 : ((b & 15) << 2) | (c >> 6);
        const index4 = Number.isNaN(c) ? 64 : c & 63;
        output += chars.charAt(index1) + chars.charAt(index2) + chars.charAt(index3) + chars.charAt(index4);
    }
    return output;
}

//# sourceMappingURL=text.js.map

/***/ }),

/***/ "./packages/common/dist/types.js":
/*!***************************************!*\
  !*** ./packages/common/dist/types.js ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);

//# sourceMappingURL=types.js.map

/***/ }),

/***/ "./packages/common/dist/visualize.js":
/*!*******************************************!*\
  !*** ./packages/common/dist/visualize.js ***!
  \*******************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   visualObject: () => (/* binding */ visualObject),
/* harmony export */   vs: () => (/* binding */ vs)
/* harmony export */ });
/* harmony import */ var _clockwork_jnitrace__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/jnitrace */ "./packages/jnitrace/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _define_java_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./define/java.js */ "./packages/common/dist/define/java.js");
/* harmony import */ var _text_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./text.js */ "./packages/common/dist/text.js");




const { black, gray, red, green, cyan, dim, italic, bold, yellow, hidden } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.use();
function vs(value, type, jniEnv = Java.vm.tryGetEnv()?.handle) {
    if (value === undefined)
        return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(undefined);
    if (value === null)
        return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(null);
    //loop over array until max length
    if (type?.endsWith('[]')) {
        const itemType = type.substring(type.length - 3);
        const items = [];
        const size = value.size ?? value.length;
        6;
        let messageSize = 0;
        for (let i = 0; i < size; i += 1) {
            const mapped = `${value[i]}`;
            items.push(mapped);
            messageSize += mapped.length;
            if ((messageSize > 200 || i >= 16) && i + 1 < size) {
                items.push(gray(' ... '));
                break;
            }
        }
        if (items.length === 0)
            return black('[]');
        return `${black('[')} ${items.join(black(', '))} ${black(']')}`;
    }
    // select by provided type
    switch (type) {
        case 'boolean':
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(value ? 'true' : 'false');
        case 'byte': {
            const strByte = `0x${(0,_text_js__WEBPACK_IMPORTED_MODULE_3__.toHex)(value)}`;
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(strByte);
        }
        case 'char': {
            //@ts-ignore
            const strChar = Classes.String.valueOf.overload('char').bind(Classes.String);
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.char(strChar(value));
        }
        case 'short': {
            //@ts-ignore
            const strShort = Classes.String.valueOf.overload('short').bind(Classes.String);
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(strShort(value));
        }
        case 'int': {
            //@ts-ignore
            const strInt = Classes.String.valueOf.overload('int').bind(Classes.String);
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(strInt(Number(value)));
        }
        case 'float': {
            //@ts-ignore
            const strFloat = Classes.String.valueOf.overload('float').bind(Classes.String);
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(strFloat(Number(value)));
        }
        case 'double': {
            //@ts-ignore
            const strDoubke = Classes.String.valueOf.overload('double').bind(Classes.String);
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(strDoubke(value));
        }
        case 'long':
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(`${new Int64(value.toString())}`);
    }
    // select by actual value type
    switch (typeof value) {
        case 'string':
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.string(value);
        case 'boolean':
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(value ? 'true' : 'false');
        case 'number':
        case 'bigint':
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(value);
    }
    // * should only have java objects in here
    const classHandle = value.$h ?? value;
    const handleStr = `${classHandle}`;
    // console.log(value, type, typeof value, value.$h, value instanceof NativePointer);
    // return `${classHandle}`;
    if (handleStr === '0x0') {
        return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(null);
    }
    if (classHandle) {
        const text = (handleStr.length === 12) ? (0,_clockwork_jnitrace__WEBPACK_IMPORTED_MODULE_0__.asLocalRef)(jniEnv, classHandle, (ptr) => visualObject(ptr, type)) : visualObject(classHandle, type);
        if (text)
            return text;
    }
    return black(`${value}`);
}
function visualObject(value, type) {
    // ? do not ask, i have no idea why this prevents crashes
    // String(value) + String(value.readByteArray(8));
    try {
        if (type === _define_java_js__WEBPACK_IMPORTED_MODULE_2__.ClassesString.String) {
            const str = Java.cast(value, Classes.String);
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.string(str);
        }
        if (type === _define_java_js__WEBPACK_IMPORTED_MODULE_2__.ClassesString.InputDevice) {
            const dev = Java.cast(value, Classes.InputDevice);
            return `${_define_java_js__WEBPACK_IMPORTED_MODULE_2__.ClassesString.InputDevice}(name=${dev.getName()})`;
        }
        if (type === _define_java_js__WEBPACK_IMPORTED_MODULE_2__.ClassesString.OpenSSLX509Certificate) {
            const win = Java.cast(value, Classes.OpenSSLX509Certificate);
            return `${_define_java_js__WEBPACK_IMPORTED_MODULE_2__.ClassesString.OpenSSLX509Certificate}(issuer=${win.getIssuerX500Principal()})`;
        }
        if (type === _define_java_js__WEBPACK_IMPORTED_MODULE_2__.ClassesString.Certificate) {
            const win = Java.cast(value, Classes.Certificate);
            return `${_define_java_js__WEBPACK_IMPORTED_MODULE_2__.ClassesString.Certificate}(issuer=${win.getType()})`;
        }
        if (type === _define_java_js__WEBPACK_IMPORTED_MODULE_2__.ClassesString.WindowInsets) {
            const win = Java.cast(value, Classes.WindowInsets);
            return `${_define_java_js__WEBPACK_IMPORTED_MODULE_2__.ClassesString.WindowInsets}(frame=${win.getFrame()})`;
        }
        const object = Java.cast(value, Classes.Object);
        //@ts-ignore
        return Classes.String.valueOf(object);
    }
    catch (e) {
        return black(`${e.message} ${black('<')}${dim(`${value}`)}${black('>')}${black(`${typeof value}:${type}`)}`);
    }
}

//# sourceMappingURL=visualize.js.map

/***/ }),

/***/ "./packages/dump/dist/dexDump.js":
/*!***************************************!*\
  !*** ./packages/dump/dist/dexDump.js ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   dexBytesVerify: () => (/* binding */ verify),
/* harmony export */   scheduleDexDump: () => (/* binding */ scheduleDexDump)
/* harmony export */ });
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _clockwork_native__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/native */ "./packages/native/dist/index.js");
/* harmony import */ var _clockwork_native_dist_utils_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @clockwork/native/dist/utils.js */ "./packages/native/dist/utils.js");



const logger = (0,_clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.subLogger)('dexdump');
const FLAG_ENABLE_DEEP_SEARCH = false;
function dump() {
    let enable_deep_search = FLAG_ENABLE_DEEP_SEARCH;
    (0,_clockwork_native_dist_utils_js__WEBPACK_IMPORTED_MODULE_2__.mkdir)(`${(0,_clockwork_native__WEBPACK_IMPORTED_MODULE_1__.getSelfFiles)()}/frida_dumped_files/`);
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
            }
            else {
                buffer = buf;
            }
            // For Device
            //@ts-ignore
            const file = new File(
            //@ts-ignore
            `${(0,_clockwork_native__WEBPACK_IMPORTED_MODULE_1__.getSelfFiles)()}/frida_dumped_files/${scandex.addr}.dex`, 'wb');
            file.write(buffer);
            file.flush();
            file.close();
        }
        catch (e) {
            logger.warn(e);
        }
    });
    function getBytesFromString(str) {
        const buffer = new ArrayBuffer(str.length);
        for (let i = 0; i < str.length; ++i) {
            const code = str.charCodeAt(i);
            buffer[i] = [code & 0xff, (code / 256) >>> 0];
        }
        return buffer;
    }
    function getConcatByteArrays(array1, array2) {
        logger.trace(typeof array1);
        // logger.trace(array2)
        const buffer = new ArrayBuffer(array1.byteLength + array2.byteLength);
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
    function memorydump(address, size) {
        // return new NativePointer(address).readByteArray(size);
        return address.readByteArray(size);
    }
    function switchmode(bool) {
        enable_deep_search = bool;
    }
    function scandex() {
        const result = [];
        Process.enumerateRanges('r--').forEach((range) => {
            try {
                Memory.scanSync(range.base, range.size, '64 65 78 0a 30 ?? ?? 00').forEach((match) => {
                    // range.file.path.startsWith("/data/app/") ||
                    if (range?.file?.path?.startsWith('/data/dalvik-cache/') ||
                        range?.file?.path?.startsWith('/system/')) {
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
                }
                else {
                    if (range.base.readCString(4) != 'dex\n' && verify(range.base, range, true)) {
                        const dex_size = range.base.add(0x20).readUInt();
                        result.push({ addr: range.base, size: dex_size });
                    }
                }
            }
            catch (e) { }
        });
        return result;
    }
}
function verify(dexptr, range, enable_verify_maps) {
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
        }
        else {
            return dexptr.add(0x3c).readUInt() === 0x70;
        }
    }
}
function verifyByMaps(dexptr, mapsptr) {
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
            }
            catch (err) {
                logger.warn(`failed to dump:${err.message}`);
                return;
            }
            logger.info('finish dumping');
        });
    }, delay);
}

//# sourceMappingURL=dexDump.js.map

/***/ }),

/***/ "./packages/dump/dist/index.js":
/*!*************************************!*\
  !*** ./packages/dump/dist/index.js ***!
  \*************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   dexBytesVerify: () => (/* reexport safe */ _dexDump_js__WEBPACK_IMPORTED_MODULE_0__.dexBytesVerify),
/* harmony export */   dumpLibSync: () => (/* reexport safe */ _soDump_js__WEBPACK_IMPORTED_MODULE_1__.dumpLibSync),
/* harmony export */   initSoDump: () => (/* reexport safe */ _soDump_js__WEBPACK_IMPORTED_MODULE_1__.initSoDump),
/* harmony export */   scheduleDexDump: () => (/* reexport safe */ _dexDump_js__WEBPACK_IMPORTED_MODULE_0__.scheduleDexDump)
/* harmony export */ });
/* harmony import */ var _dexDump_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./dexDump.js */ "./packages/dump/dist/dexDump.js");
/* harmony import */ var _soDump_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./soDump.js */ "./packages/dump/dist/soDump.js");


//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./packages/dump/dist/soDump.js":
/*!**************************************!*\
  !*** ./packages/dump/dist/soDump.js ***!
  \**************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   dumpLibSync: () => (/* binding */ dumpLibSync),
/* harmony export */   initSoDump: () => (/* binding */ initSoDump)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _clockwork_native__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @clockwork/native */ "./packages/native/dist/index.js");
/* harmony import */ var _clockwork_native_dist_utils_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! @clockwork/native/dist/utils.js */ "./packages/native/dist/utils.js");
/* harmony import */ var frida_buffer__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! frida-buffer */ "./node_modules/frida-buffer/index.js");





//base64 encoded elf files
const soFixer32 = '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EQAQAAAsAABYDAIAJgAAABEADwDVAwAAx7AAAB4AAAASAAwAOyoAAMA0AgAIAAAAEQAQAEEqAAAYNwIACAAAABEAEABHKgAAQDcCAAgAAAARABAATSoAAPA2AgAIAAAAEQAQAFMqAABoNwIACAAAABEAEABZKgAA6DQCAAgAAAARABAAViwAAJ4KAgAuAAAAEQAPAEIlAAB1IgEAeAAAABIADABfKgAAiDUCAAgAAAARABAANDgAAAc9AQAEAAAAEgAMAKMBAACxtgAAVAEAACIADADwEwAAufkAAEgAAAASAAwA+SIAAHseAQAGAAAAEgAMAGUqAACwNQIACAAAABEAEAB/NgAAUA0CABQAAAARAA8AvwwAAOfuAAAWAAAAIgAMAGsqAADYNQIACAAAABEAEACQAgAA0bsAAFwAAAASAAwAdRsAAJw4AgAoAAAAEQAQAHEqAAAANgIACAAAABEAEABVMwAA7TsBACgAAAASAAwAdyoAAHg2AgAIAAAAEQAQAPs3AAAhPQEAEAAAABIADABcOAAAQDsCAAwAAAARABAAxjgAAPQ6AgAUAAAAEQAQAH0qAACgNgIACAAAABEAEACRMQAAizsBAAQAAAASAAwAZzcAAD09AQAQAAAAEgAMAIwBAADNvAAAfAAAACIADADUGwAAeRUBABAAAAAiAAwA3SwAAD4LAgAEAAAAEQAPAHoDAAARuwAAwAAAABIADACgBgAASb4AAI4AAAASAAwA5SwAABoLAgAEAAAAEQAPAH84AAB9DQIADwAAABEADwCDKgAAODUCAAgAAAARABAA7SwAACwLAgAEAAAAEQAPAGQUAABd+wAASAAAACIADACJKgAAYDUCAAgAAAARABAA9SwAALYLAgAEAAAAEQAPAA85AAD9PQEAMAAAABIADAD9LAAAvwsCAAQAAAARAA8AhB4AAPUaAQAoAAAAEgAMAAsiAAD1HQEAMAAAABIADACPKgAAIDQCAAgAAAARABAABS0AAK0LAgAEAAAAEQAPAJUqAACYNAIACAAAABEAEAANLQAAyAsCAAQAAAARAA8AfS0AADsLAgADAAAAEQAPAP0xAACqDAIAGQAAABEADwAdNwAAKDoCABQAAAARABAAfhIAAEg6AgAUAAAAEQAQAJsqAAAoNgIACAAAABEAEAAVLQAANQsCAAQAAAARAA8AhC0AABcLAgADAAAAEQAPAKEqAABQNgIACAAAABEAEAAdLQAAWQsCAAQAAAARAA8Aiy0AACkLAgADAAAAEQAPANECAABVvQAAkAAAABIADAAVKAAA+DgCAAwAAAARABAAJS0AAGILAgAEAAAAEQAPAJItAACzCwIAAwAAABEADwB9BgAASb4AAI4AAAASAAwAwxMAAMH1AAD8AAAAEgAMAD8oAAAUNAIADAAAABEAEACZLQAAvAsCAAMAAAARAA8ANjcAAGE9AQAMAAAAEgAMAC0tAABrCwIABAAAABEADwCgLQAAqgsCAAMAAAARAA8A9TAAAN07AQAEAAAAEgAMAFA3AAAxPQEADAAAABIADABMAAAA/7kAAHoAAAASAAwACwQAABkkAQBAAAAAEgAMAEgEAAB0OAIAKAAAABEAEAA0GAAALQIBAEQAAAAiAAwANS0AAHQLAgAEAAAAEQAPAKctAADFCwIAAwAAABEADwBINAAA5TwBABAAAAASAAwAYCsAADMKAgAiAAAAEQAPAD0tAACPCwIABAAAABEADwCuLQAAMgsCAAMAAAARAA8AqDkAABRQAgAAAAAAEADx/2wmAACwOQIADAAAABEAEABFLQAAmAsCAAQAAAARAA8AtS0AAFYLAgADAAAAEQAPAKI4AABkDQIADQAAABEADwA0AgAA2bQAAPQAAAASAAwAvC0AAF8LAgADAAAAEQAPAD8vAAAwOAIAHAAAABEAEAAuEwAA6fgAANAAAAASAAwAMxwAAIkVAQAOAAAAIgAMAAEeAAAAUAIABAAAABEAFAB1JwAArDMCAAwAAAARABAAwy0AAGgLAgADAAAAEQAPACkaAABV/QAAjAAAACIADAAEJwAAlDMCAAwAAAARABAATS0AAEcLAgAEAAAAEQAPAMotAABxCwIAAwAAABEADwBxCQAAa84AACoAAAAiAAwAVS0AAFALAgAEAAAAEQAPANEtAACMCwIAAwAAABEADwDNIwAABSQBABQAAAASAAwA2C0AAJULAgADAAAAEQAPAF0tAAAFCwIABAAAABEADwCxAAAA07gAABwAAAASAAwAPxsAABgzAgAMAAAAEQAQAGUtAAAjCwIABAAAABEADwArMgAAfgwCAA0AAAARAA8A5wMAACGwAACIAAAAEgAMAG0tAAB9CwIABAAAABEADwB1LQAAhgsCAAQAAAARAA8A3y0AAEQLAgADAAAAEQAPAC8wAADhOwEADAAAABIADAA5CAAAk+EAAG4AAAAiAAwA5i0AAE0LAgADAAAAEQAPAO8BAABJvQAADAAAACIADAARJQAA+SEBABwAAAASAAwA7S0AAAILAgADAAAAEQAPAPQtAAAgCwIAAwAAABEADwB3IwAAgR4BACgAAAASAAwA+y0AAHoLAgADAAAAEQAPAEg4AAAFPQEAAgAAABIADAAFFAAAufkAAEgAAAASAAwAAi4AAIMLAgADAAAAEQAPAEcBAAB5ugAAlgAAABIADABCBwAAsekAABQAAAAiAAwAbTMAAO07AQAoAAAAEgAMAMUOAABL3QAALgAAACIADADvIQAAJR4BACwAAAASAAwA5zEAAIsMAgASAAAAEQAPAA44AAAdPQEABAAAABIADAClMQAAiTsBAAIAAAASAAwAKDYAAPkMAgARAAAAEQAPACoZAACx/gAAJAAAACIADAC8JgAAyDYCAAgAAAARABAAfTcAAD09AQAQAAAAEgAMAMMmAADgNwIACAAAABEAEACILAAAnwsCAAQAAAARAA8AYiUAABEjAQAQAAAAEgAMAJAsAADnCwIABAAAABEADwD9MwAAgTwBABAAAAASAAwAyiYAAEg0AgAIAAAAEQAQAKYuAADcMwIAHAAAABEAEAA7CwAAu+YAAC4AAAAiAAwAmCwAAAwLAgAEAAAAEQAPAJ4dAADhGAEASAAAACIADAAoDgAAjeQAABIAAAAiAAwA0SYAALg3AgAIAAAAEQAQALseAACpGwEABAAAACIADAAVMQAAiTsBAAIAAAASAAwAszgAAAg7AgAUAAAAEQAQANgmAACQNwIACAAAABEAEABiNAAAWTwBACgAAAASAAwAsAIAAM2xAAA0AQAAEgAMACIUAABtAQEAYAAAACIADACgLAAA2wsCAAQAAAARAA8AJwMAAM2zAAAMAQAAEgAMADgjAAB1HgEABgAAABIADACbJwAAuDMCAAwAAAARABAACS4AADkLAgACAAAAEQAPAAgdAAC5GQEAxAAAACIADACoLAAAzwsCAAQAAAARAA8ADy4AABULAgACAAAAEQAPAJY0AAD1PAEAEAAAABIADADuNgAAtDoCABQAAAARABAAFS4AACcLAgACAAAAEQAPABsuAACxCwIAAgAAABEADwBpMQAAvTsBAAQAAAASAAwADgoAAMHeAABYAQAAIgAMACEuAAC6CwIAAgAAABEADwAnLgAAqAsCAAIAAAARAA8AqRsAAM0XAQC8AAAAEgAMAC0uAADDCwIAAgAAABEADwBSNgAAKw0CABIAAAARAA8AMy4AADALAgACAAAAEQAPALgbAACRFgEAPAEAABIADACGKwAAVQoCACQAAAARAA8AOS4AAFQLAgACAAAAEQAPAAoCAAC5vAAAFAAAACIADAD5AwAAIbAAAIgAAAASAAwAsQoAAM3nAACsAAAAIgAMAD8uAABdCwIAAgAAABEADwA0JQAAnSEBAFwAAAASAAwARS4AAGYLAgACAAAAEQAPAGM1AAAcOgIADAAAABEAEAAeKgAALDsCAAgAAAARABAASy4AAG8LAgACAAAAEQAPAO4GAABVwAAADAAAACIADACMCAAAffAAABIAAAAiAAwALyAAAK0gAQB4AAAAEgAMAOwnAADEOAIADAAAABEAEABRLgAAigsCAAIAAAARAA8AnyIAAFEeAQASAAAAEgAMALgjAACFJAEAFAAAABIADABXLgAAkwsCAAIAAAARAA8AOiYAAAhQAgAEAAAAEQAUAKgmAAAFPQEAAgAAABIADAD1JQAAzSQBACQAAAASAAwAGjIAAJ0MAgANAAAAEQAPAF0uAABCCwIAAgAAABEADwBjLgAASwsCAAIAAAARAA8AszIAAEU8AQAQAAAAEgAMANYxAACUOQIACAAAABEAEACNNQAAnDoCAAwAAAARABAAITgAAB09AQAEAAAAEgAMALsiAACJOwEAAgAAABIADABpLgAAAAsCAAIAAAARAA8A7hQAAB0BAQBOAAAAIgAMAOggAACFHAEAPAAAABIADABvLgAAHgsCAAIAAAARAA8Ayy4AAAg4AgAcAAAAEQAQAAMwAABxNQEA1AAAABIADAD4MgAA1TwBABAAAAASAAwA0gYAAGHAAAAMAAAAIgAMAPgaAABL/wAAIgAAACIADAB1LgAAeAsCAAIAAAARAA8AtTMAAMU8AQAQAAAAEgAMAHsuAACBCwIAAgAAABEADwCSOAAAcQ0CAAwAAAARAA8AFjQAAFk8AQAoAAAAEgAMAKwQAABd5QAAtAAAACIADACrHwAASxwBAAQAAAAiAAwA1QEAADW+AAASAAAAIgAMAIUNAABV5gAALgAAACIADAAiJgAABFACAAQAAAARABQAwycAAMQzAgAMAAAAEQAQAHECAABdsQAAcAAAABIADADcBQAAHdcAAIgBAAASAAwAMhUAAB3/AAAuAAAAIgAMALYVAABHAwEAeAAAACIADAA1MQAAiTsBAAIAAAASAAwATAYAAB/cAADEAAAAIgAMAHw0AABZPAEAKAAAABIADAChEgAAqR4BACoAAAASAAwA5zQAAKU8AQAQAAAAEgAMAGEDAADNtQAA5AAAABIADACxNAAAWTwBACgAAAASAAwA1ysAADMMAgAlAAAAEQAPAFkeAACJOwEAAgAAABIADABuBAAApRsBAAQAAAAiAAwAVhMAAHX3AAB0AQAAEgAMAN8mAABoOAIADAAAABEAEAAMFwAA3/wAABYAAAAiAAwAuhwAAI8ZAQAqAAAAIgAMAHsyAABVPAEABAAAABIADAD/BQAA684AAF4AAAASAAwA0BkAAOH9AAC0AAAAIgAMADorAAARCgIAIgAAABEADwDoJAAAOSMBAEgAAAASAAwAtAgAADXjAAAQAAAAIgAMAFUOAADH3QAAHAAAACIADAAMIAAAMRwBABoAAAAiAAwAexwAAKUVAQBKAAAAIgAMANAkAACLHwEABAAAABIADAAqBAAA1gkCAAsAAAARAA8AFSQAAJEfAQBYAAAAEgAMAIIEAAAdGwEARAAAACIADADwLwAA8awBABAAAAASAAwAozUAAMg6AgAMAAAAEQAQAMoyAADtOwEAKAAAABIADAAMEwAAMfMAAGwBAAASAAwAxSgAAOA2AgAQAAAAEQAQAM4oAAD4NwIAEAAAABEAEACuKwAAeQoCACUAAAARAA8ADzMAAFk8AQAoAAAAEgAMAM0zAADtOwEAKAAAABIADADrNQAA1AwCABAAAAARAA8ArzkAABRQAgAAAAAAEADx/8Q2AAD8OQIAFAAAABEAEADXKAAAYDQCABAAAAARABAAFy8AACA5AgAcAAAAEQAQAC80AABZPAEAKAAAABIADAC6NQAA6DoCAAwAAAARABAAwB8AAE8cAQAaAAAAIgAMAHwkAAAlIQEAPgAAABIADACxAwAA8a8AADAAAAASAAwAqh4AALw5AgAMAAAAEQAQAIEuAABMOAIAHAAAABEAEADyIwAA4x4BABwAAAASAAwAmgUAAKW/AACwAAAAEgAMAOAoAADQNwIAEAAAABEAEADpKAAAqDcCABAAAAARABAAuTEAAMg5AgAMAAAAEQAQAEI5AAAlPwEAZAIAABIADACwLAAAowsCAAUAAAARAA8AuSwAAOsLAgAFAAAAEQAPAGswAACROwEADAAAABIADAAeHAAAuRMBADQAAAAiAAwAAzUAAO07AQAoAAAAEgAMADkEAADgMgIAGAAAABEAEABtHgAA8SQBABQAAAASAAwAzDQAAFk8AQAoAAAAEgAMAKYUAADx/wAApAAAACIADADCLAAAEAsCAAUAAAARAA8AfTEAAIk7AQACAAAAEgAMANU3AAANPQEAEAAAABIADAApHwAAnRsBAAQAAAAiAAwAczkAAAGtAQAQAAAAEgAMAL0BAADlvQAARAAAACIADABrKAAA0DMCAAwAAAARABAAnyQAAGUeAQAAAAAAEgAMAJM3AABRPQEAEAAAABIADAALBwAAa9sAAAwAAAAiAAwAyywAAN8LAgAFAAAAEQAPAP81AAAbDQIAEAAAABEADwCCJgAAnDkCABQAAAARABAA1CwAANMLAgAFAAAAEQAPAE8nAACgMwIADAAAABEAEABTMAAAwTsBAAwAAAASAAwAtTAAAM07AQAQAAAAEgAMAA0JAADt8AAArAEAACIADACnKgAAnAsCAAMAAAARAA8AURsAAOEJAgAOAAAAEQAPAK4qAADkCwIAAwAAABEADwDhMgAA7TsBACgAAAASAAwAiRgAAKv6AAAkAAAAIgAMALAPAACf6wAAIAAAACIADABaIAAA/RwBADAAAAASAAwAhxoAAJUAAQCIAAAAIgAMACYzAABZPAEAKAAAABIADADlMwAA7TsBACgAAAASAAwAsSQAAP8eAQAEAAAAEgAMALUqAAAJCwIAAwAAABEADwBDIQAALR0BACwAAAASAAwA7yoAAPAJAgAhAAAAEQAPAPIoAAAoNQIAEAAAABEAEAD6KAAAiDQCABAAAAARABAAeDUAAHw6AgAMAAAAEQAQAAIpAADYNAIAEAAAABEAEADDAwAA8a8AADAAAAASAAwAxwcAAFHpAABgAAAAIgAMAGkPAACD3QAAJAAAACIADADmHgAAexwBAAQAAAAiAAwACikAADA3AgAQAAAAEQAQALwqAADYCwIAAwAAABEADwASKQAAWDcCABAAAAARABAAgB8AAHEcAQAGAAAAIgAMABopAAAINwIAEAAAABEAEADDKgAAzAsCAAMAAAARAA8A8S4AAAQ5AgAcAAAAEQAQAJYyAACRPAEABAAAABIADADiAAAAgbkAABwAAAASAAwAnR4AAO8JAgABAAAAEQAPACIpAACANwIAEAAAABEAEABcJAAAFSIBAGAAAAASAAwAKikAAAA1AgAQAAAAEQAQAIUzAAC1PAEAEAAAABIADAAyKQAAoDUCABAAAAARABAAPDIAAGw5AgAUAAAAEQAQADs1AAAQOgIADAAAABEAEADDGwAAFQ8BAKQEAAASAAwAJiIAALkdAQA8AAAAEgAMADopAADINQIAEAAAABEAEAAfNQAA7TsBACgAAAASAAwAQikAAPA1AgAQAAAAEQAQAJIpAAAYNQIAEAAAABEAEABKKQAAGDYCABAAAAARABAAmSkAAHg0AgAQAAAAEQAQAGg2AAA9DQIAEwAAABEADwBSKQAAkDYCABAAAAARABAAoCkAAMg0AgAQAAAAEQAQAFopAAC4NgIAEAAAABEAEACnKQAAIDcCABAAAAARABAA6DcAAA09AQAQAAAAEgAMAK4pAABINwIAEAAAABEAEABjGwAAADMCABgAAAARABAAtSkAAPg2AgAQAAAAEQAQAHoFAACl2AAAqAIAABIADAC8KQAAcDcCABAAAAARABAAqTcAAE09AQAEAAAAEgAMAHwEAAB7GwEABAAAACIADABiKQAAUDUCABAAAAARABAAwykAAPA0AgAQAAAAEQAQANk2AABoOgIAFAAAABEAEABqKQAAeDUCABAAAAARABAAyikAAJA1AgAQAAAAEQAQAIMwAACdOwEABAAAABIADAAgAgAAqbAAAB4AAAAiAAwAKAcAAE3bAAAMAAAAIgAMANEpAAC4NQIAEAAAABEAEACVAwAALbwAAIwAAAASAAwAcikAADg0AgAQAAAAEQAQAHopAACwNAIAEAAAABEAEADYKQAA4DUCABAAAAARABAAPh8AAGkcAQAEAAAAIgAMAIIpAABANgIAEAAAABEAEADfKQAACDYCABAAAAARABAAiikAAGg2AgAQAAAAEQAQAOYpAACANgIAEAAAABEAEAATNgAAwwwCABEAAAARAA8A4xcAAH36AAAuAAAAIgAMAFcdAADvFQEASAAAACIADADtKQAAqDYCABAAAAARABAA+BsAANcUAQAQAAAAIgAMANUwAADNOwEAEAAAABIADAAEAwAAAbMAAMwAAAASAAwAvwkAAJ3vAADgAAAAIgAMAPQpAABANQIAEAAAABEAEABPNQAAqDoCAAwAAAARABAA1jgAABw7AgAQAAAAEQAQAJ4bAACJGAEAPAAAABIADAD7KQAAaDUCABAAAAARABAAugQAAD0gAQBwAAAAEgAMAMMGAADZvgAAkAAAACIADAC+CwAAqewAAIwAAAAiAAwAAioAACg0AgAQAAAAEQAQAAkqAACgNAIAEAAAABEAEABFHgAArTsBABAAAAASAAwA+iQAAIEjAQA0AAAAEgAMABAqAAAwNgIAEAAAABEAEAAXKgAAWDYCABAAAAARABAACh8AAK0bAQAEAAAAIgAMAM8iAADUOQIAFAAAABEAEAAUAQAAZbkAABwAAAASAAwAcyAAAIUcAQA8AAAAEgAMAGoyAACAOQIAFAAAABEAEAAVDwAAEesAAEQAAAAiAAwAgBcAANX+AAAuAAAAIgAMAJ0oAADQNgIAEAAAABEAEAClKAAA6DcCABAAAAARABAAfxkAAA3/AAAQAAAAIgAMAPwdAAA5FgEAWAAAABIADADjIgAA6DkCABQAAAARABAAAF9fY3hhX2F0ZXhpdABMSUJDAGxpYmMuc28AbGliZHVtcGZpeGVyLnNvAF9fY3hhX2ZpbmFsaXplAF9fcmVnaXN0ZXJfYXRmb3JrAF9aMjRwaGRyX3RhYmxlX2dldF9hcm1fZXhpZHhQSzEwRWxmMzJfUGhkcmlQaFBQalMzXwBfWjI0cGhkcl90YWJsZV9nZXRfbG9hZF9zaXplUEsxMEVsZjMyX1BoZHJqUGpTMl8AX1oyN3BoZHJfdGFibGVfcHJvdGVjdF9zZWdtZW50c1BLMTBFbGYzMl9QaGRyaVBoAF9aMjhwaGRyX3RhYmxlX3Byb3RlY3RfZ251X3JlbHJvUEsxMEVsZjMyX1BoZHJpUGgAX1oyOXBoZHJfdGFibGVfdW5wcm90ZWN0X3NlZ21lbnRzUEsxMEVsZjMyX1BoZHJpUGgAX1ozMHBoZHJfdGFibGVfZ2V0X2R5bmFtaWNfc2VjdGlvblBLMTBFbGYzMl9QaGRyaVBoUFA5RWxmMzJfRHluUGpTNl8AX1pOMTBGaWxlUmVhZGVyNE9wZW5FdgBfWk4xMEZpbGVSZWFkZXI0UmVhZEVQdmppAF9aTjEwRmlsZVJlYWRlcjVDbG9zZUV2AF9aTjEwRmlsZVJlYWRlcjdJc1ZhbGlkRXYAX1pOMTBGaWxlUmVhZGVyOEZpbGVTaXplRXYAX1pOMTBGaWxlUmVhZGVyQzJFUEtjAF9aTjEwRmlsZVJlYWRlckQyRXYAX1pOOUVsZlJlYWRlcjEyTG9hZFNlZ21lbnRzRXYAX19nbnVfVW53aW5kX0ZpbmRfZXhpZHgATElCQ19OAF9aTjlFbGZSZWFkZXIxM1JlYWRFbGZIZWFkZXJFdgBfWk45RWxmUmVhZGVyMTRBcHBseVBoZHJUYWJsZUV2AF9aTjlFbGZSZWFkZXIxNVZlcmlmeUVsZkhlYWRlckV2AF9aTjlFbGZSZWFkZXIxN0dldER5bmFtaWNTZWN0aW9uRVBQOUVsZjMyX0R5blBqUzNfAF9aTjlFbGZSZWFkZXIxN1JlYWRQcm9ncmFtSGVhZGVyRXYAX1pOOUVsZlJlYWRlcjE5UmVzZXJ2ZUFkZHJlc3NTcGFjZUVqAF9aTjlFbGZSZWFkZXI0TG9hZEV2AF9aTjlFbGZSZWFkZXI4RmluZFBoZHJFdgBfWk45RWxmUmVhZGVyOUNoZWNrUGhkckVQaABfWk45RWxmUmVhZGVyOXNldFNvdXJjZUVQS2MAX1pOOUVsZlJlYWRlckMxRXYAX1pOOUVsZlJlYWRlckMyRXYAX1pOOUVsZlJlYWRlckQwRXYAX1pOOUVsZlJlYWRlckQxRXYAX1pOOUVsZlJlYWRlckQyRXYAX1pTdDl0ZXJtaW5hdGV2AF9aVEk5RWxmUmVhZGVyAF9aVFM5RWxmUmVhZGVyAF9aVFY5RWxmUmVhZGVyAF9aVFZOMTBfX2N4eGFiaXYxMTdfX2NsYXNzX3R5cGVfaW5mb0UAX1pkYVB2AF9aZGxQdgBfWm5hagBfWm53agBfX2FlYWJpX21lbWNweQBfX2FlYWJpX21lbXNldABfX2FuZHJvaWRfbG9nX3ByaW50AF9fY3hhX2JlZ2luX2NhdGNoAF9fZXJybm8AX19mcmVhZF9jaGsAX19neHhfcGVyc29uYWxpdHlfdjAAX19tZW1jcHlfY2hrAF9fbWVtc2V0X2NoawBfX3N0YWNrX2Noa19mYWlsAF9fc3RhY2tfY2hrX2d1YXJkAGZjbG9zZQBmb3BlbgBmcmVhZABmc2VlawBmdGVsbABzdHJlcnJvcgBfWk4xMkVsZlJlYnVpbGRlcjEwUmVhZFNvSW5mb0V2AF9aTjEyRWxmUmVidWlsZGVyMTBSZWJ1aWxkRmluRXYAX1pOMTJFbGZSZWJ1aWxkZXIxMVJlYnVpbGRQaGRyRXYAX1pOMTJFbGZSZWJ1aWxkZXIxMVJlYnVpbGRTaGRyRXYAX1pOMTJFbGZSZWJ1aWxkZXIxM1JlYnVpbGRSZWxvY3NFdgBfWk4xMkVsZlJlYnVpbGRlcjdSZWJ1aWxkRXYAX1pOMTJFbGZSZWJ1aWxkZXI4cmVsb2NhdGVJTGIwRUVFdlBoUDlFbGYzMl9SZWxqAF9aTjEyRWxmUmVidWlsZGVyOHJlbG9jYXRlSUxiMUVFRXZQaFA5RWxmMzJfUmVsagBfWk4xMkVsZlJlYnVpbGRlckMxRVAxMU9iRWxmUmVhZGVyAF9aTjEyRWxmUmVidWlsZGVyQzJFUDExT2JFbGZSZWFkZXIAX1pONnNvaW5mb0MyRXYAX1pOOUVsZlJlYWRlcjEwcGhkcl9jb3VudEV2AF9aTjlFbGZSZWFkZXIxMWxvYWRlZF9waGRyRXYAX1pOOUVsZlJlYWRlcjExcmVjb3JkX2VoZHJFdgBfWk45RWxmUmVhZGVyOWxvYWRfYmlhc0V2AF9aTktTdDZfX25kazEyMF9fdmVjdG9yX2Jhc2VfY29tbW9uSUxiMUVFMjBfX3Rocm93X2xlbmd0aF9lcnJvckV2AF9aTktTdDZfX25kazEyMV9fYmFzaWNfc3RyaW5nX2NvbW1vbklMYjFFRTIwX190aHJvd19sZW5ndGhfZXJyb3JFdgBfWk5LU3Q2X19uZGsxNnZlY3RvckkxMEVsZjMyX1NoZHJOU185YWxsb2NhdG9ySVMxX0VFRThtYXhfc2l6ZUV2AF9aTlN0MTFsb2dpY19lcnJvckMyRVBLYwBfWk5TdDEybGVuZ3RoX2Vycm9yRDFFdgBfWk5TdDZfX25kazExMWNoYXJfdHJhaXRzSWNFNGNvcHlFUGNQS2NqAF9aTlN0Nl9fbmRrMTExY2hhcl90cmFpdHNJY0U2YXNzaWduRVJjUktjAF9aTlN0Nl9fbmRrMTExY2hhcl90cmFpdHNJY0U2bGVuZ3RoRVBLYwBfWk5TdDZfX25kazExMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUUxMF9fYWxpZ25faXRJTGoxNkVFRWpqAF9aTlN0Nl9fbmRrMTEyYmFzaWNfc3RyaW5nSWNOU18xMWNoYXJfdHJhaXRzSWNFRU5TXzlhbGxvY2F0b3JJY0VFRTIxX19ncm93X2J5X2FuZF9yZXBsYWNlRWpqampqalBLYwBfWk5TdDZfX25kazExMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUU2YXBwZW5kRVBLYwBfWk5TdDZfX25kazExMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUU2YXBwZW5kRVBLY2oAX1pOU3Q2X19uZGsxMTJiYXNpY19zdHJpbmdJY05TXzExY2hhcl90cmFpdHNJY0VFTlNfOWFsbG9jYXRvckljRUVFOV9fZ3Jvd19ieUVqampqamoAX1pOU3Q2X19uZGsxMTJiYXNpY19zdHJpbmdJY05TXzExY2hhcl90cmFpdHNJY0VFTlNfOWFsbG9jYXRvckljRUVFOXB1c2hfYmFja0VjAF9aTlN0Nl9fbmRrMTE0X19zcGxpdF9idWZmZXJJMTBFbGYzMl9TaGRyUk5TXzlhbGxvY2F0b3JJUzFfRUVFQzJFampTNF8AX1pOU3Q2X19uZGsxMTRfX3NwbGl0X2J1ZmZlckkxMEVsZjMyX1NoZHJSTlNfOWFsbG9jYXRvcklTMV9FRUVEMkV2AF9aTlN0Nl9fbmRrMTE2YWxsb2NhdG9yX3RyYWl0c0lOU185YWxsb2NhdG9ySTEwRWxmMzJfU2hkckVFRTExX19jb25zdHJ1Y3RJUzJfSlJLUzJfRUVFdk5TXzE3aW50ZWdyYWxfY29uc3RhbnRJYkxiMUVFRVJTM19QVF9EcE9UMF8AX1pOU3Q2X19uZGsxMTZhbGxvY2F0b3JfdHJhaXRzSU5TXzlhbGxvY2F0b3JJMTBFbGYzMl9TaGRyRUVFMjBfX2NvbnN0cnVjdF9iYWNrd2FyZElTMl9FRU5TXzllbmFibGVfaWZJWGFhb29MX1pOU18xN2ludGVncmFsX2NvbnN0YW50SWJMYjFFRTV2YWx1ZUVFbnRzcjE1X19oYXNfY29uc3RydWN0SVMzX1BUX1M5X0VFNXZhbHVlc3IzMWlzX3RyaXZpYWxseV9tb3ZlX2NvbnN0cnVjdGlibGVJUzlfRUU1dmFsdWVFdkU0dHlwZUVSUzNfU0FfU0FfUlNBXwBfWk5TdDZfX25kazExNmFsbG9jYXRvcl90cmFpdHNJTlNfOWFsbG9jYXRvckkxMEVsZjMyX1NoZHJFRUU3ZGVzdHJveUlTMl9FRXZSUzNfUFRfAF9aTlN0Nl9fbmRrMTE2YWxsb2NhdG9yX3RyYWl0c0lOU185YWxsb2NhdG9ySTEwRWxmMzJfU2hkckVFRTlfX2Rlc3Ryb3lJUzJfRUV2TlNfMTdpbnRlZ3JhbF9jb25zdGFudEliTGIxRUVFUlMzX1BUXwBfWk5TdDZfX25kazExNmFsbG9jYXRvcl90cmFpdHNJTlNfOWFsbG9jYXRvckkxMEVsZjMyX1NoZHJFRUU5Y29uc3RydWN0SVMyX0pSS1MyX0VFRXZSUzNfUFRfRHBPVDBfAF9aTlN0Nl9fbmRrMTE3X0RlYWxsb2NhdGVDYWxsZXIyN19fZG9fZGVhbGxvY2F0ZV9oYW5kbGVfc2l6ZUVQdmoAX1pOU3Q2X19uZGsxMTdfRGVhbGxvY2F0ZUNhbGxlcjlfX2RvX2NhbGxFUHYAX1pOU3Q2X19uZGsxMTdfX2NvbXByZXNzZWRfcGFpcklOU18xMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUU1X19yZXBFUzVfRUMySUxiMUV2RUV2AF9aTlN0Nl9fbmRrMTE3X19jb21wcmVzc2VkX3BhaXJJUDEwRWxmMzJfU2hkck5TXzlhbGxvY2F0b3JJUzFfRUVFQzJJRG5MYjFFRUVPVF8AX1pOU3Q2X19uZGsxMTdfX2NvbXByZXNzZWRfcGFpcklQMTBFbGYzMl9TaGRyUk5TXzlhbGxvY2F0b3JJUzFfRUVFQzJJRG5TNV9FRU9UX09UMF8AX1pOU3Q2X19uZGsxMjJfX2NvbXByZXNzZWRfcGFpcl9lbGVtSVAxMEVsZjMyX1NoZHJMaTBFTGIwRUVDMklEbnZFRU9UXwBfWk5TdDZfX25kazEyMl9fY29tcHJlc3NlZF9wYWlyX2VsZW1JUk5TXzlhbGxvY2F0b3JJMTBFbGYzMl9TaGRyRUVMaTFFTGIwRUVDMklTNF92RUVPVF8AX1pOU3Q2X19uZGsxNnZlY3RvckkxMEVsZjMyX1NoZHJOU185YWxsb2NhdG9ySVMxX0VFRTIxX0NvbnN0cnVjdFRyYW5zYWN0aW9uQzJFUlM0X2oAX1pOU3Q2X19uZGsxNnZlY3RvckkxMEVsZjMyX1NoZHJOU185YWxsb2NhdG9ySVMxX0VFRTIxX0NvbnN0cnVjdFRyYW5zYWN0aW9uRDJFdgBfWk5TdDZfX25kazE2dmVjdG9ySTEwRWxmMzJfU2hkck5TXzlhbGxvY2F0b3JJUzFfRUVFMjFfX3B1c2hfYmFja19zbG93X3BhdGhJUktTMV9FRXZPVF8AX1pOU3Q2X19uZGsxNnZlY3RvckkxMEVsZjMyX1NoZHJOU185YWxsb2NhdG9ySVMxX0VFRTIyX19jb25zdHJ1Y3Rfb25lX2F0X2VuZElKUktTMV9FRUV2RHBPVF8AX1pOU3Q2X19uZGsxNnZlY3RvckkxMEVsZjMyX1NoZHJOU185YWxsb2NhdG9ySVMxX0VFRTI2X19zd2FwX291dF9jaXJjdWxhcl9idWZmZXJFUk5TXzE0X19zcGxpdF9idWZmZXJJUzFfUlMzX0VFAF9fYWVhYmlfbWVtY3B5NABfX2FlYWJpX21lbW1vdmU0AGdldG9wdF9sb25nAG9wdGVycgBvcHRhcmcAX1pOU3Q2X19uZGsxOWFsbG9jYXRvckkxMEVsZjMyX1NoZHJFOWNvbnN0cnVjdElTMV9KUktTMV9FRUV2UFRfRHBPVDBfAG9wdG9wdABvcHRpbmQAb3B0cmVzZXQAX1pUSVN0MTJsZW5ndGhfZXJyb3IAX1pUVlN0MTJsZW5ndGhfZXJyb3IAX19tZW1tb3ZlX2NoawBfX2N4YV9hbGxvY2F0ZV9leGNlcHRpb24AX192c3ByaW50Zl9jaGsAX19jeGFfZnJlZV9leGNlcHRpb24AX19zdHJsZW5fY2hrAF9fY3hhX3Rocm93AGZ3cml0ZQBzdHJsZW4AZmlsZW5vAF9aTjExT2JFbGZSZWFkZXIxM0ZpeER1bXBTb1BoZHJFdgBfWk4xMU9iRWxmUmVhZGVyMTlBcHBseUR5bmFtaWNTZWN0aW9uRXYAX1pOMTFPYkVsZlJlYWRlcjMyTG9hZER5bmFtaWNTZWN0aW9uRnJvbUJhc2VTb3VyY2VFdgBfWk4xMU9iRWxmUmVhZGVyMzVoYXZlRHluYW1pY1NlY3Rpb25JbkxvYWRhYmxlU2VnbWVudEV2AF9aTjExT2JFbGZSZWFkZXI0TG9hZEV2AF9aTjExT2JFbGZSZWFkZXJEMEV2AF9aTjExT2JFbGZSZWFkZXJEMUV2AF9aTjExT2JFbGZSZWFkZXJEMkV2AHN0cnRvdWwAX1pOS1N0Nl9fbmRrMTZ2ZWN0b3JJUDEwRWxmMzJfUGhkck5TXzlhbGxvY2F0b3JJUzJfRUVFOG1heF9zaXplRXYAX1pOU3Q2X19uZGsxMTNfX3ZlY3Rvcl9iYXNlSVAxMEVsZjMyX1BoZHJOU185YWxsb2NhdG9ySVMyX0VFRUQyRXYAX1pOU3Q2X19uZGsxMTRfX3NwbGl0X2J1ZmZlcklQMTBFbGYzMl9QaGRyUk5TXzlhbGxvY2F0b3JJUzJfRUVFQzJFampTNV8AX1pOU3Q2X19uZGsxMTRfX3NwbGl0X2J1ZmZlcklQMTBFbGYzMl9QaGRyUk5TXzlhbGxvY2F0b3JJUzJfRUVFRDJFdgBfWk5TdDZfX25kazExNmFsbG9jYXRvcl90cmFpdHNJTlNfOWFsbG9jYXRvcklQMTBFbGYzMl9QaGRyRUVFMTFfX2NvbnN0cnVjdElTM19KUktTM19FRUV2TlNfMTdpbnRlZ3JhbF9jb25zdGFudEliTGIxRUVFUlM0X1BUX0RwT1QwXwBfWk5TdDZfX25kazExNmFsbG9jYXRvcl90cmFpdHNJTlNfOWFsbG9jYXRvcklQMTBFbGYzMl9QaGRyRUVFMjBfX2NvbnN0cnVjdF9iYWNrd2FyZElTM19FRU5TXzllbmFibGVfaWZJWGFhb29MX1pOU18xN2ludGVncmFsX2NvbnN0YW50SWJMYjFFRTV2YWx1ZUVFbnRzcjE1X19oYXNfY29uc3RydWN0SVM0X1BUX1NBX0VFNXZhbHVlc3IzMWlzX3RyaXZpYWxseV9tb3ZlX2NvbnN0cnVjdGlibGVJU0FfRUU1dmFsdWVFdkU0dHlwZUVSUzRfU0JfU0JfUlNCXwBfWk5TdDZfX25kazExNmFsbG9jYXRvcl90cmFpdHNJTlNfOWFsbG9jYXRvcklQMTBFbGYzMl9QaGRyRUVFN2Rlc3Ryb3lJUzNfRUV2UlM0X1BUXwBfWk5TdDZfX25kazExNmFsbG9jYXRvcl90cmFpdHNJTlNfOWFsbG9jYXRvcklQMTBFbGYzMl9QaGRyRUVFOV9fZGVzdHJveUlTM19FRXZOU18xN2ludGVncmFsX2NvbnN0YW50SWJMYjFFRUVSUzRfUFRfAF9aTlN0Nl9fbmRrMTE2YWxsb2NhdG9yX3RyYWl0c0lOU185YWxsb2NhdG9ySVAxMEVsZjMyX1BoZHJFRUU5Y29uc3RydWN0SVMzX0pSS1MzX0VFRXZSUzRfUFRfRHBPVDBfAF9aTlN0Nl9fbmRrMTE3X19jb21wcmVzc2VkX3BhaXJJUFAxMEVsZjMyX1BoZHJOU185YWxsb2NhdG9ySVMyX0VFRUMySURuTGIxRUVFT1RfAF9aTlN0Nl9fbmRrMTE3X19jb21wcmVzc2VkX3BhaXJJUFAxMEVsZjMyX1BoZHJSTlNfOWFsbG9jYXRvcklTMl9FRUVDMklEblM2X0VFT1RfT1QwXwBfWk5TdDZfX25kazEyMl9fY29tcHJlc3NlZF9wYWlyX2VsZW1JUFAxMEVsZjMyX1BoZHJMaTBFTGIwRUVDMklEbnZFRU9UXwBfWk5TdDZfX25kazEyMl9fY29tcHJlc3NlZF9wYWlyX2VsZW1JUk5TXzlhbGxvY2F0b3JJUDEwRWxmMzJfUGhkckVFTGkxRUxiMEVFQzJJUzVfdkVFT1RfAF9aTlN0Nl9fbmRrMTZ2ZWN0b3JJUDEwRWxmMzJfUGhkck5TXzlhbGxvY2F0b3JJUzJfRUVFMjFfQ29uc3RydWN0VHJhbnNhY3Rpb25DMkVSUzVfagBfWk5TdDZfX25kazE2dmVjdG9ySVAxMEVsZjMyX1BoZHJOU185YWxsb2NhdG9ySVMyX0VFRTIxX0NvbnN0cnVjdFRyYW5zYWN0aW9uRDJFdgBfWk5TdDZfX25kazE2dmVjdG9ySVAxMEVsZjMyX1BoZHJOU185YWxsb2NhdG9ySVMyX0VFRTIxX19wdXNoX2JhY2tfc2xvd19wYXRoSVJLUzJfRUV2T1RfAF9aTlN0Nl9fbmRrMTZ2ZWN0b3JJUDEwRWxmMzJfUGhkck5TXzlhbGxvY2F0b3JJUzJfRUVFMjJfX2NvbnN0cnVjdF9vbmVfYXRfZW5kSUpSS1MyX0VFRXZEcE9UXwBfWk5TdDZfX25kazE2dmVjdG9ySVAxMEVsZjMyX1BoZHJOU185YWxsb2NhdG9ySVMyX0VFRTI2X19zd2FwX291dF9jaXJjdWxhcl9idWZmZXJFUk5TXzE0X19zcGxpdF9idWZmZXJJUzJfUlM0X0VFAF9aTlN0Nl9fbmRrMTlhbGxvY2F0b3JJUDEwRWxmMzJfUGhkckU5Y29uc3RydWN0SVMyX0pSS1MyX0VFRXZQVF9EcE9UMF8AX1pUSTExT2JFbGZSZWFkZXIAX1pUUzExT2JFbGZSZWFkZXIAX1pUVjExT2JFbGZSZWFkZXIAX1pUVk4xMF9fY3h4YWJpdjEyMF9fc2lfY2xhc3NfdHlwZV9pbmZvRQBKTklfT25Mb2FkAF9aNWZpeE1lUGNTX1NfAF9aNnVzZWFnZXYAX1o5bWFpbl9sb29waVBQYwBfWk4xMU9iRWxmUmVhZGVyMTNzZXRCYXNlU29OYW1lRVBLYwBfWk4xMU9iRWxmUmVhZGVyMTdzZXREdW1wU29CYXNlQWRkckVqAF9aTjExT2JFbGZSZWFkZXJDMkV2AF9aTjEyRWxmUmVidWlsZGVyMTRnZXRSZWJ1aWxkRGF0YUV2AF9aTjEyRWxmUmVidWlsZGVyMTRnZXRSZWJ1aWxkU2l6ZUV2AF9aTjEyRWxmUmVidWlsZGVyRDJFdgBfWk5TdDZfX25kazExMWNoYXJfdHJhaXRzSWNFNG1vdmVFUGNQS2NqAF9aTlN0Nl9fbmRrMTEyYmFzaWNfc3RyaW5nSWNOU18xMWNoYXJfdHJhaXRzSWNFRU5TXzlhbGxvY2F0b3JJY0VFRTZhc3NpZ25FUEtjAF9aTlN0Nl9fbmRrMTEyYmFzaWNfc3RyaW5nSWNOU18xMWNoYXJfdHJhaXRzSWNFRU5TXzlhbGxvY2F0b3JJY0VFRTZhc3NpZ25FUEtjagBfWk5TdDZfX25kazExMmJhc2ljX3N0cmluZ0ljTlNfMTFjaGFyX3RyYWl0c0ljRUVOU185YWxsb2NhdG9ySWNFRUVEMkV2AF9aTlN0Nl9fbmRrMTEzX192ZWN0b3JfYmFzZUkxMEVsZjMyX1NoZHJOU185YWxsb2NhdG9ySVMxX0VFRUQyRXYAX19hZWFiaV9tZW1tb3ZlAF9fZndyaXRlX2NoawBtYWluAHNob3J0X29wdGlvbnMAc3RyY21wAHB0aHJlYWRfbXV0ZXhfbG9jawBjYWxsb2MAcHRocmVhZF9tdXRleF91bmxvY2sAX1pOU3Q5YmFkX2FsbG9jQzFFdgBfWk5TdDliYWRfYWxsb2NEMUV2AF9aU3QxNWdldF9uZXdfaGFuZGxlcnYAX1pTdDE3X190aHJvd19iYWRfYWxsb2N2AF9aU3Q3bm90aHJvdwBfWlRJU3Q5YmFkX2FsbG9jAF9aZGFQdlJLU3Q5bm90aHJvd190AF9aZGFQdlN0MTFhbGlnbl92YWxfdABfWmRhUHZTdDExYWxpZ25fdmFsX3RSS1N0OW5vdGhyb3dfdABfWmRhUHZqAF9aZGFQdmpTdDExYWxpZ25fdmFsX3QAX1pkbFB2UktTdDlub3Rocm93X3QAX1pkbFB2U3QxMWFsaWduX3ZhbF90AF9aZGxQdlN0MTFhbGlnbl92YWxfdFJLU3Q5bm90aHJvd190AF9aZGxQdmoAX1pkbFB2alN0MTFhbGlnbl92YWxfdABfWm5halJLU3Q5bm90aHJvd190AF9abmFqU3QxMWFsaWduX3ZhbF90AF9abmFqU3QxMWFsaWduX3ZhbF90UktTdDlub3Rocm93X3QAX1pud2pSS1N0OW5vdGhyb3dfdABfWm53alN0MTFhbGlnbl92YWxfdABfWm53alN0MTFhbGlnbl92YWxfdFJLU3Q5bm90aHJvd190AF9fY3hhX2VuZF9jYXRjaABmcmVlAG1hbGxvYwBwb3NpeF9tZW1hbGlnbgBfWk5TdDExbG9naWNfZXJyb3JDMUVQS2MAX1pOU3QxMWxvZ2ljX2Vycm9yQzFFUktOU3Q2X19uZGsxMTJiYXNpY19zdHJpbmdJY05TMF8xMWNoYXJfdHJhaXRzSWNFRU5TMF85YWxsb2NhdG9ySWNFRUVFAF9aTlN0MTFsb2dpY19lcnJvckMxRVJLU18AX1pOU3QxMWxvZ2ljX2Vycm9yQzJFUktOU3Q2X19uZGsxMTJiYXNpY19zdHJpbmdJY05TMF8xMWNoYXJfdHJhaXRzSWNFRU5TMF85YWxsb2NhdG9ySWNFRUVFAF9aTlN0MTFsb2dpY19lcnJvckMyRVJLU18AX1pOU3QxMWxvZ2ljX2Vycm9yYVNFUktTXwBfWk5TdDEzcnVudGltZV9lcnJvckMxRVBLYwBfWk5TdDEzcnVudGltZV9lcnJvckMxRVJLTlN0Nl9fbmRrMTEyYmFzaWNfc3RyaW5nSWNOUzBfMTFjaGFyX3RyYWl0c0ljRUVOUzBfOWFsbG9jYXRvckljRUVFRQBfWk5TdDEzcnVudGltZV9lcnJvckMxRVJLU18AX1pOU3QxM3J1bnRpbWVfZXJyb3JDMkVQS2MAX1pOU3QxM3J1bnRpbWVfZXJyb3JDMkVSS05TdDZfX25kazExMmJhc2ljX3N0cmluZ0ljTlMwXzExY2hhcl90cmFpdHNJY0VFTlMwXzlhbGxvY2F0b3JJY0VFRUUAX1pOU3QxM3J1bnRpbWVfZXJyb3JDMkVSS1NfAF9aTlN0MTNydW50aW1lX2Vycm9yYVNFUktTXwBfWk5TdDlleGNlcHRpb25EMkV2AF9aVFZTdDExbG9naWNfZXJyb3IAX1pUVlN0MTNydW50aW1lX2Vycm9yAF9aTjEwX19jeHhhYml2MTE5X19nZXRFeGNlcHRpb25DbGFzc0VQSzIxX1Vud2luZF9Db250cm9sX0Jsb2NrAF9aTjEwX19jeHhhYml2MTE5X19zZXRFeGNlcHRpb25DbGFzc0VQMjFfVW53aW5kX0NvbnRyb2xfQmxvY2t5AF9aTjEwX19jeHhhYml2MTIxX19pc091ckV4Y2VwdGlvbkNsYXNzRVBLMjFfVW53aW5kX0NvbnRyb2xfQmxvY2sAX1pTdDEzZ2V0X3Rlcm1pbmF0ZXYAX1pTdDE0Z2V0X3VuZXhwZWN0ZWR2AF9fYWVhYmlfbWVtY2xyAF9fY3hhX2FsbG9jYXRlX2RlcGVuZGVudF9leGNlcHRpb24AX19jeGFfYmVnaW5fY2xlYW51cABfX2N4YV9jYWxsX3VuZXhwZWN0ZWQAX19jeGFfY3VycmVudF9leGNlcHRpb25fdHlwZQBfX2N4YV9jdXJyZW50X3ByaW1hcnlfZXhjZXB0aW9uAF9fY3hhX2RlY3JlbWVudF9leGNlcHRpb25fcmVmY291bnQAX19jeGFfZW5kX2NsZWFudXAAX19jeGFfZnJlZV9kZXBlbmRlbnRfZXhjZXB0aW9uAF9fY3hhX2dldF9leGNlcHRpb25fcHRyAF9fY3hhX2dldF9nbG9iYWxzAF9fY3hhX2dldF9nbG9iYWxzX2Zhc3QAX19jeGFfaW5jcmVtZW50X2V4Y2VwdGlvbl9yZWZjb3VudABfX2N4YV9yZXRocm93AF9fY3hhX3JldGhyb3dfcHJpbWFyeV9leGNlcHRpb24AX19jeGFfdW5jYXVnaHRfZXhjZXB0aW9uAF9fY3hhX3VuY2F1Z2h0X2V4Y2VwdGlvbnMAYWJvcnQAcHRocmVhZF9nZXRzcGVjaWZpYwBwdGhyZWFkX2tleV9jcmVhdGUAcHRocmVhZF9vbmNlAHB0aHJlYWRfc2V0c3BlY2lmaWMAX1pTdDEwdW5leHBlY3RlZHYAX1pTdDE1c2V0X25ld19oYW5kbGVyUEZ2dkUAX19jeGFfbmV3X2hhbmRsZXIAX19jeGFfdGVybWluYXRlX2hhbmRsZXIAX19jeGFfdW5leHBlY3RlZF9oYW5kbGVyAF9aTlN0MTNiYWRfZXhjZXB0aW9uRDFFdgBfWlRJU3QxM2JhZF9leGNlcHRpb24AX1pUVlN0MTNiYWRfZXhjZXB0aW9uAF9fYWVhYmlfbWVtY2xyOABfWk5TdDl0eXBlX2luZm9EMkV2AF9aVElEaABfWlRJRGkAX1pUSURuAF9aVElEcwBfWlRJRHUAX1pUSU4xMF9fY3h4YWJpdjExNl9fZW51bV90eXBlX2luZm9FAF9aVElOMTBfX2N4eGFiaXYxMTZfX3NoaW1fdHlwZV9pbmZvRQBfWlRJTjEwX19jeHhhYml2MTE3X19hcnJheV90eXBlX2luZm9FAF9aVElOMTBfX2N4eGFiaXYxMTdfX2NsYXNzX3R5cGVfaW5mb0UAX1pUSU4xMF9fY3h4YWJpdjExN19fcGJhc2VfdHlwZV9pbmZvRQBfWlRJTjEwX19jeHhhYml2MTE5X19wb2ludGVyX3R5cGVfaW5mb0UAX1pUSU4xMF9fY3h4YWJpdjEyMF9fZnVuY3Rpb25fdHlwZV9pbmZvRQBfWlRJTjEwX19jeHhhYml2MTIwX19zaV9jbGFzc190eXBlX2luZm9FAF9aVElOMTBfX2N4eGFiaXYxMjFfX3ZtaV9jbGFzc190eXBlX2luZm9FAF9aVElOMTBfX2N4eGFiaXYxMjNfX2Z1bmRhbWVudGFsX3R5cGVfaW5mb0UAX1pUSU4xMF9fY3h4YWJpdjEyOV9fcG9pbnRlcl90b19tZW1iZXJfdHlwZV9pbmZvRQBfWlRJUERoAF9aVElQRGkAX1pUSVBEbgBfWlRJUERzAF9aVElQRHUAX1pUSVBLRGgAX1pUSVBLRGkAX1pUSVBLRG4AX1pUSVBLRHMAX1pUSVBLRHUAX1pUSVBLYQBfWlRJUEtiAF9aVElQS2MAX1pUSVBLZABfWlRJUEtlAF9aVElQS2YAX1pUSVBLZwBfWlRJUEtoAF9aVElQS2kAX1pUSVBLagBfWlRJUEtsAF9aVElQS20AX1pUSVBLbgBfWlRJUEtvAF9aVElQS3MAX1pUSVBLdABfWlRJUEt2AF9aVElQS3cAX1pUSVBLeABfWlRJUEt5AF9aVElQYQBfWlRJUGIAX1pUSVBjAF9aVElQZABfWlRJUGUAX1pUSVBmAF9aVElQZwBfWlRJUGgAX1pUSVBpAF9aVElQagBfWlRJUGwAX1pUSVBtAF9aVElQbgBfWlRJUG8AX1pUSVBzAF9aVElQdABfWlRJUHYAX1pUSVB3AF9aVElQeABfWlRJUHkAX1pUSVN0OXR5cGVfaW5mbwBfWlRJYQBfWlRJYgBfWlRJYwBfWlRJZABfWlRJZQBfWlRJZgBfWlRJZwBfWlRJaABfWlRJaQBfWlRJagBfWlRJbABfWlRJbQBfWlRJbgBfWlRJbwBfWlRJcwBfWlRJdABfWlRJdgBfWlRJdwBfWlRJeABfWlRJeQBfWlRTRGgAX1pUU0RpAF9aVFNEbgBfWlRTRHMAX1pUU0R1AF9aVFNOMTBfX2N4eGFiaXYxMTZfX2VudW1fdHlwZV9pbmZvRQBfWlRTTjEwX19jeHhhYml2MTE2X19zaGltX3R5cGVfaW5mb0UAX1pUU04xMF9fY3h4YWJpdjExN19fYXJyYXlfdHlwZV9pbmZvRQBfWlRTTjEwX19jeHhhYml2MTE3X19jbGFzc190eXBlX2luZm9FAF9aVFNOMTBfX2N4eGFiaXYxMTdfX3BiYXNlX3R5cGVfaW5mb0UAX1pUU04xMF9fY3h4YWJpdjExOV9fcG9pbnRlcl90eXBlX2luZm9FAF9aVFNOMTBfX2N4eGFiaXYxMjBfX2Z1bmN0aW9uX3R5cGVfaW5mb0UAX1pUU04xMF9fY3h4YWJpdjEyMF9fc2lfY2xhc3NfdHlwZV9pbmZvRQBfWlRTTjEwX19jeHhhYml2MTIxX192bWlfY2xhc3NfdHlwZV9pbmZvRQBfWlRTTjEwX19jeHhhYml2MTIzX19mdW5kYW1lbnRhbF90eXBlX2luZm9FAF9aVFNOMTBfX2N4eGFiaXYxMjlfX3BvaW50ZXJfdG9fbWVtYmVyX3R5cGVfaW5mb0UAX1pUU1BEaABfWlRTUERpAF9aVFNQRG4AX1pUU1BEcwBfWlRTUER1AF9aVFNQS0RoAF9aVFNQS0RpAF9aVFNQS0RuAF9aVFNQS0RzAF9aVFNQS0R1AF9aVFNQS2EAX1pUU1BLYgBfWlRTUEtjAF9aVFNQS2QAX1pUU1BLZQBfWlRTUEtmAF9aVFNQS2cAX1pUU1BLaABfWlRTUEtpAF9aVFNQS2oAX1pUU1BLbABfWlRTUEttAF9aVFNQS24AX1pUU1BLbwBfWlRTUEtzAF9aVFNQS3QAX1pUU1BLdgBfWlRTUEt3AF9aVFNQS3gAX1pUU1BLeQBfWlRTUGEAX1pUU1BiAF9aVFNQYwBfWlRTUGQAX1pUU1BlAF9aVFNQZgBfWlRTUGcAX1pUU1BoAF9aVFNQaQBfWlRTUGoAX1pUU1BsAF9aVFNQbQBfWlRTUG4AX1pUU1BvAF9aVFNQcwBfWlRTUHQAX1pUU1B2AF9aVFNQdwBfWlRTUHgAX1pUU1B5AF9aVFNhAF9aVFNiAF9aVFNjAF9aVFNkAF9aVFNlAF9aVFNmAF9aVFNnAF9aVFNoAF9aVFNpAF9aVFNqAF9aVFNsAF9aVFNtAF9aVFNuAF9aVFNvAF9aVFNzAF9aVFN0AF9aVFN2AF9aVFN3AF9aVFN4AF9aVFN5AF9aVFZOMTBfX2N4eGFiaXYxMTZfX2VudW1fdHlwZV9pbmZvRQBfWlRWTjEwX19jeHhhYml2MTE2X19zaGltX3R5cGVfaW5mb0UAX1pUVk4xMF9fY3h4YWJpdjExN19fYXJyYXlfdHlwZV9pbmZvRQBfWlRWTjEwX19jeHhhYml2MTE3X19wYmFzZV90eXBlX2luZm9FAF9aVFZOMTBfX2N4eGFiaXYxMTlfX3BvaW50ZXJfdHlwZV9pbmZvRQBfWlRWTjEwX19jeHhhYml2MTIwX19mdW5jdGlvbl90eXBlX2luZm9FAF9aVFZOMTBfX2N4eGFiaXYxMjFfX3ZtaV9jbGFzc190eXBlX2luZm9FAF9aVFZOMTBfX2N4eGFiaXYxMjNfX2Z1bmRhbWVudGFsX3R5cGVfaW5mb0UAX1pUVk4xMF9fY3h4YWJpdjEyOV9fcG9pbnRlcl90b19tZW1iZXJfdHlwZV9pbmZvRQBfX2N4YV9wdXJlX3ZpcnR1YWwAX19keW5hbWljX2Nhc3QAX1pOS1N0MTNiYWRfZXhjZXB0aW9uNHdoYXRFdgBfWk5LU3QyMGJhZF9hcnJheV9uZXdfbGVuZ3RoNHdoYXRFdgBfWk5LU3Q5YmFkX2FsbG9jNHdoYXRFdgBfWk5LU3Q5ZXhjZXB0aW9uNHdoYXRFdgBfWk5TdDEzYmFkX2V4Y2VwdGlvbkQwRXYAX1pOU3QxM2JhZF9leGNlcHRpb25EMkV2AF9aTlN0MjBiYWRfYXJyYXlfbmV3X2xlbmd0aEMxRXYAX1pOU3QyMGJhZF9hcnJheV9uZXdfbGVuZ3RoQzJFdgBfWk5TdDIwYmFkX2FycmF5X25ld19sZW5ndGhEMEV2AF9aTlN0MjBiYWRfYXJyYXlfbmV3X2xlbmd0aEQxRXYAX1pOU3QyMGJhZF9hcnJheV9uZXdfbGVuZ3RoRDJFdgBfWk5TdDliYWRfYWxsb2NDMkV2AF9aTlN0OWJhZF9hbGxvY0QwRXYAX1pOU3Q5YmFkX2FsbG9jRDJFdgBfWk5TdDlleGNlcHRpb25EMEV2AF9aTlN0OWV4Y2VwdGlvbkQxRXYAX1pUSVN0MjBiYWRfYXJyYXlfbmV3X2xlbmd0aABfWlRJU3Q5ZXhjZXB0aW9uAF9aVFNTdDEzYmFkX2V4Y2VwdGlvbgBfWlRTU3QyMGJhZF9hcnJheV9uZXdfbGVuZ3RoAF9aVFNTdDliYWRfYWxsb2MAX1pUU1N0OWV4Y2VwdGlvbgBfWlRWU3QyMGJhZF9hcnJheV9uZXdfbGVuZ3RoAF9aVFZTdDliYWRfYWxsb2MAX1pUVlN0OWV4Y2VwdGlvbgBfWk5LU3QxMWxvZ2ljX2Vycm9yNHdoYXRFdgBfWk5LU3QxM3J1bnRpbWVfZXJyb3I0d2hhdEV2AF9aTlN0MTFsb2dpY19lcnJvckQwRXYAX1pOU3QxMWxvZ2ljX2Vycm9yRDFFdgBfWk5TdDExbG9naWNfZXJyb3JEMkV2AF9aTlN0MTFyYW5nZV9lcnJvckQwRXYAX1pOU3QxMXJhbmdlX2Vycm9yRDFFdgBfWk5TdDExcmFuZ2VfZXJyb3JEMkV2AF9aTlN0MTJkb21haW5fZXJyb3JEMEV2AF9aTlN0MTJkb21haW5fZXJyb3JEMUV2AF9aTlN0MTJkb21haW5fZXJyb3JEMkV2AF9aTlN0MTJsZW5ndGhfZXJyb3JEMEV2AF9aTlN0MTJsZW5ndGhfZXJyb3JEMkV2AF9aTlN0MTJvdXRfb2ZfcmFuZ2VEMEV2AF9aTlN0MTJvdXRfb2ZfcmFuZ2VEMUV2AF9aTlN0MTJvdXRfb2ZfcmFuZ2VEMkV2AF9aTlN0MTNydW50aW1lX2Vycm9yRDBFdgBfWk5TdDEzcnVudGltZV9lcnJvckQxRXYAX1pOU3QxM3J1bnRpbWVfZXJyb3JEMkV2AF9aTlN0MTRvdmVyZmxvd19lcnJvckQwRXYAX1pOU3QxNG92ZXJmbG93X2Vycm9yRDFFdgBfWk5TdDE0b3ZlcmZsb3dfZXJyb3JEMkV2AF9aTlN0MTV1bmRlcmZsb3dfZXJyb3JEMEV2AF9aTlN0MTV1bmRlcmZsb3dfZXJyb3JEMUV2AF9aTlN0MTV1bmRlcmZsb3dfZXJyb3JEMkV2AF9aTlN0MTZpbnZhbGlkX2FyZ3VtZW50RDBFdgBfWk5TdDE2aW52YWxpZF9hcmd1bWVudEQxRXYAX1pOU3QxNmludmFsaWRfYXJndW1lbnREMkV2AF9aVElTdDExbG9naWNfZXJyb3IAX1pUSVN0MTFyYW5nZV9lcnJvcgBfWlRJU3QxMmRvbWFpbl9lcnJvcgBfWlRJU3QxMm91dF9vZl9yYW5nZQBfWlRJU3QxM3J1bnRpbWVfZXJyb3IAX1pUSVN0MTRvdmVyZmxvd19lcnJvcgBfWlRJU3QxNXVuZGVyZmxvd19lcnJvcgBfWlRJU3QxNmludmFsaWRfYXJndW1lbnQAX1pUU1N0MTFsb2dpY19lcnJvcgBfWlRTU3QxMXJhbmdlX2Vycm9yAF9aVFNTdDEyZG9tYWluX2Vycm9yAF9aVFNTdDEybGVuZ3RoX2Vycm9yAF9aVFNTdDEyb3V0X29mX3JhbmdlAF9aVFNTdDEzcnVudGltZV9lcnJvcgBfWlRTU3QxNG92ZXJmbG93X2Vycm9yAF9aVFNTdDE1dW5kZXJmbG93X2Vycm9yAF9aVFNTdDE2aW52YWxpZF9hcmd1bWVudABfWlRWU3QxMXJhbmdlX2Vycm9yAF9aVFZTdDEyZG9tYWluX2Vycm9yAF9aVFZTdDEyb3V0X29mX3JhbmdlAF9aVFZTdDE0b3ZlcmZsb3dfZXJyb3IAX1pUVlN0MTV1bmRlcmZsb3dfZXJyb3IAX1pUVlN0MTZpbnZhbGlkX2FyZ3VtZW50AF9aTktTdDEwYmFkX3R5cGVpZDR3aGF0RXYAX1pOS1N0OGJhZF9jYXN0NHdoYXRFdgBfWk5TdDEwYmFkX3R5cGVpZEMxRXYAX1pOU3QxMGJhZF90eXBlaWRDMkV2AF9aTlN0MTBiYWRfdHlwZWlkRDBFdgBfWk5TdDEwYmFkX3R5cGVpZEQxRXYAX1pOU3QxMGJhZF90eXBlaWREMkV2AF9aTlN0OGJhZF9jYXN0QzFFdgBfWk5TdDhiYWRfY2FzdEMyRXYAX1pOU3Q4YmFkX2Nhc3REMEV2AF9aTlN0OGJhZF9jYXN0RDFFdgBfWk5TdDhiYWRfY2FzdEQyRXYAX1pOU3Q5dHlwZV9pbmZvRDBFdgBfWk5TdDl0eXBlX2luZm9EMUV2AF9aVElTdDEwYmFkX3R5cGVpZABfWlRJU3Q4YmFkX2Nhc3QAX1pUU1N0MTBiYWRfdHlwZWlkAF9aVFNTdDhiYWRfY2FzdABfWlRTU3Q5dHlwZV9pbmZvAF9aVFZTdDEwYmFkX3R5cGVpZABfWlRWU3Q4YmFkX2Nhc3QAX1pUVlN0OXR5cGVfaW5mbwBfX2Fzc2VydDIAX19zRgBmcHV0YwB2YXNwcmludGYAdmZwcmludGYAX1pTdDEzc2V0X3Rlcm1pbmF0ZVBGdnZFAF9aU3QxNHNldF91bmV4cGVjdGVkUEZ2dkUAX19jeGFfZGVtYW5nbGUAaXNsb3dlcgBpc3hkaWdpdAByZWFsbG9jAHNucHJpbnRmAF9fY3hhX2RlbGV0ZWRfdmlydHVhbABmZmx1c2gAZnByaW50ZgBkbGFkZHIAbGliZGwuc28AX2VkYXRhAF9fYnNzX3N0YXJ0AF9lbmQAbGlibG9nLnNvAGxp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AwAAAAIAAwACAAIAAgACAAIAAgACAAIAAgACAAMAAwACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAMAAwACAAIAAgACAAIAAgACAAMAAgACAAIAAgACAAMAAgACAAIAAgACAAIAAgACAAIAAgACAAQAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEA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dD8CABcAAAB4PwIAFwAAAIA/AgAXAAAAhD8CABcAAACIPwIAFwAAAIw/AgAXAAAAkD8CABcAAACUPwIAFwAAAJg/AgAXAAAAnD8CABcAAACgPwIAFwAAAKQ/AgAXAAAArD8CABcAAACwPwIAFwAAALg/AgAXAAAAvD8CABcAAADAPwIAFwAAAMQ/AgAXAAAAyD8CABcAAADMPwIAFwAAANA/AgAXAAAA1D8CABcAAADYPwIAFwAAANw/AgAXAAAA5D8CABcAAADoPwIAFwAAAPA/AgAXAAAA9D8CABcAAAD4PwIAFwAAAPw/AgAXAAAAAEACABcAAAAEQAIAFwAAAAhAAgAXAAAADEACABcAAAAQQAIAFwAAABRAAgAXAAAAHEACABcAAAAgQAIAFwAAAChAAgAXAAAALEACABcAAAAwQAIAFwAAADRAAgAXAAAAOEACABcAAAA8QAIAFwAAAEBAAgAXAAAAREACABcAAABIQAIAFwAAAExAAgAXAAAAVEACABcAAABYQAIAFwAAAGBAAgAXAAAAZEACABcAAABoQAIAFwAAAGxAAgAXAAAAcEACABcAAAB0QAIAFwAAAHhAAgAXAAAAfEACABcAAACAQAIAFwAAAIRAAgAXAAAAjEACABcAAACQQAIAFwAAAJhAAgAXAAAAnEACABcAAACgQAIAFwAAAKRAAgAXAAAAqEACABcAAACsQAIAFwAAALBAAgAXAAAAtEACABcAAAC4QAIAFwAAALxAAgAXAAAAxEACABcAAADIQAIAFwAAANBAAgAXAAAA1EACABcAAADYQAIAFwAAANxAAgAXAAAA4EACABcAAADkQAIAFwAAAOhAAgAXAAAA7EACABcAAADwQAIAFwAAAPRAAgAXAAAA/EACABcAAAAAQQIAFwAAAAhBAgAXAAAADEECABcAAAAQQQIAFwAAABRBAgAXAAAAGEECABcAAAAcQQIAFwAAACBBAgAXAAAAJEECABcAAAAoQQIAFwAAACxBAgAXAAAANEECABcAAAA4QQIAFwAAAEBBAgAXAAAAREECABcAAABIQQIAFwAAAExBAgAXAAAAUEECABcAAABUQQIAFwAAAFhBAgAXAAAAXEECABcAAABgQQIAFwAAAGRBAgAXAAAAbEECABcAAABwQQIAFwAAAHhBAgAXAAAAfEECABcAAACAQQIAFwAAAIRBAgAXAAAAiEECABcAAACMQQIAFwAAAJBBAgAXAAAAlEECABcAAACYQQIAFwAAAJxBAgAXAAAApEECABcAAACoQQIAFwAAALBBAgAXAAAAtEECABcAAAC4QQIAFwAAALxBAgAXAAAAwEECABcAAADEQQIAFwAAAMhBAgAXAAAAzEECABcAAADQQQIAFwAAANRBAgAXAAAA3EECABcAAADgQQIAFwAAAOhBAgAXAAAA7EECABcAAADwQQIAFwAAAPRBAgAXAAAA+EECABcAAAD8QQIAFwAAAABCAgAXAAAABEICABcAAAAIQgIAFwAAAAxCAgAXAAAAFEICABcAAAAYQgIAFwAAACBCAgAXAAAAJEICABcAAAAoQgIAFwAAACxCAgAXAAAAMEICABcAAAA0QgIAFwAAADhCAgAXAAAAPEICABcAAABAQgIAFwAAAERCAgAXAAAATEICABcAAABQQgIAFwAAAFhCAgAXAAAAXEICABcAAABgQgIAFwAAAGRCAgAXAAAAaEICABcAAABsQgIAFwAAAHBCAgAXAAAAdEICABcAAAB4QgIAFwAAAHxCAgAXAAAAhEICABcAAACIQgIAFwAAAJBCAgAXAAAAlEICABcAAACYQgIAFwAAAJxCAgAXAAAAoEICABcAAACkQgIAFwAAAKhCAgAXAAAArEICABcAAACwQgIAFwAAALRCAgAXAAAAvEICABcAAADAQgIAFwAAAMhCAgAXAAAAzEICABcAAADQQgIAFwAAANRCAgAXAAAA2EICABcAAADcQgIAFwAAAOBCAgAXAAAA5EICABcAAADoQgIAFwAAAOxCAgAXAAAA9EICABcAAAD4QgIAFwAAAABDAgAXAAAABEMCABcAAAAIQwIAFwAAAAxDAgAXAAAAEEMCABcAAAAUQwIAFwAAABhDAgAXAAAAHEMCABcAAAAgQwIAFwAAACRDAgAXAAAALEMCABcAAAAwQwIAFwAAADhDAgAXAAAAPEMCABcAAABAQwIAFwAAAERDAgAXAAAASEMCABcAAABMQwIAFwAAAFBDAgAXAAAAVEMCABcAAABYQwIAFwAAAFxDAgAXAAAAZEMCABcAAABoQwIAFwAAAHBDAgAXAAAAdEMCABcAAAB4QwIAFwAAAHxDAgAXAAAAgEMCABcAAACEQwIAFwAAAIhDAgAXAAAA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NDYCAAIEAQBcNgIAAgcBALQ5AgACDQEAYDoCAAIQAQDcNgIAAhIBAOw2AgACEgEA9DcCAAIUAQAEOAIAAhQBANQ2AgACFQEA7DcCAAIXAQD0OQIAAhgBAFw0AgACGQEAbDQCAAIZAQBUNAIAAhwBAMw3AgACHwEA3DcCAAIfAQBATAIAFSIBAKQ3AgACIwEAtDcCAAIjAQDENwIAAicBACQ5AgACKgEAJEwCABUqAQAUNQIAAisBAJw3AgACLQEAdDQCAAIuAQDgOgIAAi8BAMQ0AgACMQEAHDcCAAIyAQBkOQIAAjMBAEQ3AgACNQEA9DYCAAI2AQBsNwIAAjgBAKA6AgACOQEA7DQCAAI6AQC8MwIAAjwBAIw1AgACPQEAtDUCAAJBAQDcNQIAAkMBAAA6AgACRAEAnDMCAAJFAQAgOwIAAkUBAAQ2AgACRgEAoDgCAAJKAQB8NgIAAksBAKQ2AgACTgEA/EsCABVPAQAkOwIAAlABAMA5AgACUgEAPDUCAAJTAQBkNQIAAlQBAOA5AgACVQEAhDkCAAJWAQC4OQIAAlYBAMQ5AgACVgEAGDoCAAJWAQCkOgIAAlYBADw7AgACVgEASDsCAAJWAQBITAIAFVYBAOw5AgACVwEAsDoCAAJXAQDQOgIAAlcBAPA6AgACVwEA/DoCAAJYAQBgOQIAAlkBAHQ5AgACWQEAiDkCAAJZAQCkOQIAAlkBACQ0AgACWgEAKEwCABVaAQCcNAIAAl0BAJQ6AgACYAEALDYCAAJjAQB0OgIAAmQBAFQ2AgACZQEAODsCAAJmAQAATAIAFWwBADQ4AgACbQEALEwCABVtAQA0OgIAAnYBAMg4AgACeQEA8EsCABV6AQBQOAIAAn0BAOQ5AgACgAEADDoCAAKAAQA4OgIAAoABAFg6AgACgAEAeDoCAAKAAQCkMwIAAoMBAPwyAgACigEA9DMCAAKNAQC4OgIAAo4BAMgzAgACkwEAFDoCAAKWAQAoNAIAApoBADg0AgACmgEAUDQCAAKaAQBgNAIAApoBAHg0AgACmgEAiDQCAAKaAQCgNAIAApoBALA0AgACmgEAyDQCAAKaAQDYNAIAApoBAPA0AgACmgEAADUCAAKaAQAYNQIAApoBACg1AgACmgEAQDUCAAKaAQBQNQIAApoBAGg1AgACmgEAeDUCAAKaAQCQNQIA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TPe85QDGj+IayoziRPe85QDGj+IayoziPPe85QDGj+IayoziNPe85QDGj+IayoziLPe85QDGj+IayoziJPe85QDGj+IayoziHPe85QDGj+IayoziFPe85QDGj+IayoziDPe85QDGj+IayoziBPe85QDGj+Iayozi/Pa85QDGj+Iayozi9Pa85QDGj+Iayozi7Pa85QDGj+Iayozi5Pa85QDGj+Iayozi3Pa85QDGj+Iayozi1Pa85QDGj+IayozizPa85QDGj+IayozixPa85QDGj+IayozivPa85QDGj+IayozitPa85QDGj+IayozirPa85QDGj+IayozipPa85QDGj+IayozinPa85QDGj+IayozilPa85QDGj+IayozijPa85QDGj+IayozihPa85QDGj+IayozifPa85QDGj+IayozidPa85QDGj+IayozibPa85QDGj+IayoziZPa85QDGj+IayoziXPa85QDGj+IayoziVPa85QDGj+IayoziTPa85QDGj+IayoziRPa85QDGj+IayoziPPa85QDGj+IayoziNPa85QDGj+IayoziLPa85QDGj+IayoziJPa85QDGj+IayoziHPa85QDGj+IayoziFPa85QDGj+IayoziDPa85QDGj+IayoziBPa85QDGj+Iayozi/PW85QDGj+Iayozi9PW85QDGj+Iayozi7PW85QDGj+Iayozi5PW85QDGj+Iayozi3PW85QDGj+Iayozi1PW85QDGj+IayozizPW85QDGj+IayozixPW85QDGj+IayozivPW85QDGj+IayozitPW85QDGj+IayozirPW85QDGj+IayozipPW85QDGj+IayozinPW85QDGj+IayozilPW85QDGj+IayozijPW85QDGj+IayozihPW85QDGj+IayozifPW85QDGj+IayozidPW85QDGj+IayozibPW85QDGj+IayoziZPW85QDGj+IayoziXPW85QDGj+IayoziVPW85QDGj+IayoziTPW85QDGj+IayoziRPW85QDGj+IayoziPPW85QDGj+IayoziNPW85QDGj+IayoziLPW85QDGj+IayoziJPW85QDGj+IayoziHPW85QDGj+IayoziFPW85QDGj+IayoziDPW85QDGj+IayoziBPW85QDGj+Iayozi/PS85QDGj+Iayozi9PS85QDGj+Iayozi7PS85QDGj+Iayozi5PS85QDGj+Iayozi3PS85QDGj+Iayozi1PS85QDGj+IayozizPS85QDGj+IayozixPS85QDGj+IayozivPS85QDGj+IayozitPS85QDGj+IayozirPS85QDGj+IayozipPS85QDGj+IayozinPS85QDGj+IayozilPS85QDGj+IayozijPS85QDGj+IayozihPS85QDGj+IayozifPS85QDGj+IayozidPS85QDGj+IayozibPS85QDGj+IayoziZPS85QDGj+IayoziXPS85QDGj+IayoziVPS85QDGj+IayoziTPS85QDGj+IayoziRPS85QDGj+IayoziPPS85QDGj+IayoziNPS85QDGj+IayoziLPS85QDGj+IayoziJPS85QDGj+IayoziHPS85QDGj+IayoziFPS85QDGj+IayoziDPS85QDGj+IayoziBPS85QDGj+Iayozi/PO85QDGj+Iayozi9PO85QDGj+Iayozi7PO85QDGj+Iayozi5PO85QDGj+Iayozi3PO85QDGj+Iayozi1PO85QDGj+IayozizPO85QDGj+IayozixPO85QDGj+IayozivPO85QDGj+IayozitPO85QDGj+IayozirPO85QDGj+IayozipPO85QDGj+IayozinPO85QDGj+IayozilPO85QDGj+IayozijPO85QDGj+IayozihPO85QDGj+IayozifPO85QDGj+IayozidPO85QDGj+IayozibPO85QDGj+IayoziZPO85QDGj+IayoziXPO85QDGj+IayoziVPO85QDGj+IayoziTPO85QDGj+IayoziRPO85QDGj+IayoziPPO85QDGj+IayoziNPO85QDGj+IayoziLPO85QDGj+IayoziJPO85QDGj+IayoziHPO85QDGj+IayoziFPO85QDGj+IayoziDPO85QDGj+IayoziBPO85QDGj+Iayozi/PK85QDGj+Iayozi9PK85QDGj+Iayozi7PK85QDGj+Iayozi5PK85QDGj+Iayozi3PK85QDGj+Iayozi1PK85QDGj+IayozizPK85QDGj+IayozixPK85QDGj+IayozivPK85QDGj+IayozitPK85QDGj+IayozirPK85QDGj+IayozipPK85QDGj+IayozinPK85QDGj+IayozilPK85QDGj+IayozijPK85QDGj+IayozihPK85QDGj+IayozifPK85QDGj+IayozidPK85QDGj+IayozibPK85QDGj+IayoziZPK85QDGj+IayoziXPK85QDGj+IayoziVPK85QDGj+IayoziTPK85QDGj+IayoziRPK85QDGj+IayoziPPK85QDGj+IayoziNPK85QDGj+IayoziLPK85QDGj+IayoziJPK85QDGj+IayoziHPK85QDGj+IayoziFPK85QDGj+IayoziDPK85QDGj+IayoziBPK85QDGj+Iayozi/PG85QDGj+Iayozi9PG85QDGj+Iayozi7PG85QDGj+Iayozi5PG85QDGj+Iayozi3PG85QDGj+Iayozi1PG85QDGj+IayozizPG85QDGj+IayozixPG85QDGj+IayozivPG85QDGj+IayozitPG85QDGj+IayozirPG85QDGj+IayozipPG85QDGj+IayozinPG85QDGj+IayozilPG85QDGj+IayozijPG85QDGj+IayozihPG85QDGj+IayozifPG85QDGj+IayozidPG85QDGj+IayozibPG85QDGj+IayoziZPG85QDGj+IayoziXPG85QDGj+IayoziVPG85QDGj+IayoziTPG85QDGj+IayoziRPG85QDGj+IayoziPPG85QDGj+IayoziNPG85QDGj+IayoziLPG85QDGj+IayoziJPG85QDGj+IayoziHPG85QDGj+IayoziFPG85QDGj+IayoziDPG85QDGj+IayoziBPG85QDGj+Iayozi/PC85QDGj+Iayozi9PC85QDGj+Iayozi7PC85QDGj+Iayozi5PC85QDGj+Iayozi3PC85QDGj+Iayozi1PC85QDGj+IayozizPC85QDGj+IayozixPC85QDGj+IayozivPC85QDGj+IayozitPC85QDGj+IayozirPC85QDGj+IayozipPC85QDGj+IayozinPC85QDGj+IayozilPC85QDGj+IayozijPC85QDGj+IayozihPC85QDGj+IayozifPC85QDGj+IayozidPC85QDGj+IayozibPC85QDGj+IayoziZPC85QQAn+UAAI/gR/3/6jSDAQAe/y/h/f//6gAAUOMe/y8BEP8v4QAQoOEMAJ/l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uACQAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOAI4AjgCOALsAvgDBAMQAxwDKAM0A0ADTANYA2QDcAN8A4gDlAOgA6wDuAPEA9AD3APoA/QAAAQMBBgEJAQwBDwESARUBGAGMSHhEcEeh9YBwHygk2N/oEPAgALAAswC2ALkAvAC/AMIAxQDIAMsAzgDRANQA1wDaAN0A4ADjAOYA6QDsAO8A8gD1APgA+wD+AAMBBgEJAQwBpkh4RHBHxEh4RHBHdkh4RHBHdUh4RHBHdUh4RHBHdEh4RHBHdEh4RHBHc0h4RHBHc0h4RHBHckh4RHBHckh4RHBHcUh4RHBHcUh4RHBHcEh4RHBHcEh4RHBHYEh4RHBHbkh4RHBHbUh4RHBHbUh4RHBHbEh4RHBHbEh4RHBHa0h4RHBHa0h4RHBHakh4RHBHakh4RHBHaUh4RHBHaUh4RHBHaEh4RHBHaEh4RHBHZ0h4RHBHZ0h4RHBHZkh4RHBHZkh4RHBHZUh4RHBHZUh4RHBHZEh4RHBHZEh4RHBHY0h4RHBHY0h4RHBHYkh4RHBHYkh4RHBHYUh4RHBHYUh4RHBHYEh4RHBHYEh4RHBHX0h4RHBHX0h4RHBHXkh4RHBHX0h4RHBHXkh4RHBHXkh4RHBHXUh4RHBHXUh4RHBHXEh4RHBHXEh4RHBHW0h4RHBHW0h4RHBHWkh4RHBHWkh4RHBHWUh4RHBHWUh4RHBHWEh4RHBHWEh4RHBHV0h4RHBHV0h4RHBHVkh4RHBHVkh4RHBHVUh4RHBHVUh4RHBHVEh4RHBHVEh4RHBHU0h4RHBHU0h4RHBHUkh4RHBHUkh4RHBHTEoAAFBIeERwR1BIeERwR09IeERwR09IeERwR9dIAACGSQAAK0kAAChJAAAlSQAAIkkAAB9JAAAcSQAAGUkAABZJAAATSQAAEEkAAA1JAAALSQAACUkAAAFJAAD+SAAA+0gAAPhIAAD1SAAA8kgAAO9IAADsSAAA6UgAAOZIAADjSAAA4UgAAN9IAADdSAAA20gAANlIAADXSAAA1UgAANNIAADRSAAAz0gAAM1IAADLSAAAyUgAAMdIAADFSAAAw0gAAMFIAAC/SAAAvUgAALtIAAC5SAAA10kAALpIAAC3SAAAtEgAALFIAACuSAAAq0gAAKhIAAClSAAAokgAAJ9IAACdSAAAm0gAAJlIAACXSAAAlUgAAJNIAACRSAAAj0gAAI1IAACLSAAAiUgAAIdIAACFSAAAg0gAAIFIAAB/SAAAfUgAAHdIAAB1SAAAc0gAAHFIAABHSgAAAOCg4f8fnug00J7lPOCe5R7/L+EgC5DsHv8v4SALkOwe/y/hIAvQ7B7/L+F4R8BGAMCf5Q/wjOBk4/7/eEfARgDAn+UP8IzgJOn+/3hHwEYAwJ/lD/CM4Bji/v94R8BGAMCf5Q/wjODw4f7/eEfARgDAn+UP8IzgDOn+/3hHwEYAwJ/lD/CM4BTp/v94R8BGAMCf5Q/wjOAQ6f7/eEfARgDAn+UP8IzgYOn+/3hHwEYAwJ/lD/CM4Nzk/v94R8BGAMCf5Q/wjOA04/7/eEfARgDAn+UP8IzgeOn+/3hHwEYAwJ/lD/CM4Ozp/v94R8BGAMCf5Q/wjOC86P7/eEfARgDAn+UP8IzgiOL+/3hHwEYAwJ/lD/CM4OT+//94R8BGAMCf5Q/wjOD4/v//4Ov+fwEAAAAs7P5/sLAAgFTs/n8IhJeA1Oz+f1QTAADq7P5/CISXgCD0/n+wsAiA5vT+fwiEl4D69P5/sLAIgGj1/n8IhJeAmPX+f7CwCIDy9f5/sLAGgGT2/n8IhJeAEPj+fyQTAACU+P5/sLABgKD4/n8IhJeAFPn+f7CwAIAY+f5/sLAGgKD5/n8IhJeA3Pn+fwEAAADg+f5/sLAAgOr5/n8BAAAA5Pn+fwiEl4Bs+v5/sLAAgPT6/n8IhJeAAvv+f9wSAAAg+/5/CISXgMj7/n+wsACA2Pv+fwiEl4CgCf9/sLAAgLQJ/38IhJeA6An/f7CwAYD4Cf9/sLACgC4K/38IhJeAhAr/f6wSAABQEv9/CISXgHgW/3+wsACAfBb/fwiEl4CGFv9/sLAAgIoW/3+wsA+A8Bf/f4gSAABEGP9/sLAAgEYY/38IhJeAbBj/f7CwAIBuGP9/CISXgKAY/3+wsACAohj/fwiEl4DsGP9/sLAAgPYY/38IhJeABBn/f7CwAIAGGf9/CISXgBAZ/3+wsACAEhn/fwiEl4BkGf9/PBIAALQa/38IhJeAEhv/f7CwAYAcG/9/CISXgCYb/3+wsACAKBv/fwiEl4D+G/9/sLAAgP4b/38IhJeAZBz/f7CwAIBmHP9/CISXgOoc/3+wsACA7hz/fwiEl4D4HP9/sLAAgPwc/3/gEQAAPB3/fwiEl4BgHf9/sLAAgGgd/38IhJeAuB3/f7CwAoDQHf9/CISXgCYe/3+wsACAKB7/f8ARAABCHv9/CISXgKQe/3+wsACAph7/fwiEl4C0Hv9/uBEAADgf/3/EEQAA5B//fwiEl4DuH/9/sLAAgPAf/3+wsAKAECD/fwiEl4BKIP9/sLAAgGYg/38IhJeA4CD/f7CwAIDkIP9/CISXgGAh/3+YEQAABCL/fwiEl4CEIv9/lBEAAMwi/3+kEQAAJCP/fwiEl4DyI/9/sLAAgPoj/38IhJeABCT/f7CwAIAGJP9/sLCwgAQk/38IhJeASiT/f7CwAIBMJP9/CISXgMgk/3+wsACAyiT/fwiEl4A0Jf9/sLAAgDgl/38IhJeACif/f7CwAIAKJ/9/sLADgBQn/38IhJeAICf/f7CwAIAiJ/9/CISXgIYn/38wEQAAyif/fwiEl4DuJ/9/sLABgPAn/38wEQAAECj/fwiEl4CwKf9/OBEAAFQr/38IhJeAYiv/f7CwAIBkK/9/CISXgMor/3+wsACAzCv/fwEAAADEK/9/FBEAACgt/38IhJeA7C3/f7CwAIAMLv9/sLABgBgu/38IhJeA4C//fwQRAABMMf9/CISXgHwy/38QEQAA0DL/fwiEl4AwM/9/sLAAgDIz/38IhJeA4DP/f7CwA4DqM/9/CISXgAg0/3+wsACACjT/fwiEl4BGNP9/sLAAgEg0/38IhJeAgjT/f9wQAADMNP9/CISXgPA0/3+wsAGA8jT/f9wQAAAONf9/CISXgBg1/3+wsACAGjX/fwiEl4AoNf9/1BAAAKw1/3/gEAAAWDb/fwiEl4BiNv9/sLAAgGQ2/3+wsAKAgDb/fwiEl4CmNv9/sLAAgLg2/38IhJeAhDf/f8QQAAAgOP9/CISXgKA4/3/AEAAA6Dj/f9AQAABAOf9/CISXgHA5/3+wsACAdDn/fwiEl4B+Of9/sLAAgIA5/38IhJeA/Dn/f7CwAID+Of9/CISXgGQ6/3+wsACAaDr/fwiEl4CiO/9/sLAAgKw7/38IhJeA7Dv/f4wQAAAwPP9/CISXgIw8/3+wsAGAlDz/fwiEl4CmPP9/sLAAgKw8/398EAAAlED/f7CwAoCsQP9/CISXgF5C/39wEAAAIEP/fwiEl4D4Q/9/bBAAAMxF/3+wsACAzkX/fwEAAADIRf9/YBAAAGRK/38IhJeAekv/f7CwAYCES/9/bBAAAPRL/38IhJeABEz/f7CwAYAMTP9/sLAAgCBM/38IhJeABE3/f1AQAAA4Tv9/CISXgKBP/39MEAAA6k//fwiEl4A+Uf9/sLABgEBR/38BAAAAOFH/fwiEl4BYUf9/PBAAAJRR/39AEAAAplH/f7CwsICiUf9/UBAAALRR/3+wsLCAxFH/f2AQAAA8Uv9/ZBAAAE5S/3+wsLCASlL/f3QQAABcUv9/sLCwgHBS/38BAAAAaFL/f3wQAACcUv9/jBAAANBS/3+QEAAA+FL/f7CwsIAcU/9/mBAAACZT/3+cEAAAbFP/f6AQAACgU/9/sBAAAMhT/3+wsLCA7FP/f7gQAAD2U/9/AQAAAABU/3+wsLCALFT/f6wQAABOVP9/xBAAAFZU/3/YEAAAalT/f7CwsIBoVP9/1BAAALxU/38IhJeAzFT/f9AQAADWVP9/sLCwgNRU/3/MEAAAJFX/f+QQAABwVf9/6BAAANhV/38AEQAASFb/fwQRAACAVv9/CISXgLBW/38UEQAABFf/f7CwsIAYV/9/EBEAAHBX/38oEQAA4Ff/fywRAAD8V/9/CISXgARY/38oEQAAElj/fwEAAAAMWP9/NBEAAExY/384EQAAeFj/fwiEl4DAWP9/AQAAALhY/3+wsLCAxFj/fyQRAAD8WP9/CISXgCBZ/3+wsLCALFn/fygRAABYWf9/sLCwgIhZ/38BAAAAgFn/fzgRAACQWv9/CISXgJxa/380EQAAYF3/fzgRAACQXf9/PBEAAKRd/39AEQAA5F3/f0QRAABIX/9/oBEAAL5f/3+kEQAA4F//f6gRAABAYP9/rBEAAHBg/3+wEQAAkGD/f7QRAAC8YP9/AQAAALRg/3+wEQAA8GD/f7QRAACgYf9/uBEAAMxh/3+wsLCA4GH/f7QRAACYYv9/sLCwgKxi/3+wEQAAuGL/fwEAAACwYv9/sLCwgLJi/38IhJeASmP/f7CwsIBQY/9/CISXgG5j/3+wsLCAfGP/f5QRAAAQZP9/sLCwgDhk/3+QEQAASGT/f5QRAABkZP9/mBEAAJBk/3+cEQAA8GT/f6ARAAA4Zf9/pBEAABhn/3+oEQAAtGf/f6wRAAAEaP9/sBEAALxo/3+0EQAAiGn/f7gRAADeaf9/sLCwgOhp/3+0EQAAjmv/f7gRAADAa/9/vBEAAO5r/3/AEQAAqGz/f8QRAAAabf9/yBEAABJu/3/MEQAAVG7/f9ARAAB8bv9/AQAAAHRu/3+wsLCA0G7/fwEAAADIbv9/vBEAAOhu/3/AEQAAEG//fwiEl4AYb/9/sLCwgBRv/3+0EQAANG//fwiEl4A8b/9/sLCwgDhv/38IhJeAoG//fwEAAACYb/9/sLCwgKxv/38IhJeAtG//f7CwsIDMb/9/CISXgNRv/3+wsLCA2G//fwEAAADQb/9/aBEAAChw/38BAAAAIHD/f7CwsIB4cP9/XBEAAExx/38IhJeAYHH/fwEAAABYcf9/UBEAALRz/39oEQAA0nP/f2wRAADkc/9/cBEAADp0/390EQAASnT/f3gRAABadP9/fBEAAHx0/3+AEQAArHT/f4QRAAC8dP9/iBEAAAh6/3+MEQAAWnr/f5ARAACEev9/lBEAAICC/3+YEQAAmoL/f5wRAACwgv9/oBEAAEyG/3+wsLCAaIb/f5wRAABQh/9/oBEAAMKH/3+kEQAA3If/f6gRAAA0iP9/rBEAALiI/3+wEQAAFIn/f7QRAAB8if9/uBEAAJSJ/3+wsLCAmon/f7QRAACwif9/sLCwgLaJ/3+wEQAA4In/f7QRAAAYiv9/sLCwgBSK/3+wEQAAKIv/f7QRAAAIjv9/0BEAADCO/3/UEQAAbI7/f9gRAACMjv9/3BEAAOSO/3/gEQAAAJD/f+QRAABYkP9/6BEAAEiR/3/sEQAAtJH/f/ARAADwk/9/FBIAAAiU/3+wsLCAHJT/fxASAABAlP9/CISXgEaU/3+wsLCAQpT/fwQSAACYlP9/CBIAALaU/38MEgAA1JT/fxwSAADylP9/LBIAABCV/388EgAAMJX/f0wSAABOlf9/XBIAAGyV/3+wsLCApJX/f2QSAABIqf9/gBIAAISp/3+EEgAAQK3/f4gSAADArf9/jBIAAAiu/3+QEgAARK7/f5QSAAB8rv9/mBIAANyv/3+cEgAAFLD/f6ASAADssP9/pBIAACix/3+oEgAATLH/f6wSAACIsf9/sBIAALSx/3+0EgAA1LH/f7gSAAD4sf9/vBIAAFSy/3/AEgAAgLL/f8QSAAAIs/9/sLCwgASz/3/AEgAALLP/f7CwsIAos/9/vBIAAMiz/3+wsLCA4LP/f7gSAAB8tP9/sLCwgHi0/3+0EgAAFLX/f7CwsIAQtf9/sBIAAFS1/3+wsLCAULX/f6wSAAB4tf9/sBIAAJi1/3+wsLCAmLX/f6wSAABQtv9/sLCwgEy2/3+oEgAAqLb/f7gSAAAkt/9/sLCwgCC3/3/EEgAA3Lf/f7CwsIDYt/9/wBIAAPS3/3/EEgAAOLj/f7CwsIA0uP9/wBIAAJC4/3+wsLCAjLj/f7wSAADAuP9/sLCwgLy4/3+4EgAAGLn/f7wSAABEuf9/wBIAAFy5/3/EEgAAsLn/f7CwsICsuf9/wBIAAPC5/3+wsLCA7Ln/f7wSAAA2uv9/wBIAAHC6/3/EEgAAmLr/f8gSAABou/9/zBIAAIy7/3/QEgAACLz/f9QSAAAcvP9/2BIAAEC8/38IhJeARrz/f7CwsIBEvP9/zBIAAKzB/3/oEgAAzMH/f7CwsIDIwf9/5BIAAObB/3/oEgAABML/f+wSAAAowv9/8BIAAEbC/3/0EgAAZML/f/gSAACCwv9//BIAAKDC/38AEwAAwML/fwQTAADgwv9/sLCwgNzC/38AEwAA/ML/f7CwsID4wv9//BIAABTD/38IhJeAGsP/f7CwsIAYw/9/8BIAADTD/3/0EgAAUMP/f7CwsIBMw/9/8BIAAJzD/3+wsLCAmMP/f+wSAADQw/9/8BIAACjE/3+wsLCAJMT/f+wSAAB8xP9/sLCwgHjE/3/oEgAAkMT/f+wSAAC4xP9/sLCwgLTE/3/oEgAA+MT/f7CwsID0xP9/5BIAABzF/3/oEgAA1MX/f7CwsIDQxf9/5BIAAPDF/3/oEgAAEMb/f7CwsIAMxv9/5BIAAHzG/3+wsLCAeMb/f+ASAADExv9/sLCwgMzG/3/oEgAA6Mb/f7CwsIDkxv9/5BIAABTH/3+wsLCAEMf/f+ASAABIx/9/5BIAALDH/38IhJeAwMf/f7CwsIC8x/9/2BIAAAzI/3+wsLCACMj/f9QSAABAyP9/2BIAAITI/3+wsLCAgMj/f9QSAAC8yP9/sLCwgLjI/3/QEgAADMn/f7CwsIAIyf9/zBIAACbJ/3+wsLCAIsn/f8gSAAB8yf9/zBIAAKTJ/3/QEgAAyMn/f7CwsIDEyf9/zBIAAOjJ/3/QEgAAUMr/fwiEl4Bgyv9/sLCwgCzL/3/EEgAAfMv/f7CwsIB4y/9/wBIAAIrL/38IhJeAkMv/f7CwsICMy/9/tBIAAKjL/38IhJeArsv/f7CwsIC0y/9/qBIAANzL/3+wsLCA4Mv/f6QSAAAUzP9/qBIAAMjM/3+wsLCAxMz/f6QSAAAEzf9/sLCwgADN/3+gEgAACM//f6QSAAAY0P9/qBIAADbQ/3+sEgAAVND/f7ASAAB00P9/tBIAACTR/3+4EgAAWNH/f7wSAACI0f9/sLCwgITR/3+4EgAArNH/f7CwsICw0f9/tBIAAMzR/3+4EgAAiNL/f7CwsICE0v9/tBIAAMTS/3+wsLCAwNL/f7ASAADk0v9/sLCwgPTS/3+sEgAATNP/f7CwsIBQ0/9/qBIAAIzT/3+wsLCAiNP/f6QSAACg0/9/qBIAAOTT/3+wsLCA8NP/f6QSAABc1P9/sLCwgGDU/3+gEgAAyNT/f6QSAAD41P9/sLCwgPTU/3+gEgAAEtX/f7CwsIAU1f9/nBIAALzV/3+gEgAAANb/f7CwsID81f9/CISXgCjW/3+wsLCAKNb/f4wSAADI1v9/oBIAACTX/3+wsLCAINf/f6gSAABO1/9/rBIAAGbX/3+wsLCAYtf/fwEAAABc1/9/CISXgHTX/38BAAAAbNf/f5ASAACs1/9/lBIAAAza/3+YEgAAsNr/f5wSAABY2/9/oBIAAKDc/3+wsLCAoNz/f5wSAADI3P9/sLCwgNDc/3+YEgAAaN3/f5wSAAB43v9/sLCwgHTe/3+YEgAA1N7/f5wSAAAA3/9/oBIAACzf/3+wsLCAMN//fwiEl4A63/9/AQAAAGTf/3+MEgAApN//f5ASAADQ3/9/lBIAABDg/3+YEgAAQOD/f5wSAAB04P9/sLCwgHLg/3+YEgAAjOD/fwiEl4CY4P9/lBIAAKzg/38IhJeAsOD/f7CwsICu4P9/CISXgLLg/3+wsLCA6uD/f3gSAAA24f9/sLCwgEjh/390EgAAdOH/f3gSAADQ4f9/sLCwgNjh/390EgAASOL/f3gSAAC04v9/fBIAAFjj/3+AEgAADOT/f4QSAABQ5P9/iBIAAFzk/3+MEgAAiOT/f5ASAADg5P9/lBIAABzl/3+YEgAAvOb/f5wSAADw5v9/oBIAADDn/3+wsLCAbOv/fwEAAADwzf5/CISXAP8ADQEECgYYAQEAAAAAAADYzf5/CISXAP//AQwAIAAAIApcACpiAADAzf5/CISXAP8ADQEECgYeAQEAAAAAAABBlwGBsLANhAAAAACczf5/CISXAP8AEQEIFB5KATIqAAABAAAAAAAAQZcBgbCwC4QAAAAAdM3+fwiElwD//wEMABIAABIILgAaLgAAXM3+fwiElwD/AA0BBBAGHAEBAAAAAAAARM3+fwiElwD//wEIPg5uAExAAAAwzf5/CISXAP//AQ0AXAAAXB6WAQB6OgAAAAAAQZcBgbCwDYQAAAAACM3+fwiElwD/AA0BBCYMSAEBAAAAAAAA8Mz+fwiElwD/ABEBCCQITAEsNAAAAQAAAAAAANTM/n8IhJcA/wANAQQyDEYBAQAAAAAAALzM/n8IhJcA/wANAQQWBiIBAQAAAAAAAEOXAYGwq4CAAAAAAJjM/n8IhJcA//8BCk46YgCIAeQBAAAAAIDM/n8IhJcA//8BDwAyAAAyzAGoAQD+AXYAAABkzP5/CISXAP8AEQEIFB5KATIqAAABAAAAAAAASMz+fwiElwD/AA0BBDIMTAEBAAAAAAAAMMz+fwiElwD/AA0BBBIGHgEBAAAAAAAAGMz+fwiElwD//wEIPg5uAExAAAAEzP5/CISXAP//AQ0AXAAAXB6WAQB6OgAAAAAAQZcBgbCwDYQAAAAA3Mv+fwiElwD/AA0BBCYMSAEBAAAAAAAAxMv+fwiElwD/ABEBCCQITAEsNAAAAQAAAAAAAKjL/n8IhJcA/wANAQQyDEYBAQAAAAAAAEGXAYGwsA2EAAAAAEGXAYGwsAuEAAAAAEGXAYGwsA2EAAAAAGzL/n8IhJcA//8BFwBAAABAygSIAQCMBbwCxgUAyAfcAQAAAISXAYGwsAAIAAAAAEGXAYGwsAuEAAAAADDL/n8IhJcA/wANAQQyDEwBAQAAAAAAAEGXAYGwsA2EAAAAAAzL/n8IhJcA/wAVAQwEBAoBCAYAAA4EFgEBAAAAAAAA7Mr+fwiElwD/ABUBDAQECgEIBgAADgQWAQEAAAAAAABDlwGBsKsQgAAAAADAyv5/CISXAP8AFQEMBAQKAQgGAAAOBBYBAQAAAAAAAKDK/n8IhJcA/wAVAQwEBAoBCAYAAA4EFgEBAAAAAAAAgMr+f4RBlwGwsLAL//8BCB4GKAAkGAAAQ5cBgbCrgIAAAAAAXMr+f4RBlwGwsLAL//8BCBQEHAAYGAAAQZcBgbCwDYQAAAAAQZcBgbCwDYQAAAAALMr+f4RBlwGwsLAL//8BCB4GKAAkGAAAFMr+f4RBlwGwsLAL//8BCBQEHAAYGAAAQZcBgbCwDYQAAAAA8Mn+f4RBlwGwsLAL/wANAQgKBiYBEBoAAH8AAAAAAADQyf5/CISXAP8ADQEIBAYMAQoGAAB/AAAAAAAAQZcBgbCwDYQAAAAAQ5cBgbCrEIAAAAAAQZcBgbCwDYQAAAAAkMn+f4RBlwGwsLAN/wANAQgGBEoBCk4AAH8AAAAAAABBlwGBsLALhAAAAABkyf5/gEOXAbCwq4D/AA0BCA4EZAESXgAAfwAAAAAAAEGXAYGwsAuEAAAAADjJ/n+EQZcBsLCwDf8ADQEIKgQ6AS4QAAB/AAAAAAAAQ5cBgbCrgIAAAAAADMn+f4RBlwGwsLAN/wANAQgEBFQBCFgAAH8AAAAAAABBlwGBsLALhAAAAABBlwGBsLANhAAAAADUyP5/CISXAP8ADQEIBAQSAQgOAAB/AAAAAAAAQZcBgbCwDYQAAAAAQZcBgbCwDYQAAAAAoMj+f7CwqAD/ABEBCAIENgEgCDIBAQAAAAAAAITI/n+EQZcBsLCwDf8AGQEQBAoOAQ4EAAASCBoBHAQmAQEAAAAAAABFlwGBsKuwgAAAAABGlwGBsKvwgAAAAABBlwGBsLANhAAAAABBlwGBsLALhAAAAABDlwGBsKuAgAAAAAAgyP5/gEaXAbCwq/D/AFUBSwBGAABGBEoBWAbGAgB0BsQCAIQBBrYCAJwBKMICANIBGLgCAOoBEgAA/AEEuAIAgAIIAACIAgy4AgCkAhLCAgDIAgTSAgHMAiAAAAEAAAAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAARZcBgbCrsIAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwDYQAAAAAQZcBgbCwDYQAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrEIAAAAAAQ5cBgbCrgIAAAAAARZcBgbCrcIAAAAAARMf+f4RBlwGwsLAN/wANAQQIBBABAQAAAAAAAEWXAYGwq3CAAAAAAEGXAYGwsA2EAAAAAEGXAYGwsAuEAAAAAEOXAYGwq4CAAAAAAEWXAYGwq3CAAAAAAEGXAYGwsAuEAAAAAEaXAYGwq/CAAAAAAEWXAYGwq7CAAAAAAEGXAYGwsAuEAAAAAEOXAYGwq4CAAAAAAEWXAYGwq7CAAAAAAEGXAYGwsA2EAAAAAEaXAYGwq/CAAAAAAEOXAYGwq4CAAAAAAEOXAYGwq4CAAAAAAEWXAYGwq7CAAAAAAEWXAYGwq7CAAAAAAEaXAYGwq/CAAAAAAEWXAYGwq7CAAAAAAEOXAYGwq4CAAAAAAEGXAYGwsA2EAAAAAEGXAYGwsA2EAAAAAEGXAYGwsA2EAAAAAEOXAYECq4CAAAAAAEGXAYGwsAuEAAAAAPzF/n+ARpcBsLCr8P//AQ2oAbgCtAQA4AOEAQAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwDYQAAAAAQZcBgbCwDYQAAAAAQZcBgbCwDYQAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwC4QAAAAARpcBgbCr8IAAAAAAQ5cBgbCrgIAAAAAAQ5cBgbCrgIAAAAAARpcBgbCr8IAAAAAAQZcBgbCwDYQAAAAAQZcBgbCwDYQAAAAARpcBgbCr8IAAAAAAQ5cBgbCrEIAAAAAARZcBgbCrsIAAAAAAQZcBgbCwC4QAAAAARZcBgbCrsIAAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrEIAAAAAAmMT+f4BGlwGwsKvw//8BEQDmAQAA5gEGyAUA7AH8AwAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwDYQAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAARZcBgbCrsIAAAAAAQZcBgbCwDYQAAAAAQ5cBgbCrEIAAAAAARpcBgbCr8IAAAAAAFMT+f4BFlwGwsKuw//8BHACgAgAAoAIMiAQArAJeAACKAwaKBACQA7QBAABBlwGBsLANhAAAAABBlwGBsLALhAAAAABDlwGBsKuAgAAAAABBlwGBsLALhAAAAAC4w/5/hEGXAbCwsA3//wEIFAQeABgOAACgw/5/hEGXAbCwsA3//wEIFAQeABgOAACIw/5/hEGXAbCwsA3//wEIFAQeABgOAABww/5/hEGXAbCwsA3//wEIFAIgABYSAABYw/5/hEGXAbCwsA3//wEIFgIeABgOAABAw/5/hEGXAbCwsA3//wEIFgIeABgOAAAow/5/gEaXAbCwq/D//wERAOQQAADkEAbCJQDqEMIWAAAAAABDlwGBsKuAgAAAAABFlwGBsKtwgAAAAABBlwGBsLALhAAAAABFlwGBsKuwgAAAAABDlwGBsKsQgAAAAABDlwGBsKuAgAAAAABFlwGBsKuwgAAAAABDlwGBsKsQgAAAAABDlwGBsKsQgAAAAABDlwGBsKuAgAAAAABBlwGBsLANhAAAAABDlwGBsKuAgAAAAABBlwGBsLANhAAAAABBlwGBsLALhAAAAABBlwGBsLANhAAAAABFlwGBsKuwgAAAAABBlwGBsLANhAAAAABDlwGBsKuAgAAAAABBlwGBsLANhAAAAABDlwGBsKsQgAAAAABDlwGBsKsQgAAAAABDlwGBsKsQgAAAAABDlwGBsKuAgAAAAABBlwGBsLANhAAAAABBlwGBsLALhAAAAABBlwGBsLALhAAAAADMwf5/gEOXAbCwq4D//wEIMgZUADgsAAC0wf5/gEaXAbCwq/D//wEMHgRyAF4GdABkIAAARpcBgbCr8IAAAAAAQZcBgbCwDYQAAAAAQ5cBgbCrgIAAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwC4QAAAAARpcBgbCr8IAAAAAARZcBgbCrsIAAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwDYQAAAAAQZcBgbCwC4QAAAAAQZcBgbCwDYQAAAAAQZcBgbCwC4QAAAAAwMD+f4BDlwGwsKsQ//8BEQDeBgAA3gYGvgkA5AaMBAAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwDYQAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwDYQAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwDYQAAAAAQ5cBgbCrEIAAAAAAQZcBgbCwDYQAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrEIAAAAAAZL/+f4RBlwGwsLAL//8BCCYIQAAuJgAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwDYQAAAAAQ5cBgbCrgIAAAAAAQ5cBgbCrgIAAAAAAQ5cBgbCrgIAAAAAAQ5cBgbCrgIAAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwDYQAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwDYQAAAAAQZcBgbCwDYQAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAARpcBgbCr8IAAAAAARZcBgbCrsIAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAARZcBgbCrsIAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwDYQAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrgIAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAAQ5cBgbCrEIAAAAAAQZcBgbCwC4QAAAAAQZcBgbCwC4QAAAAARZcBgbCrcIAAAAAAQZcBgbCwC4QAAAAAML3+f4BDlwGwsKuA//8BCRY+jgEAVFQAAAAAABS9/n+AQ5cBsLCrgP//AQgWNlgATBgAAEOXAYGwq4CAAAAAAEGXAYGwsAuEAAAAAEGXAYGwsA2EAAAAAEaXAYGwq/CAAAAAAEOXAYGwq4CAAAAAAEOXAYGwq4CAAAAAAEaXAYGwq/CAAAAAAEGXAYGwsAuEAAAAAEOXAYGwqxCAAAAAAEaXAYGwq/CAAAAAAEGXAYGwsAuEAAAAAEGXAYGwsA2EAAAAAEGXAYGwsA2EAAAAAEGXAYGwsA2EAAAAAEOXAYGwq4CAAAAAAEOXAYGwq4CAAAAAAEOXAYGwq4CAAAAAAEOXAYGwqxCAAAAAAEGXAYGwsA2EAAAAAEGXAYGwsA2EAAAAAEGXAYGwsA2EAAAAAEOXAYGwqxCAAAAAAEOXAYGwq4CAAAAAAEGXAYGwsA2EAAAAAEGXAYGwsA2EAAAAAEGXAYGwsAuEAAAAAEOXAYGwqxCAAAAAAEGXAYGwsAuEAAAAAEGXAYGwsA2EAAAAAEGXAYGwsA2EAAAAAEWXAYGwq7CAAAAAAEGXAYGwsAuEAAAAAEaXAYGwq/CAAAAAAEGXAYGwsAuEAAAAAEOXAYGwqxCAAAAAAEVycm9yAFslczolZF0iJXMiIGlzIHRvbyBzbWFsbCB0byBiZSBhbiBFTEYgZXhlY3V0YWJsZQoAUmVhZEVsZkhlYWRlcgBbJXM6JWRdIiVzIiBoYXMgYmFkIEVMRiBtYWdpYwoAVmVyaWZ5RWxmSGVhZGVyAFslczolZF0iJXMiIG5vdCAzMi1iaXQ6ICVkCgBbJXM6JWRdIiVzIiBub3QgbGl0dGxlLWVuZGlhbjogJWQKAFslczolZF0iJXMiIGhhcyB1bmV4cGVjdGVkIGVfdmVyc2lvbjogJWQKAFslczolZF0iJXMiIGhhcyBpbnZhbGlkIGVfcGhudW06ICV6dQoAUmVhZFByb2dyYW1IZWFkZXIAWyVzOiVkXSIlcyIgaGFzIG5vIHZhbGlkIHBoZHIgZGF0YQoAWyVzOiVkXSIlcyIgaGFzIG5vIGxvYWRhYmxlIHNlZ21lbnRzCgBSZXNlcnZlQWRkcmVzc1NwYWNlAFslczolZF1jb3VsZG4ndCBtYXAgIiVzIiBzZWdtZW50ICV6dTogJXMKAExvYWRTZWdtZW50cwBbJXM6JWRdY2FuJ3QgZmluZCBsb2FkZWQgcGhkciBmb3IgIiVzIgoARmluZFBoZHIAWyVzOiVkXSIlcyIgbG9hZGVkIHBoZHIgJXAgbm90IGluIGxvYWRhYmxlIHNlZ21lbnQKAENoZWNrUGhkcgBbJXM6JWRdY2FuJ3QgcmVhZCBmaWxlICIlcyI6ICVzCgBSZWFkAFslczolZF0iJXMiIGhhcyBubyBlbm91Z2ggZGF0YSBhdCAleDolengsIG5vdCBhIHZhbGlkIGZpbGUgb3IgeW91IG5lZWQgdG8gZHVtcCBtb3JlIGRhdGEKAHJiAERlYnVnAFslczolZF09PT09PT09PT09PT09TG9hZER5bmFtaWNTZWN0aW9uRnJvbUJhc2VTb3VyY2U9PT09PT09PT09UmVidWlsZFBoZHI9PT09PT09PT09PT09PT09PT09PT09PT09CgBSZWJ1aWxkUGhkcgBbJXM6JWRdPT09PT09PT09PT09PT09PT09PT09UmVidWlsZFBoZHIgRW5kPT09PT09PT09PT09PT09PT09PT09PQoAWyVzOiVkXT09PT09PT09PT09PT09PT09PT09PT09UmVidWlsZFNoZHI9PT09PT09PT09PT09PT09PT09PT09PT09CgBSZWJ1aWxkU2hkcgAuZHluc3ltAC5keW5zdHIALmhhc2gALnJlbC5keW4ALnJlbGEuZHluAC5yZWwucGx0AC5yZWxhLnBsdAAucGx0AC50ZXh0JkFSTS5leHRhYgAuQVJNLmV4aWR4AC5maW5pX2FycmF5AC5pbml0X2FycmF5AC5keW5hbWljAC5kYXRhAC5zaHN0cnRhYgBbJXM6JWRdPT09PT09PT09PT09PT09PT09PT09UmVidWlsZFNoZHIgRW5kPT09PT09PT09PT09PT09PT09PT09PQoAWyVzOiVkXT09PT09PT09PT09PT09PT09PT09PT09UmVhZFNvSW5mbz09PT09PT09PT09PT09PT09PT09PT09PT0KAFJlYWRTb0luZm8AWyVzOiVkXU5vIHZhbGlkIGR5bmFtaWMgcGhkciBkYXRhCgBbJXM6JWRdc3RyaW5nIHRhYmxlIGZvdW5kIGF0ICV4CgBbJXM6JWRdc3ltYm9sIHRhYmxlIGZvdW5kIGF0ICV4CgBbJXM6JWRdJXMgcGx0X3JlbCAoRFRfSk1QUkVMKSBmb3VuZCBhdCAleAoAWyVzOiVkXSVzIHBsdF9yZWxfY291bnQgKERUX1BMVFJFTFNaKSAlenUKAFslczolZF0lcyByZWwgKERUX1JFTCkgZm91bmQgYXQgJXgKAFslczolZF0lcyByZWxfc2l6ZSAoRFRfUkVMU1opICV6dQoAWyVzOiVkXSVzIGNvbnN0cnVjdG9ycyAoRFRfSU5JVCkgZm91bmQgYXQgJXgKAFslczolZF0lcyBkZXN0cnVjdG9ycyAoRFRfRklOSSkgZm91bmQgYXQgJXgKAFslczolZF0lcyBjb25zdHJ1Y3RvcnMgKERUX0lOSVRfQVJSQVkpIGZvdW5kIGF0ICV4CgBbJXM6JWRdJXMgY29uc3RydWN0b3JzIChEVF9JTklUX0FSUkFZU1opICV6dQoAWyVzOiVkXSVzIGRlc3RydWN0b3JzIChEVF9GSU5JX0FSUkFZKSBmb3VuZCBhdCAleAoAWyVzOiVkXSVzIGRlc3RydWN0b3JzIChEVF9GSU5JX0FSUkFZU1opICV6dQoAWyVzOiVkXSVzIGNvbnN0cnVjdG9ycyAoRFRfUFJFSU5JVF9BUlJBWSkgZm91bmQgYXQgJWQKAFslczolZF0lcyBjb25zdHJ1Y3RvcnMgKERUX1BSRUlOSVRfQVJSQVlTWikgJXp1CgBbJXM6JWRdc29uYW1lICVzCgBbJXM6JWRdVW51c2VkIERUIGVudHJ5OiB0eXBlIDB4JTA4eCBhcmcgMHglMDh4CgBbJXM6JWRdPT09PT09PT09PT09PT09PT09PT09PT1SZWFkU29JbmZvIEVuZD09PT09PT09PT09PT09PT09PT09PT09PT0KAFslczolZF09PT09PT09PT09PT09PT09PT09PT09PXRyeSB0byBmaW5pc2ggZmlsZSByZWJ1aWxkID09PT09PT09PT09PT09PT09PT09PT09PT0KAFJlYnVpbGRGaW4AWyVzOiVkXT09PT09PT09PT09PT09PT09PT09PT09RW5kPT09PT09PT09PT09PT09PT09PT09PT09PQoAWyVzOiVkXT09PT09PT09PT09PT09PT09PT09PT09UmVidWlsZFJlbG9jcz09PT09PT09PT09PT09PT09PT09PT09PT0KAFJlYnVpbGRSZWxvY3MAWyVzOiVkXT09PT09PT09PT09PT09PT09PT09PT09UmVidWlsZFJlbG9jcyBFbmQ9PT09PT09PT09PT09PT09PT09PT09PQoAbmFtZQBiYXNpY19zdHJpbmcAYWxsb2NhdG9yPFQ+OjphbGxvY2F0ZShzaXplX3QgbikgJ24nIGV4Y2VlZHMgbWF4aW11bSBzdXBwb3J0ZWQgc2l6ZQB2ZWN0b3IASW5mbwBbJXM6JWRdZHluYW1pYyBzZWdtZW50IGhhdmUgYmVlbiBmb3VuZCBpbiBsb2FkYWJsZSBzZWdtZW50LCBhcmd1bWVudCBiYXNlc28gd2lsbCBiZSBpZ25vcmVkLgoATG9hZABbJXM6JWRdVW5hYmxlIHRvIHBhcnNlIGJhc2Ugc28gZmlsZSwgaXMgaXQgY29ycmVjdD8KAExvYWREeW5hbWljU2VjdGlvbkZyb21CYXNlU291cmNlAGhkbTpzOm86YjoAWyVzOiVkXVVzZSBkZWJ1ZyBtb2RlCgBtYWluX2xvb3AARXJyb3Igb3BlbmluZyAlcyBzcmMgc286ICVzAFslczolZF0lcwoAWyVzOiVkXXN0YXJ0IHRvIHJlYnVpbGQgZWxmIGZpbGUKAFslczolZF11bmFibGUgdG8gb3BlbiBzb3VyY2UgZmlsZQoAWyVzOiVkXXNvdXJjZSBzbyBmaWxlIGlzIGludmFsaWQKAFslczolZF1lcnJvciBvY2N1cmVkIGluIHJlYnVpbGRpbmcgZWxmIGZpbGUKAHdiKwBbJXM6JWRdb3V0cHV0IHNvIGZpbGUgY2Fubm90IHdyaXRlICEhIQoAWyVzOiVkXURvbmUhISEKAG1haW4ASGVyZUJlY2F1c2VJdEhhc1RvQmUALW0ALXMALW8ALWQAMHg3MmY1MDQxMDAwAC9kYXRhL2RhdGEvY29tLmV4YW1wbGUuZHVtcGZpeGVyL2ZpbGVzL2xpYmNvY28uc29fZHVtcF8uc28AL2RhdGEvZGF0YS9jb20uZXhhbXBsZS5kdW1wZml4ZXIvZmlsZXMvbGliY29jby5zb18weDcyZjUwNDEwMDBfNTA3OTA0LnNvAFslczolZF1Tb0ZpeGVyMzJ2Mi4xIGF1dGhvciBGOExFRlQoY3VycndpbikKAHVzZWFnZQBbJXM6JWRdVXNlYWdlOiBTb0ZpeGVyIDxvcHRpb24ocyk+IC1zIHNvdXJjZWZpbGUgLW8gZ2VuZXJhdGVmaWxlCgBbJXM6JWRdIHRyeSByZWJ1aWxkIHNoZHIgd2l0aCBwaGRyCgBbJXM6JWRdIE9wdGlvbnMgYXJlOgoAWyVzOiVkXSAgLWQgLS1kZWJ1ZyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFNob3cgZGVidWcgaW5mbwoAWyVzOiVkXSAgLW0gLS1tZW1zbyBtZW1CYXNlQWRkcigxNmJpdCBmb3JtYXQpICAgICAgIHRoZSBtZW1vcnkgYWRkcmVzcyB4IHdoaWNoIHRoZSBzb3VyY2Ugc28gaXMgZHVtcCBmcm9tCgBbJXM6JWRdICAtcyAtLXNvdXJjZSBzb3VyY2VGaWxlUGF0aCAgICAgICAgICAgICAgICAgU291cmNlIGZpbGUgcGF0aAoAWyVzOiVkXSAgLWIgLS1iYXNlc28gYmFzZUZpbGVQYXRoICAgICAgICAgICAgICAgICAgIE9yaWdpbmFsIHNvIGZpbGUgcGF0aC4odXNlZCB0byBnZXQgYmFzZSBpbmZvcm1hdGlvbikoZXhwZXJpbWVudGFsKQoAWyVzOiVkXSAgLW8gLS1vdXRwdXQgZ2VuZXJhdGVGaWxlUGF0aCAgICAgICAgICAgICAgIEdlbmVyYXRlIGZpbGUgcGF0aAoAWyVzOiVkXSAgLWggLS1oZWxwICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIERpc3BsYXkgdGhpcyBpbmZvcm1hdGlvbgoAaGVscABkZWJ1ZwBtZW1zbwBzb3VyY2UAYmFzZXNvAG91dHB1dABjYW5ub3QgYWxsb2NhdGUgX19jeGFfZWhfZ2xvYmFscwBzdGQ6Ol9fbGliY3BwX3Rsc19zZXQgZmFpbHVyZSBpbiBfX2N4YV9nZXRfZ2xvYmFscygpAGV4ZWN1dGUgb25jZSBmYWlsdXJlIGluIF9fY3hhX2dldF9nbG9iYWxzX2Zhc3QoKQBjYW5ub3QgY3JlYXRlIHRocmVhZCBzcGVjaWZpYyBrZXkgZm9yIF9fY3hhX2dldF9nbG9iYWxzKCkAY2Fubm90IHplcm8gb3V0IHRocmVhZCB2YWx1ZSBmb3IgX19jeGFfZ2V0X2dsb2JhbHMoKQB1bmV4cGVjdGVkX2hhbmRsZXIgdW5leHBlY3RlZGx5IHJldHVybmVkAHRlcm1pbmF0ZV9oYW5kbGVyIHVuZXhwZWN0ZWRseSByZXR1cm5lZAB0ZXJtaW5hdGVfaGFuZGxlciB1bmV4cGVjdGVkbHkgdGhyZXcgYW4gZXhjZXB0aW9uAHN0ZDo6ZXhjZXB0aW9uAHN0ZDo6YmFkX2V4Y2VwdGlvbgBzdGQ6OmJhZF9hbGxvYwBiYWRfYXJyYXlfbmV3X2xlbmd0aABzdGQ6OmJhZF9jYXN0AHN0ZDo6YmFkX3R5cGVpZAAvVm9sdW1lcy9BbmRyb2lkL2J1aWxkYm90L3NyYy9hbmRyb2lkL25kay1yZWxlYXNlLXIyMS9leHRlcm5hbC9saWJjeHgvLi4vLi4vZXh0ZXJuYWwvbGliY3h4YWJpL3NyYy9hYm9ydF9tZXNzYWdlLmNwcABhYm9ydF9tZXNzYWdlAHRlcm1pbmF0aW5nIHdpdGggJXMgZXhjZXB0aW9uIG9mIHR5cGUgJXM6ICVzAHRlcm1pbmF0aW5nIHdpdGggJXMgZXhjZXB0aW9uIG9mIHR5cGUgJXMAdGVybWluYXRpbmcgd2l0aCAlcyBmb3JlaWduIGV4Y2VwdGlvbgB0ZXJtaW5hdGluZwB1bmNhdWdodAB1bmV4cGVjdGVkAF9aAF9fWgBfX19aAF9fX19aAF9ibG9ja19pbnZva2UAaW52b2NhdGlvbiBmdW5jdGlvbiBmb3IgYmxvY2sgaW4gAFVhOWVuYWJsZV9pZkkAdnRhYmxlIGZvciAAVlRUIGZvciAAdHlwZWluZm8gZm9yIAB0eXBlaW5mbyBuYW1lIGZvciAAY292YXJpYW50IHJldHVybiB0aHVuayB0byAAdGhyZWFkLWxvY2FsIHdyYXBwZXIgcm91dGluZSBmb3IgAHRocmVhZC1sb2NhbCBpbml0aWFsaXphdGlvbiByb3V0aW5lIGZvciAAdmlydHVhbCB0aHVuayB0byAAbm9uLXZpcnR1YWwgdGh1bmsgdG8gAGd1YXJkIHZhcmlhYmxlIGZvciAAcmVmZXJlbmNlIHRlbXBvcmFyeSBmb3IgAGNvbnN0cnVjdGlvbiB2dGFibGUgZm9yIAAtaW4tAFN0AHN0ZAA6OgBhdXRvAGRlY2x0eXBlKAApAGdzACYmACYAJj0APQBhbGlnbm9mICgAY29uc3RfY2FzdAAsAH4AZHluYW1pY19jYXN0ACoALioALgAvAC89AF4AXj0APT0APj0APgA8PQA8PAA8PD0APAAtAC09ACo9AC0tACE9ACEAbm9leGNlcHQgKAB8fAB8AHw9AC0+KgArACs9ACsrAC0+AHJlaW50ZXJwcmV0X2Nhc3QAJQAlPQA+PgA+Pj0Ac3RhdGljX2Nhc3QAc2l6ZW9mICgAc2l6ZW9mLi4uICgAdHlwZWlkICgAdGhyb3cAdThfX3V1aWRvZnQAdThfX3V1aWRvZnoAd2NoYXJfdABiMEUAYjFFAGNoYXIAc2lnbmVkIGNoYXIAdW5zaWduZWQgY2hhcgBzaG9ydAB1bnNpZ25lZCBzaG9ydAAAdQBsAHVsAGxsAHVsbABfX2ludDEyOAB1bnNpZ25lZCBfX2ludDEyOAAoAHRydWUAZmFsc2UAJWFmACVhACVMYUwAZnAAZkwAYWEAYW4AYU4AYVMAY20AZHMAZHYAZFYAZW8AZU8AZXEAZ2UAZ3QAbGUAbHMAbFMAbHQAbWkAbUkAbWwAbUwAbmUAb28Ab3IAb1IAcGwAcEwAcm0Ack0AcnMAclMALi4uIAAgLi4uAC4uLgAsIAApIAAgKAA+KABjdgApKABkZWxldGUAW10gAHNyTgBzcgBfR0xPQkFMX19OAChhbm9ueW1vdXMgbmFtZXNwYWNlKQBkbgBvbgBvcGVyYXRvciYmAG9wZXJhdG9yJgBvcGVyYXRvciY9AG9wZXJhdG9yPQBvcGVyYXRvcigpAG9wZXJhdG9yLABvcGVyYXRvcn4Ab3BlcmF0b3IgZGVsZXRlW10Ab3BlcmF0b3IqAG9wZXJhdG9yIGRlbGV0ZQBvcGVyYXRvci8Ab3BlcmF0b3IvPQBvcGVyYXRvcl4Ab3BlcmF0b3JePQBvcGVyYXRvcj09AG9wZXJhdG9yPj0Ab3BlcmF0b3I+AG9wZXJhdG9yW10Ab3BlcmF0b3I8PQBvcGVyYXRvcjw8AG9wZXJhdG9yPDw9AG9wZXJhdG9yPABvcGVyYXRvci0Ab3BlcmF0b3ItPQBvcGVyYXRvcio9AG9wZXJhdG9yLS0Ab3BlcmF0b3IgbmV3W10Ab3BlcmF0b3IhPQBvcGVyYXRvciEAb3BlcmF0b3IgbmV3AG9wZXJhdG9yfHwAb3BlcmF0b3J8AG9wZXJhdG9yfD0Ab3BlcmF0b3ItPioAb3BlcmF0b3IrAG9wZXJhdG9yKz0Ab3BlcmF0b3IrKwBvcGVyYXRvci0+AG9wZXJhdG9yPwBvcGVyYXRvciUAb3BlcmF0b3IlPQBvcGVyYXRvcj4+AG9wZXJhdG9yPj49AG9wZXJhdG9yPD0+AG9wZXJhdG9yIABvcGVyYXRvciIiIAApWwBdACA9IAAgLi4uIABudwBuYQBwaQA6Om9wZXJhdG9yIABuZXcAW10AKSA/ICgAKSA6ICgAc2l6ZW9mLi4uKAB0aHJvdyAAX191dWlkb2YoAHN0ZDo6YWxsb2NhdG9yAHN0ZDo6YmFzaWNfc3RyaW5nAHN0ZDo6YmFzaWNfc3RyaW5nPGNoYXIsIHN0ZDo6Y2hhcl90cmFpdHM8Y2hhcj4sIHN0ZDo6YWxsb2NhdG9yPGNoYXI+ID4Ac3RkOjpiYXNpY19pc3RyZWFtPGNoYXIsIHN0ZDo6Y2hhcl90cmFpdHM8Y2hhcj4gPgBzdGQ6OmJhc2ljX29zdHJlYW08Y2hhciwgc3RkOjpjaGFyX3RyYWl0czxjaGFyPiA+AHN0ZDo6YmFzaWNfaW9zdHJlYW08Y2hhciwgc3RkOjpjaGFyX3RyYWl0czxjaGFyPiA+AGFsbG9jYXRvcgBiYXNpY19pc3RyZWFtAGJhc2ljX29zdHJlYW0AYmFzaWNfaW9zdHJlYW0AW2FiaToAREMAVXQAVWwAdkUAVWIAJ2Jsb2NrLWxpdGVyYWwnACd1bm5hbWVkACcAJ2xhbWJkYQAnKABzdHJpbmcgbGl0ZXJhbABzdGQ6OnN0cmluZwBzdGQ6OmlzdHJlYW0Ac3RkOjpvc3RyZWFtAHN0ZDo6aW9zdHJlYW0Ac3RyaW5nAGlzdHJlYW0Ab3N0cmVhbQBpb3N0cmVhbQAgAFN0TABzdGQ6OgAgW2VuYWJsZV9pZjoAIGNvbnN0ACB2b2xhdGlsZQAgcmVzdHJpY3QAICYAICYmAHZvaWQAYm9vbABpbnQAdW5zaWduZWQgaW50AGxvbmcAdW5zaWduZWQgbG9uZwBsb25nIGxvbmcAdW5zaWduZWQgbG9uZyBsb25nAGZsb2F0AGRvdWJsZQBsb25nIGRvdWJsZQBfX2Zsb2F0MTI4AGRlY2ltYWw2NABkZWNpbWFsMTI4AGRlY2ltYWwzMgBkZWNpbWFsMTYAY2hhcjMyX3QAY2hhcjE2X3QAY2hhcjhfdABkZWNsdHlwZShhdXRvKQBzdGQ6Om51bGxwdHJfdAAgY29tcGxleAAgaW1hZ2luYXJ5AERvAG5vZXhjZXB0AERPAER3AER4AFJFAE9FAG5vZXhjZXB0KAB0aHJvdygAb2JqY3Byb3RvAER2AHBpeGVsIHZlY3RvclsAIHZlY3RvclsAWwA6OioAVHMAc3RydWN0AFR1AHVuaW9uAFRlAGVudW0AaWQ8AG9iamNfb2JqZWN0AFB1cmUgdmlydHVhbCBmdW5jdGlvbiBjYWxsZWQhAERlbGV0ZWQgdmlydHVhbCBmdW5jdGlvbiBjYWxsZWQhAGxpYnVud2luZDogJXMgJXM6JWQgLSAlcwoAX1Vud2luZF9SZXN1bWUAL1ZvbHVtZXMvQW5kcm9pZC9idWlsZGJvdC9zcmMvYW5kcm9pZC9uZGstcmVsZWFzZS1yMjEvZXh0ZXJuYWwvbGliY3h4Ly4uLy4uL2V4dGVybmFsL2xpYnVud2luZF9sbHZtL3NyYy9VbndpbmQtRUhBQkkuY3BwAF9VbndpbmRfUmVzdW1lKCkgY2FuJ3QgcmV0dXJuAF9VbndpbmRfVlJTX1NldAB1bnN1cHBvcnRlZCByZWdpc3RlciBjbGFzcwBfVW53aW5kX1ZSU19Qb3AAdW53aW5kX3BoYXNlMgBkdXJpbmcgcGhhc2UxIHBlcnNvbmFsaXR5IGZ1bmN0aW9uIHNhaWQgaXQgd291bGQgc3RvcCBoZXJlLCBidXQgbm93IGluIHBoYXNlMiBpdCBkaWQgbm90IHN0b3AgaGVyZQBfVW53aW5kX1ZSU19HZXRfSW50ZXJuYWwAL1ZvbHVtZXMvQW5kcm9pZC9idWlsZGJvdC9zcmMvYW5kcm9pZC9uZGstcmVsZWFzZS1yMjEvZXh0ZXJuYWwvbGliY3h4Ly4uLy4uL2V4dGVybmFsL2xpYnVud2luZF9sbHZtL3NyYy9VbndpbmRDdXJzb3IuaHBwAGdldFJlZ2lzdGVyAC9Wb2x1bWVzL0FuZHJvaWQvYnVpbGRib3Qvc3JjL2FuZHJvaWQvbmRrLXJlbGVhc2UtcjIxL2V4dGVybmFsL2xpYmN4eC8uLi8uLi9leHRlcm5hbC9saWJ1bndpbmRfbGx2bS9zcmMvUmVnaXN0ZXJzLmhwcAB1bnN1cHBvcnRlZCBhcm0gcmVnaXN0ZXIAc2V0UmVnaXN0ZXIAZ2V0RmxvYXRSZWdpc3RlcgBVbmtub3duIEFSTSBmbG9hdCByZWdpc3RlcgBzZXRGbG9hdFJlZ2lzdGVyACVzAGdldEluZm9Gcm9tRUhBQklTZWN0aW9uAHVua25vd24gcGVyc29uYWxpdHkgcm91dGluZQBpbmRleCBpbmxpbmVkIHRhYmxlIGRldGVjdGVkIGJ1dCBwciBmdW5jdGlvbiByZXF1aXJlcyBleHRyYSB3b3JkcwBwYwBscgBzcAByMAByMQByMgByMwByNAByNQByNgByNwByOAByOQByMTAAcjExAHIxMgBzMABzMQBzMgBzMwBzNABzNQBzNgBzNwBzOABzOQBzMTAAczExAHMxMgBzMTMAczE0AHMxNQBzMTYAczE3AHMxOABzMTkAczIwAHMyMQBzMjIAczIzAHMyNABzMjUAczI2AHMyNwBzMjgAczI5AHMzMABzMzEAZDAAZDEAZDIAZDMAZDQAZDUAZDYAZDcAZDgAZDkAZDEwAGQxMQBkMTIAZDEzAGQxNABkMTUAZDE2AGQxNwBkMTgAZDE5AGQyMABkMjEAZDIyAGQyMwBkMjQAZDI1AGQyNgBkMjcAZDI4AGQyOQBkMzAAZDMxAHVua25vd24gcmVnaXN0ZXIAOUVsZlJlYWRlcgAxMU9iRWxmUmVhZGVyAABOMTBfX2N4eGFiaXYxMTZfX3NoaW1fdHlwZV9pbmZvRQBOMTBfX2N4eGFiaXYxMTdfX2NsYXNzX3R5cGVfaW5mb0UATjEwX19jeHhhYml2MTE3X19wYmFzZV90eXBlX2luZm9FAE4xMF9fY3h4YWJpdjExOV9fcG9pbnRlcl90eXBlX2luZm9FAE4xMF9fY3h4YWJpdjEyMF9fZnVuY3Rpb25fdHlwZV9pbmZvRQBOMTBfX2N4eGFiaXYxMjlfX3BvaW50ZXJfdG9fbWVtYmVyX3R5cGVfaW5mb0UAAAAAAAAAAAD/////TjEwX19jeHhhYml2MTIzX19mdW5kYW1lbnRhbF90eXBlX2luZm9FAHYAUHYAUEt2AERuAFBEbgBQS0RuAGIAUGIAUEtiAHcAUHcAUEt3AGMAUGMAUEtjAGgAUGgAUEtoAGEAUGEAUEthAHMAUHMAUEtzAHQAUHQAUEt0AGkAUGkAUEtpAGoAUGoAUEtqAGwAUGwAUEtsAG0AUG0AUEttAHgAUHgAUEt4AHkAUHkAUEt5AG4AUG4AUEtuAG8AUG8AUEtvAERoAFBEaABQS0RoAGYAUGYAUEtmAGQAUGQAUEtkAGUAUGUAUEtlAGcAUGcAUEtnAER1AFBEdQBQS0R1AERzAFBEcwBQS0RzAERpAFBEaQBQS0RpAE4xMF9fY3h4YWJpdjExN19fYXJyYXlfdHlwZV9pbmZvRQBOMTBfX2N4eGFiaXYxMTZfX2VudW1fdHlwZV9pbmZvRQBOMTBfX2N4eGFiaXYxMjBfX3NpX2NsYXNzX3R5cGVfaW5mb0UATjEwX19jeHhhYml2MTIxX192bWlfY2xhc3NfdHlwZV9pbmZvRQBTdDlleGNlcHRpb24AU3QxM2JhZF9leGNlcHRpb24AU3Q5YmFkX2FsbG9jAFN0MjBiYWRfYXJyYXlfbmV3X2xlbmd0aABTdDEyZG9tYWluX2Vycm9yAFN0MTFsb2dpY19lcnJvcgBTdDE2aW52YWxpZF9hcmd1bWVudABTdDEybGVuZ3RoX2Vycm9yAFN0MTJvdXRfb2ZfcmFuZ2UAU3QxMXJhbmdlX2Vycm9yAFN0MTNydW50aW1lX2Vycm9yAFN0MTRvdmVyZmxvd19lcnJvcgBTdDE1dW5kZXJmbG93X2Vycm9yAFN0OXR5cGVfaW5mbwBTdDhiYWRfY2FzdABTdDEwYmFkX3R5cGVpZABOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxMVNwZWNpYWxOYW1lRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGU0Tm9kZUUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMjFDdG9yVnRhYmxlU3BlY2lhbE5hbWVFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZThOYW1lVHlwZUUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTBOZXN0ZWROYW1lRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUyNEZvcndhcmRUZW1wbGF0ZVJlZmVyZW5jZUUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTRJbnRlZ2VyTGl0ZXJhbEUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlOEJvb2xFeHByRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxNkZsb2F0TGl0ZXJhbEltcGxJZkVFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTE2RmxvYXRMaXRlcmFsSW1wbElkRUUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTZGbG9hdExpdGVyYWxJbXBsSWVFRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxNUludGVnZXJDYXN0RXhwckUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTNGdW5jdGlvblBhcmFtRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGU4Rm9sZEV4cHJFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTIyUGFyYW1ldGVyUGFja0V4cGFuc2lvbkUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTBCaW5hcnlFeHByRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxMFByZWZpeEV4cHJFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZThDYXN0RXhwckUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlOENhbGxFeHByRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxNENvbnZlcnNpb25FeHByRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxMERlbGV0ZUV4cHJFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTEzUXVhbGlmaWVkTmFtZUUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlOER0b3JOYW1lRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUyMkNvbnZlcnNpb25PcGVyYXRvclR5cGVFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTE1TGl0ZXJhbE9wZXJhdG9yRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxOUdsb2JhbFF1YWxpZmllZE5hbWVFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTEwTWVtYmVyRXhwckUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMThBcnJheVN1YnNjcmlwdEV4cHJFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTEwQnJhY2VkRXhwckUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTVCcmFjZWRSYW5nZUV4cHJFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTEySW5pdExpc3RFeHByRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxMVBvc3RmaXhFeHByRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGU3TmV3RXhwckUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTNFbmNsb3NpbmdFeHByRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxNUNvbmRpdGlvbmFsRXhwckUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTlTaXplb2ZQYXJhbVBhY2tFeHByRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxM05vZGVBcnJheU5vZGVFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTlUaHJvd0V4cHJFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTEwVVVJRE9mRXhwckUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMjdFeHBhbmRlZFNwZWNpYWxTdWJzdGl0dXRpb25FAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTEyQ3RvckR0b3JOYW1lRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxMEFiaVRhZ0F0dHJFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTE1VW5uYW1lZFR5cGVOYW1lRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxNUNsb3N1cmVUeXBlTmFtZUUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMjFTdHJ1Y3R1cmVkQmluZGluZ05hbWVFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTlMb2NhbE5hbWVFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTE5U3BlY2lhbFN1YnN0aXR1dGlvbkUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTNQYXJhbWV0ZXJQYWNrRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxMlRlbXBsYXRlQXJnc0UATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMjBOYW1lV2l0aFRlbXBsYXRlQXJnc0UATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTZTdGRRdWFsaWZpZWROYW1lRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUyMFRlbXBsYXRlQXJndW1lbnRQYWNrRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxMkVuYWJsZUlmQXR0ckUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTZGdW5jdGlvbkVuY29kaW5nRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGU5RG90U3VmZml4RQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxMk5vZXhjZXB0U3BlY0UATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMjBEeW5hbWljRXhjZXB0aW9uU3BlY0UATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTJGdW5jdGlvblR5cGVFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTEzT2JqQ1Byb3RvTmFtZUUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTdWZW5kb3JFeHRRdWFsVHlwZUUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlOFF1YWxUeXBlRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxNVBpeGVsVmVjdG9yVHlwZUUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTBWZWN0b3JUeXBlRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGU5QXJyYXlUeXBlRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUxOVBvaW50ZXJUb01lbWJlclR5cGVFAE4xMl9HTE9CQUxfX05fMTE2aXRhbml1bV9kZW1hbmdsZTIyRWxhYm9yYXRlZFR5cGVTcGVmVHlwZUUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTFQb2ludGVyVHlwZUUATjEyX0dMT0JBTF9fTl8xMTZpdGFuaXVtX2RlbWFuZ2xlMTNSZWZlcmVuY2VUeXBlRQBOMTJfR0xPQkFMX19OXzExNml0YW5pdW1fZGVtYW5nbGUyMFBvc3RmaXhRdWFsaWZpZWRUeXBlRQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANwyAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAHj4AQAAAAAAAAAAAGgAAAB9+AEAAAAAAAAAAABkAAAAg/gBAAEAAAAAAAAAbQAAAIn4AQABAAAAAAAAAHMAAACQ+AEAAQAAAAAAAABiAAAAl/gBAAEAAAAAAAAAbwAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAOUuAQDpLgEA6y4BAO0uAQAAAAAAAAAAAAAAAADlLgEA7y4BAOsuAQDtLgEAjy8BAAgAAAAAAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAQAAAAAAAAAIAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAEAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAABAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAQAAAAAAAAAIAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAEAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAABAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAQAAAAAAAAAIAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAEAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAABAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAQAAAAAAAAAIAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAEAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAABAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAQAAAAAAAAAIAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAEAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAABAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAQAAAAAAAAAIAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAEAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAABAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAQAAAAAAAAAIAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAEAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAABAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAQAAAAAAAAAIAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAEAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAABAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAA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tKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAAtKQAALSkAAC0pAAA6vMBAC0+AQAJPwEAhvsBADhSAgAAQW5kcm9pZCAoNzAxOTk4MyBiYXNlZCBvbiByMzY1NjMxYzMpIGNsYW5nIHZlcnNpb24gOS4wLjkgKGh0dHBzOi8vYW5kcm9pZC5nb29nbGVzb3VyY2UuY29tL3Rvb2xjaGFpbi9sbHZtLXByb2plY3QgYTJhMWU3MDNjMGVkYjAzYmEyOTk0NGU1MjljY2JmNDU3NzQyNzM3YikgKGJhc2VkIG9uIExMVk0gOS4wLjlzdm4pAAAABAAAAAkAAAAEAAAAR05VAGdvbGQgMS4xMgAAAEEtAAAAYWVhYmkAASMAAAAGCgdBCAEJAgoDDAERAhIEFAEVARcDGAEaAiIBJgEALmZpbmlfYXJyYXkALkFSTS5leGlkeAAudGV4dAAuZ290AC5jb21tZW50AC5ub3RlLmFuZHJvaWQuaWRlbnQALnJlbC5wbHQALmJzcwAuQVJNLmF0dHJpYnV0ZXMALmR5bnN0cgAuZ251LnZlcnNpb25fcgAuZGF0YS5yZWwucm8ALnJlbC5keW4ALmdudS52ZXJzaW9uAC5ub3RlLmdudS5nb2xkLXZlcnNpb24ALmR5bnN5bQAuZ251Lmhhc2gALm5vdGUuZ251LmJ1aWxkLWlkAC5nbnUudmVyc2lvbl9kAC5keW5hbWljAC5BUk0uZXh0YWIALnNoc3RydGFiAC5yb2RhdGEALmRhdGEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAAAAHAAAAAgAAADQBAAA0AQAAmAAAAAAAAAAAAAAABAAAAAAAAADBAAAABwAAAAIAAADMAQAAzAEAACQAAAAAAAAAAAAAAAQAAAAAAAAArwAAAAsAAAACAAAA8AEAAPABAAAwIwAABAAAAAEAAAAEAAAAEAAAAF4AAAADAAAAAgAAACAlAAAgJQAA0jkAAAAAAAAAAAAAAQAAAAAAAAC3AAAA9v//bwIAAAD0XgAA9F4AAPwNAAADAAAAAAAAAAQAAAAEAAAAiwAAAP///28CAAAA8GwAAPBsAABmBAAAAwAAAAAAAAACAAAAAgAAANQAAAD9//9vAgAAAFhxAABYcQAAHAAAAAQAAAABAAAABAAAAAAAAABmAAAA/v//bwIAAAB0cQAAdHEAAFAAAAAEAAAAAgAAAAQAAAAAAAAAggAAAAkAAAACAAAAxHEAAMRxAAC4KwAAAwAAAAAAAAAEAAAACAAAAEAAAAAJAAAAAgAAAHydAAB8nQAAOAcAAAMAAAAAAAAABAAAAAgAAABEAAAAAQAAAAYAAAC0pAAAtKQAAOgKAAAAAAAAAAAAAAQAAAAAAAAAGAAAAAEAAAAGAAAAnK8AAJyvAAAgFAEAAAAAAAAAAAAEAAAAAAAAAA0AAAABAABwggAAALzDAQC8wwEAcBMAAAwAAAAAAAAABAAAAAgAAADsAAAAAQAAAAIAAAAs1wEALNcBAJgSAAAAAAAAAAAAAAQAAAAAAAAAAQEAAAEAAAACAAAAxOkBAMTpAQB1MQAAAAAAAAAAAAAEAAAAAAAAAHUAAAABAAAAAwAAANwyAgDcIgIA0BcAAAAAAAAAAAAABAAAAAAAAAABAAAADwAAAAMAAACsSgIArDoCAAgAAAAAAAAAAAAAAAQAAAAAAAAA4wAAAAYAAAADAAAAtEoCALQ6AgAIAQAABAAAAAAAAAAEAAAACAAAAB4AAAABAAAAAwAAALxLAgC8OwIARAQAAAAAAAAAAAAABAAAAAAAAAAJAQAAAQAAAAMAAAAAUAIAAEACABQAAAAAAAAAAAAAAAQAAAAAAAAAIwAAAAEAAAAwAAAAAAAAABRAAgC2AAAAAAAAAAAAAAABAAAAAQAAAEkAAAAIAAAAAwAAACBQAgAgQAIAGQIAAAAAAAAAAAAAEAAAAAAAAACYAAAABwAAAAAAAAAAAAAAzEACABwAAAAAAAAAAAAAAAQAAAAAAAAATgAAAAMAAHAAAAAAAAAAAOhAAgAuAAAAAAAAAAAAAAABAAAAAAAAAPcAAAADAAAAAAAAAAAAAAAWQQIADwEAAAAAAAAAAAAAAQAAAAAAAAA=';
const logger = (0,_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.subLogger)('sodump');
const mutex_size = Process.pointerSize === 4 ? 24 : 40;
const mutex_addr = Memory.alloc(mutex_size);
mutex_addr.writeByteArray(new Array(mutex_size).fill(0));
let handle = NULL;
const hash_dumped_libs = new Map();
_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.pthread_mutex_init(mutex_addr, NULL);
function drop_so_fixer(rawtext, file_name) {
    const process_name = (0,_clockwork_native_dist_utils_js__WEBPACK_IMPORTED_MODULE_3__.getSelfProcessName)();
    const files_dir = `/data/data/${process_name}`;
    const full_path = `${files_dir}/${file_name}`;
    //@ts-ignore
    File.writeAllBytes(full_path, frida_buffer__WEBPACK_IMPORTED_MODULE_4__.Buffer.from(rawtext, 'base64'));
    return full_path;
}
function dlopen_lib(so_name, libso, sofixer) {
    if (handle.isNull()) {
        const systemPtr = Module.getExportByName('libc.so', 'system');
        const system = new NativeFunction(systemPtr, 'int', ['pointer']);
        let cmd = Memory.allocUtf8String(`chmod 777 ${sofixer} 2>&1`);
        system(cmd);
        cmd = Memory.allocUtf8String(`base64 -d ${sofixer} > ${sofixer}_.so  2>&1`);
        system(cmd);
        cmd = Memory.allocUtf8String('chmod 755 _${sofixer} 2>&1');
        system(cmd);
        const dlopenPtr = Module.getExportByName('libc.so', 'dlopen');
        const dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);
        const hdl = dlopen(Memory.allocUtf8String(`${sofixer}_.so`), 2);
        logger.info(`HDL -> ${hdl}`);
        return hdl;
    }
    return handle;
}
function dump_lib(so_name) {
    const libso = Process.findModuleByName(so_name);
    if (libso == null) {
        logger.error({ tag: 'dumplib' }, `Module ${so_name} not found`);
        return -1;
    }
    const generateRandomHex = (length) => [...Array(length)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
    const process_name = (0,_clockwork_native_dist_utils_js__WEBPACK_IMPORTED_MODULE_3__.getSelfProcessName)();
    const files_dir = `/data/data/${process_name}/`;
    const initial_path = `${so_name}_dump.so`;
    const final_path = `${so_name}_${libso.base}_${libso.size}.so`;
    const finalOut = `${files_dir}${final_path}`;
    Memory.protect(libso.base, libso.size, 'rwx');
    //libso_buffer is never used, we probably will need to remove it
    // let libso_buffer = libso.base.readByteArray(libso.size);
    let sofixer = '';
    if (Process.arch === 'arm') {
        sofixer = drop_so_fixer(soFixer32, `${generateRandomHex(16)}libdumpfixerArm32.so`);
    }
    else if (Process.arch === 'arm64') {
        sofixer = drop_so_fixer(soFixer64, 'libdumpfixerArm64.so');
    }
    else {
        logger.error(`Not supported arch${Process.arch}`);
        return;
    }
    logger.info({ tag: 'fixer' }, sofixer);
    const dumpedFile = dump_so_file(libso.base, libso.size, initial_path);
    logger.info({ tag: 'dumped' }, dumpedFile);
    const SoFixer = Memory.allocUtf8String(sofixer);
    _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.chmod(SoFixer, 0o777);
    const cmd = `su 0 ${sofixer} -s ${dumpedFile} -m ${libso.base} -o ${finalOut}`;
    logger.info({ tag: 'cmd' }, cmd);
    const Cmd = Memory.allocUtf8String(cmd);
    const result = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.system(Cmd);
    logger.info({ tag: 'system' }, `${result} ${finalOut}`);
    const fd = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.popen(Cmd, Memory.allocUtf8String('r'));
    if (!(0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(fd)) {
        const buffer = Memory.alloc(1024);
        while (!(0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fgets(buffer, 1024, fd))) {
            logger.info({ tag: 'output' }, `${buffer.readCString()}`);
        }
        const result = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.pclose(fd);
        logger.info({ tag: 'execv' }, `${result} ${finalOut}`);
    }
    else {
        logger.info({ tag: 'execv' }, `${fd} ${finalOut}`);
    }
}
function dump_so_file(decompressed_ptr, file_size, file_path) {
    const process_name = (0,_clockwork_native_dist_utils_js__WEBPACK_IMPORTED_MODULE_3__.getSelfProcessName)();
    const files_dir = `/data/data/${process_name}`;
    const out_path = `${files_dir}/${file_path}`;
    Memory.protect(decompressed_ptr, file_size, 'rwx');
    const buffer = decompressed_ptr.readByteArray(file_size);
    //@ts-ignore
    File.writeAllBytes(out_path, buffer);
    return out_path;
}
function dump_from_maps() {
    const modules = Process.enumerateModules();
    for (const { path, name } of modules) {
        if (!path.endsWith('/base.odex') && !path.endsWith('/libdumpfixerArm64.so')) {
            const libname = module.path.split('/').pop();
            if (libname && !hash_dumped_libs.has(libname)) {
                dump_lib(libname);
                hash_dumped_libs[libname] = true;
            }
        }
    }
}
function initSoDump() {
    _clockwork_native__WEBPACK_IMPORTED_MODULE_2__.Inject.afterInitArrayModule(({ path, name }) => {
        if (!path.endsWith('/base.odex') && !path.endsWith('/libdumpfixerArm64.so')) {
            logger.info(`path: ${path}, name: ${name}`);
            if (_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.pthread_mutex_lock(mutex_addr) === 0x0) {
                try {
                    if (!hash_dumped_libs.has(name)) {
                        dump_lib(name);
                        hash_dumped_libs[name] = true;
                    }
                }
                catch (error) {
                    logger.error(error);
                }
                finally {
                    _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.pthread_mutex_unlock(mutex_addr);
                }
            }
        }
        else if (name.includes('libc.so')) {
            if (_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.pthread_mutex_lock(mutex_addr) === 0x0) {
                try {
                    dump_from_maps();
                }
                catch (error) {
                    logger.error(error);
                }
                finally {
                    _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.pthread_mutex_unlock(mutex_addr);
                }
            }
        }
    });
}
function dumpLibSync(name) {
    // if (Libc.pthread_mutex_lock(mutex_addr) == 0x0) {
    try {
        dump_lib(name);
    }
    catch (err) {
        logger.error(err);
    }
    finally {
        // Libc.pthread_mutex_unlock(mutex_addr);
    }
    // }
}

//# sourceMappingURL=soDump.js.map

/***/ }),

/***/ "./packages/hooks/dist/addons.js":
/*!***************************************!*\
  !*** ./packages/hooks/dist/addons.js ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   always: () => (/* binding */ always),
/* harmony export */   compat: () => (/* binding */ compat),
/* harmony export */   ifKey: () => (/* binding */ ifKey),
/* harmony export */   ifReturn: () => (/* binding */ ifReturn)
/* harmony export */ });
const always = (value) => () => value;
const compat = (fn) => {
    return function (method, ...args) {
        const addon = {
            get originalMethod() {
                return method;
            },
            get originalArgs() {
                return args;
            },
            fallback() {
                return this.originalMethod.call(this, ...this.originalArgs);
            },
        };
        return fn.call(Object.assign(this, addon));
    };
};
const ifReturn = (fn) => {
    return function (method, ...args) {
        const result = fn.call(this, method, ...args);
        if (result !== undefined)
            return result;
        return method.call(this, ...args);
    };
};
const ifKey = (fn, index) => {
    return ifReturn(function (method, ...args) {
        const key = args[index ?? 0];
        return fn(key);
    });
};

//# sourceMappingURL=addons.js.map

/***/ }),

/***/ "./packages/hooks/dist/classloader.js":
/*!********************************************!*\
  !*** ./packages/hooks/dist/classloader.js ***!
  \********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ClassLoader: () => (/* binding */ ClassLoader)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _hook_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./hook.js */ "./packages/hooks/dist/hook.js");


var ClassLoader;
(function (ClassLoader) {
    const listeners = [];
    function perform(fn) {
        listeners.push(fn);
    }
    ClassLoader.perform = perform;
    function notify(classLoader) {
        for (const listener of listeners)
            listener(classLoader);
    }
    function onNewClassLoader() {
        notify(this);
    }
    function invoke() {
        (0,_hook_js__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.ClassLoader, '$init', {
            after: onNewClassLoader,
            logging: { arguments: false, call: false },
        });
        (0,_hook_js__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.BaseDexClassLoader, '$init', {
            after: onNewClassLoader,
            logging: { arguments: false },
        });
        (0,_hook_js__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.DexClassLoader, '$init', {
            after: onNewClassLoader,
            logging: { arguments: false },
        });
        (0,_hook_js__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.InMemoryDexClassLoader, '$init', {
            after: onNewClassLoader,
            logging: { arguments: false },
        });
        (0,_hook_js__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.PathClassLoader, '$init', {
            after: onNewClassLoader,
            logging: { arguments: false },
        });
        (0,_hook_js__WEBPACK_IMPORTED_MODULE_1__.hook)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Application, 'onCreate', {
            before() {
                const loader = this.getClassLoader() ?? null;
                onNewClassLoader.call(loader);
            },
        });
        notify(null);
    }
    setImmediate(() => Java.performNow(invoke));
})(ClassLoader || (ClassLoader = {}));

//# sourceMappingURL=classloader.js.map

/***/ }),

/***/ "./packages/hooks/dist/filter.js":
/*!***************************************!*\
  !*** ./packages/hooks/dist/filter.js ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Filter: () => (/* binding */ Filter),
/* harmony export */   FilterJni: () => (/* binding */ FilterJni)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");

const prefsMeasurementInternalIgnored = [
    'consent_settings',
    'consent_source',
    'last_upload_attempt',
    'backoff',
    'midnight_offset',
    'last_upload',
    'last_delete_stale',
    'health_monitor:start',
    'health_monitor:count',
    'app_backgrounded',
    'start_new_session',
    'deferred_analytics_collection',
    'measurement_enabled',
    'default_event_parameters',
    'session_timeout',
    'previous_os_version',
    'use_service',
    'deferred_attribution_cache_timestamp',
    'first_open_time',
];
const applovinPrivacyIgnored = [
    'com.applovin.sdk.compliance.has_user_consent',
    'com.applovin.sdk.compliance.is_age_restricted_user',
    'com.applovin.sdk.compliance.is_do_not_sell',
];
const settingsKeysIgnored = [
    'render_shadows_in_compositor',
    'force_resizable_activities',
    'use_blast_adapter_sv',
    'show_angle_in_use_dialog_box',
    'accessibility_captioning_enabled',
];
const Filter = {
    json: (_, ...args) => {
        let trace = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.stacktrace)();
        trace = trace.substring(trace.indexOf('\n'));
        if (trace.includes('at org.json.JSONObject.<init>'))
            return false;
        if (trace.includes('at org.json.JSONObject.get'))
            return false;
        if (trace.includes('at org.json.JSONObject.opt'))
            return false;
        if (trace.includes('at com.facebook.internal.'))
            return false;
        if (trace.includes('at com.google.android.gms.internal.ads.'))
            return false;
        if (trace.includes('at com.google.android.gms.ads.internal.config.'))
            return false;
        if (trace.includes('at com.google.firebase.installations.local.PersistedInstallation'))
            return false;
        if (trace.includes('at com.unity3d.services.core.configuration.PrivacyConfigurationLoader'))
            return false;
        return true;
    },
    prefs: (method, ...args) => {
        const trace = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.stacktrace)();
        if (trace.includes('at com.yandex.mobile.ads.core.initializer.MobileAdsInitializeProvider.'))
            return false;
        if (trace.includes('at com.facebook.FacebookSdk.getLimitEventAndDataUsage'))
            return false;
        if (trace.includes('at com.facebook.internal.'))
            return false;
        if (trace.includes('at com.appsflyer.internal.'))
            return false;
        if (trace.includes('at com.onesignal.OneSignalPrefs.'))
            return false;
        if (trace.includes('at com.google.android.gms.'))
            return false;
        // if (trace.includes('at com.google.android.gms.ads.internal.config.')) return false;
        // if (trace.includes('at com.google.android.gms.internal.appset')) return false;
        // if (trace.includes('at com.google.android.gms.measurement.internal.')) {
        //     if (args[0] && prefsMeasurementInternalIgnored.includes(args[0])) {
        //         return false;
        //     }
        // }
        if (trace.includes('at com.google.firebase.heartbeatinfo.DefaultHeartBeatController.')) {
            if (args[0] && ['last-used-date'].includes(args[0])) {
                return false;
            }
        }
        if (trace.includes('at com.applovin.impl.privacy.a')) {
            if (args[0] && applovinPrivacyIgnored.includes(args[0])) {
                return false;
            }
        }
        if (trace.includes('at com.applovin.sdk.AppLovinSdk.getInstance') &&
            trace.includes('at com.applovin.impl.sdk.')) {
            if (args[0]?.startsWith('com.applovin.sdk.')) {
                if (method.methodName === 'contains') {
                    return false;
                }
            }
        }
        if (method.methodName === 'getInt' && args[0] === 'music') {
            return false;
        }
        return true;
    },
    url: () => {
        const trace = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.stacktrace)();
        if (trace.includes('at com.facebook.internal.'))
            return false;
        if (trace.includes('at com.appsflyer.internal.'))
            return false;
        if (trace.includes('at com.onesignal.OneSignalPrefs.'))
            return false;
        if (trace.includes('at com.google.android.gms.internal.ads.'))
            return false;
        if (trace.includes('at com.adjust.sdk.SdkClickHandler.sendSdkClick'))
            return false;
        if (trace.includes('at com.appsgeyser.sdk.ads.AdsLoader'))
            return false;
        // console.log(trace);
        return true;
    },
    date: () => {
        let trace = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.stacktrace)();
        trace = trace.substring(trace.indexOf('\n'));
        if (trace.includes('at com.facebook.FacebookSdk.getGraphApiVersion('))
            return false;
        if (trace.includes('at com.safedk.android.utils.SdksMapping.printAllSdkVersions'))
            return false;
        if (trace.includes('at com.applovin.sdk.AppLovinInitProvider.onCreate'))
            return false;
        if (trace.includes('at com.google.firebase.provider.FirebaseInitProvider.onCreate'))
            return false;
        if (trace.includes('at com.google.firebase.crashlytics.CrashlyticsRegistrar'))
            return false;
        if (trace.includes('at com.facebook.appevents.internal.') &&
            trace.includes('at android.icu.util.Currency.getAvailableCurrencyCodes'))
            return false;
        // console.log(trace)
        return true;
    },
    settings: (_, ...args) => {
        const key = `${args[1]}`;
        return !settingsKeysIgnored.includes(key);
    },
    systemproperties: (_, ...args) => {
        const key = `${args[0]}`;
        switch (key) {
            case 'persist.sys.fflag.override.settings_auto_text_wrapping':
            case 'debug.force_rtl':
                return false;
        }
        return true;
    },
    systemprop: (_, ...args) => {
        const key = `${args[0]}`;
        switch (key) {
            case 'line.separator':
            case 'jsse.enableSNIExtension':
            case 'http.proxyHost':
            case 'proxyHost':
            case 'socksProxyHost':
            case 'http.keepAlive':
            case 'http.maxConnections':
            case 'http.keepAliveDuration':
            case 'javax.net.ssl.keyStore':
            case 'com.android.org.conscrypt.useEngineSocketByDefault':
            case 'java.library.path':
            case 'java.version':
            case 'java.vm.name':
            case 'file.separator':
            case 'guava.concurrent.generate_cancellation_cause':
                return false;
        }
        return true;
    },
};
const FilterJni = {
    getFieldId: (className, typeName, name) => {
        if (className === 'io.flutter.embedding.engine.FlutterJNI' && name === 'refreshRateFPS')
            return false;
        return true;
    },
};

//# sourceMappingURL=filter.js.map

/***/ }),

/***/ "./packages/hooks/dist/hook.js":
/*!*************************************!*\
  !*** ./packages/hooks/dist/hook.js ***!
  \*************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   findHook: () => (/* binding */ findHook),
/* harmony export */   getHookUnique: () => (/* binding */ getHookUnique),
/* harmony export */   hook: () => (/* binding */ hook)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _ids_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./ids.js */ "./packages/hooks/dist/ids.js");
/* harmony import */ var _logger_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./logger.js */ "./packages/hooks/dist/logger.js");




function hook(clazzOrName, methodName, params = {}) {
    const { before, replace, after, logging, loggingPredicate } = params;
    const logger = (0,_logger_js__WEBPACK_IMPORTED_MODULE_3__.getLogger)(logging);
    const clazz = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isJWrapper)(clazzOrName) ? clazzOrName : Java.use(clazzOrName);
    const method = clazz[methodName];
    if (`${typeof method}` !== 'function') {
        throw Error(`hook: method ${methodName} not found in ${clazz} !`);
    }
    const overloads = method.overloads;
    const classString = clazz.$className;
    const cId = _ids_js__WEBPACK_IMPORTED_MODULE_2__.Ids.genClassId(classString);
    const mId = _ids_js__WEBPACK_IMPORTED_MODULE_2__.Ids.genMethodId(classString, methodName);
    logger.printHookClass(classString, _ids_js__WEBPACK_IMPORTED_MODULE_2__.Ids.classId(cId));
    for (let i = 0; i < overloads.length; i++) {
        const overload = overloads[i];
        if (params?.predicate?.(overload, i) === false)
            continue;
        const logId = _ids_js__WEBPACK_IMPORTED_MODULE_2__.Ids.uniqueId(cId, mId, i);
        const { argumentTypes, returnType } = overload;
        const argTypesString = argumentTypes.map((t) => t.className ?? t.name);
        const returnTypeString = returnType.className ?? returnType.name;
        const methodDef = method.overload(...argTypesString);
        logger.printHookMethod(methodName, argTypesString, returnTypeString, logId);
        methodDef.implementation = function (...params) {
            const doLog = loggingPredicate?.call(this, methodDef, ...params) ?? true;
            doLog &&
                logger.printCall(classString, methodName, params, argTypesString, returnTypeString, logId, replace !== undefined);
            before?.call(this, methodDef, ...params);
            const retval = replace?.call(this, methodDef, ...params) ?? methodDef.call(this, ...params);
            after?.call(this, methodDef, retval, ...params);
            if (returnTypeString !== 'void')
                doLog && logger.printReturn(retval, returnTypeString, logId);
            return retval;
        };
    }
}
function findHook(clazzName, methodName, params) {
    const clazz = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.findClass)(clazzName);
    if (!clazz) {
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.debug({ tag: 'findHook' }, `class ${clazzName} not found !`);
        return;
    }
    hook(clazz, methodName, params);
}
function getHookUnique(logging = true) {
    const found = new Set();
    return (clazzName, methodName, params = {}) => {
        const clazz = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.findClass)(clazzName);
        if (!clazz) {
            logging && _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'hookUnique' }, `class ${clazzName} not found !`);
            return;
        }
        const ptr = `${clazz.$l.handle}::${methodName}`;
        if (!found.has(ptr)) {
            found.add(ptr);
            hook(clazz, methodName, params);
        }
    };
}

//# sourceMappingURL=hook.js.map

/***/ }),

/***/ "./packages/hooks/dist/ids.js":
/*!************************************!*\
  !*** ./packages/hooks/dist/ids.js ***!
  \************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Ids: () => (/* binding */ Ids)
/* harmony export */ });
var Ids;
(function (Ids) {
    let currentCId = -1;
    const classIds = {};
    let currentMId = -1;
    const methodIds = {};
    function genClassId(className) {
        const key = `${className}`;
        return typeof classIds[key] === 'number' ? classIds[key] : (classIds[key] = currentCId += 1);
    }
    Ids.genClassId = genClassId;
    function genMethodId(className, method) {
        const key = `${className}::${method}`;
        return typeof methodIds[key] === 'number' ? methodIds[key] : (methodIds[key] = currentMId += 1);
    }
    Ids.genMethodId = genMethodId;
    function classId(cId) {
        return `#id:${cId}`;
    }
    Ids.classId = classId;
    function uniqueId(cId, mId, i) {
        return `${classId(cId)}:${mId}:${i}`;
    }
    Ids.uniqueId = uniqueId;
})(Ids || (Ids = {}));

//# sourceMappingURL=ids.js.map

/***/ }),

/***/ "./packages/hooks/dist/index.js":
/*!**************************************!*\
  !*** ./packages/hooks/dist/index.js ***!
  \**************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   ClassLoader: () => (/* reexport safe */ _classloader_js__WEBPACK_IMPORTED_MODULE_0__.ClassLoader),
/* harmony export */   Filter: () => (/* reexport safe */ _filter_js__WEBPACK_IMPORTED_MODULE_3__.Filter),
/* harmony export */   FilterJni: () => (/* reexport safe */ _filter_js__WEBPACK_IMPORTED_MODULE_3__.FilterJni),
/* harmony export */   always: () => (/* reexport safe */ _addons_js__WEBPACK_IMPORTED_MODULE_2__.always),
/* harmony export */   compat: () => (/* reexport safe */ _addons_js__WEBPACK_IMPORTED_MODULE_2__.compat),
/* harmony export */   findHook: () => (/* reexport safe */ _hook_js__WEBPACK_IMPORTED_MODULE_1__.findHook),
/* harmony export */   getHookUnique: () => (/* reexport safe */ _hook_js__WEBPACK_IMPORTED_MODULE_1__.getHookUnique),
/* harmony export */   hook: () => (/* reexport safe */ _hook_js__WEBPACK_IMPORTED_MODULE_1__.hook),
/* harmony export */   ifKey: () => (/* reexport safe */ _addons_js__WEBPACK_IMPORTED_MODULE_2__.ifKey),
/* harmony export */   ifReturn: () => (/* reexport safe */ _addons_js__WEBPACK_IMPORTED_MODULE_2__.ifReturn)
/* harmony export */ });
/* harmony import */ var _classloader_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./classloader.js */ "./packages/hooks/dist/classloader.js");
/* harmony import */ var _hook_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./hook.js */ "./packages/hooks/dist/hook.js");
/* harmony import */ var _addons_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./addons.js */ "./packages/hooks/dist/addons.js");
/* harmony import */ var _filter_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./filter.js */ "./packages/hooks/dist/filter.js");





//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./packages/hooks/dist/logger.js":
/*!***************************************!*\
  !*** ./packages/hooks/dist/logger.js ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getLogger: () => (/* binding */ getLogger)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");


const { black, gray, red, green, cyan, dim, italic, bold, yellow, hidden } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.use();
const DEFAULT_LOGGER_OPTIONS = {
    spacing: '   ',
    arguments: true,
    return: true,
    multiline: true,
    short: false,
    call: true,
    hook: true,
    enable: true,
};
const HOOK_LOGGER = {
    mapMethod(config, name) {
        return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.method(name);
    },
    mapClass(config, className) {
        let type = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.toPrettyType(className);
        let array = '';
        const index = type.indexOf('[');
        if (index !== -1) {
            array = dim(yellow(type.substring(index)));
            type = type.substring(0, index);
        }
        const splits = type.split('.');
        if (config.short)
            return _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.className(splits[splits.length - 1]) + array;
        return splits.map(_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.className).join('.') + array;
    },
    mapValue(arg, type) {
        const pretty = type ? _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.toPrettyType(type) : type;
        return (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.vs)(arg, pretty);
    },
    mapArgs(config, args, types) {
        if (args.length === 0)
            return '';
        if (!config.arguments)
            return gray('...');
        const joinBy = config.multiline ? ', \n' : ', ';
        const joined = args
            .map((arg, i) => {
            let value = arg;
            let type = types?.[i] ?? null;
            const result = config.transform?.(value, type, i) ?? null;
            if (result) {
                const [newarg, newtype] = result;
                if (newarg !== undefined)
                    value = newarg;
                if (newtype !== undefined)
                    type = newtype;
            }
            const visual = this.mapValue(value, type ?? undefined);
            return `${config.multiline ? config.spacing : ''}${visual}`;
        })
            .join(joinBy);
        return config.multiline ? `\n${joined}\n` : joined;
    },
    printHookClass(config, className, logId) {
        if (!config.hook)
            return;
        let sb = '';
        sb += bold('Hooking');
        sb += ' ';
        sb += this.mapClass(config, className);
        this.logInfo(sb, logId);
    },
    printHookMethod(config, methodName, argTypes, returnType, logId) {
        if (!config.hook)
            return;
        let sb = '';
        sb += black(dim('  >'));
        sb += this.mapMethod(config, methodName);
        sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.bracket('(');
        sb += argTypes.map((argType) => this.mapClass(config, argType)).join(', ');
        sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.bracket(')');
        sb += ': ';
        sb += this.mapClass(config, returnType);
        this.logInfo(sb, logId);
    },
    printCall(config, className, methodName, argValues, argTypes, returnType, logId, isReplaced = false) {
        if (!config.call)
            return;
        let sb = '';
        // sb += dim(isReplaced ? italic('replace') : 'call');
        // sb += ' ';
        if (methodName !== '$init') {
            sb += this.mapClass(config, className);
            sb += '::';
            sb += this.mapMethod(config, methodName);
            sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.bracket('(');
            sb += this.mapArgs(config, argValues, argTypes);
            sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.bracket(')');
            sb += ': ';
            sb += this.mapClass(config, returnType);
        }
        else {
            sb += gray('new');
            sb += ' ';
            sb += this.mapClass(config, className);
            sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.bracket('(');
            sb += this.mapArgs(config, argValues, argTypes);
            sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.bracket(')');
        }
        this.logInfo(sb, logId);
    },
    printReturn(config, returnValue, returnType, logId) {
        if (!config.return)
            return;
        const value = config.transform?.(returnValue, returnType, -1) ?? returnValue;
        let sb = '';
        sb += dim('return');
        sb += ' ';
        sb += `${this.mapValue(value, returnType)}`;
        this.logInfo(sb, logId);
    },
    mapLogId(logId) {
        // janky support for kitty background, needs to be set per theme
        return ` \x1b[38;2;45;42;46m${hidden(logId)}\x1b[0m`;
    },
    logInfo(text, logId) {
        // fix line endings
        let sb = text.replaceAll(/\r\n?$/gm, '\n');
        // append logId to all lines
        if (logId) {
            sb = sb.replaceAll(/$/gm, `${this.mapLogId(logId)}`);
        }
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(sb);
    },
};
const HOOK_LOGGER_JSON = {
    mapMethod(name) {
        return name;
    },
    mapClass(className) {
        let type = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.toPrettyType(className);
        let array = '';
        const index = type.indexOf('[');
        if (index !== -1) {
            array = type.substring(index);
            type = type.substring(0, index);
        }
        const splits = type.split('.');
        return splits.join('.') + array;
    },
    mapValue(arg) {
        if (typeof arg === 'string' ||
            typeof arg === 'boolean' ||
            typeof arg === 'number' ||
            arg?.$className === _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.String) {
            return `${arg}`;
        }
        if (arg === null || arg === undefined) {
            return null;
        }
        if (typeof arg === 'object' && arg?.$className === undefined)
            try {
                //@ts-ignore
                return _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Arrays.toString(arg);
            }
            catch (_) { }
        try {
            //@ts-ignore
            return _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.String.valueOf(arg);
        }
        catch (e) {
            return `${arg}@${typeof arg}`;
        }
    },
    printHookClass(className, logId) {
        const msg = JSON.stringify({
            t: 'jvmclass',
            cn: this.mapClass(className),
            id: logId,
        });
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(msg);
    },
    printHookMethod(methodName, argTypes, returnType, logId) {
        const msg = JSON.stringify({
            t: 'jvmmethod',
            mn: this.mapMethod(methodName),
            a: argTypes.map((argType) => this.mapClass(argType)),
            r: this.mapClass(returnType),
            id: logId,
        });
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(msg);
    },
    printCall(className, methodName, argValues, argTypes, returnType, logId, isReplaced = false) {
        const msg = JSON.stringify({
            t: 'jvmcall',
            cn: this.mapClass(className),
            mn: this.mapMethod(methodName),
            id: logId,
            av: argValues.map((arg) => this.mapValue(arg)),
            st: (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.stacktraceList)(),
        });
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(msg);
    },
    printReturn(returnValue, returnType, logId) {
        const msg = JSON.stringify({
            t: 'jvmreturn',
            id: logId,
            rv: this.mapValue(returnValue),
        });
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(msg);
    },
};
function getPrettyLogger(options) {
    const opt = options ? { ...DEFAULT_LOGGER_OPTIONS, ...options } : DEFAULT_LOGGER_OPTIONS;
    return Object.assign({}, ...Object.entries(HOOK_LOGGER).map(([key, func]) => ({
        [key]: (...args) => func.call(HOOK_LOGGER, opt, ...args),
    })));
}
function getJsonLogger() {
    return HOOK_LOGGER_JSON;
}
function getLogger(options) {
    return getPrettyLogger(options);
    // return getJsonLogger()
}

//# sourceMappingURL=logger.js.map

/***/ }),

/***/ "./packages/jnitrace/dist/envWrapper.js":
/*!**********************************************!*\
  !*** ./packages/jnitrace/dist/envWrapper.js ***!
  \**********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   EnvWrapper: () => (/* binding */ EnvWrapper),
/* harmony export */   asFunction: () => (/* binding */ asFunction),
/* harmony export */   asLocalRef: () => (/* binding */ asLocalRef),
/* harmony export */   getClassName: () => (/* binding */ getClassName)
/* harmony export */ });
/* harmony import */ var _jni_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./jni.js */ "./packages/jnitrace/dist/jni.js");
/* harmony import */ var _jniEnvInterceptorArm64_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./jniEnvInterceptorArm64.js */ "./packages/jnitrace/dist/jniEnvInterceptorArm64.js");
/* harmony import */ var _model_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./model.js */ "./packages/jnitrace/dist/model.js");



class EnvWrapper {
    #env;
    jniEnv;
    jniInterceptor;
    Fields = _model_js__WEBPACK_IMPORTED_MODULE_2__.Fields;
    Methods = _model_js__WEBPACK_IMPORTED_MODULE_2__.Methods;
    ;
    #functions = {};
    #fields = {};
    constructor(env) {
        this.#env = env;
        this.jniEnv = env.handle;
        this.jniInterceptor = new _jniEnvInterceptorArm64_js__WEBPACK_IMPORTED_MODULE_1__.JNIEnvInterceptorARM64();
    }
    getFunction(def) {
        const cached = this.#functions[def.offset];
        if (cached)
            return cached;
        return (this.#functions[def.offset] = asFunction(this.jniEnv, def));
    }
    getLocalRef(ptr, fn) {
        let ref = null;
        try {
            const NewLocalRef = this.getFunction(_jni_js__WEBPACK_IMPORTED_MODULE_0__.JNI.NewLocalRef);
            return fn((ref = NewLocalRef(this.jniEnv, ptr)));
        }
        finally {
            if (ref) {
                const DeleteLocalRef = this.getFunction(_jni_js__WEBPACK_IMPORTED_MODULE_0__.JNI.DeleteLocalRef);
                DeleteLocalRef(this.jniEnv, ref);
                ref = null;
            }
        }
    }
}
function asFunction(jniEnv, def) {
    const vaTable = jniEnv.readPointer();
    const ptrPos = vaTable.add(def.offset * Process.pointerSize);
    const ptr = ptrPos.readPointer();
    return new NativeFunction(ptr, def.retType, def.argTypes);
}
function asLocalRef(jniEnv, ptr, fn) {
    let ref = null;
    try {
        const NewLocalRef = asFunction(jniEnv, _jni_js__WEBPACK_IMPORTED_MODULE_0__.JNI.NewLocalRef);
        return fn((ref = NewLocalRef(jniEnv, ptr)));
    }
    finally {
        if (ref) {
            const DeleteLocalRef = asFunction(jniEnv, _jni_js__WEBPACK_IMPORTED_MODULE_0__.JNI.DeleteLocalRef);
            DeleteLocalRef(jniEnv, ref);
            ref = null;
        }
    }
}
function getClassName(env, handle) {
    const getName = (ptr) => Java.cast(ptr, Classes.Class).getName();
    return `${handle}`.length === 12
        ? asLocalRef(env, handle, getName)
        : getName(handle);
}

//# sourceMappingURL=envWrapper.js.map

/***/ }),

/***/ "./packages/jnitrace/dist/index.js":
/*!*****************************************!*\
  !*** ./packages/jnitrace/dist/index.js ***!
  \*****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   EnvWrapper: () => (/* reexport safe */ _envWrapper_js__WEBPACK_IMPORTED_MODULE_3__.EnvWrapper),
/* harmony export */   JNI: () => (/* reexport safe */ _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI),
/* harmony export */   asFunction: () => (/* reexport safe */ _envWrapper_js__WEBPACK_IMPORTED_MODULE_3__.asFunction),
/* harmony export */   asLocalRef: () => (/* reexport safe */ _envWrapper_js__WEBPACK_IMPORTED_MODULE_3__.asLocalRef),
/* harmony export */   attach: () => (/* binding */ hookLibart)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _clockwork_native__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @clockwork/native */ "./packages/native/dist/index.js");
/* harmony import */ var _envWrapper_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./envWrapper.js */ "./packages/jnitrace/dist/envWrapper.js");
/* harmony import */ var _jni_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./jni.js */ "./packages/jnitrace/dist/jni.js");
/* harmony import */ var _jniInvokeCallback_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./jniInvokeCallback.js */ "./packages/jnitrace/dist/jniInvokeCallback.js");
/* harmony import */ var _model_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./model.js */ "./packages/jnitrace/dist/model.js");
/* harmony import */ var _tracer_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./tracer.js */ "./packages/jnitrace/dist/tracer.js");








const logger = (0,_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.subLogger)('jnitrace');
const { black, gray, dim, redBright, magenta, orange, lavender } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.use();
function ColorMethod(jMethodId, method) {
    let sb = '';
    sb += redBright(`${jMethodId} -${dim('>')}`);
    sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.className(method.className);
    sb += '::';
    sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.method(method.name);
    sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.bracket('(');
    sb += method.jParameterTypes.map(_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.className).join(', ');
    sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.bracket(')');
    sb += ': ';
    sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.className(method.jReturnType);
    return sb;
}
function ColorMethodInvoke(method, args) {
    const isConstructor = method.name === '<init>';
    let sb = '';
    if (isConstructor) {
        sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.keyword('new');
        sb += ' ';
        sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.className(method.className);
    }
    else {
        sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.className(method.className);
        sb += '::';
        sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.method(method.name);
    }
    sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.bracket('(');
    if (args.length > 0) {
        sb += '\n';
        sb += args.map((arg) => `    ${arg}`).join(', \n');
        sb += '\n';
    }
    sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.bracket(')');
    if (!isConstructor) {
        sb += ': ';
        sb += _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.className(method.jReturnType);
    }
    return sb;
}
function hookIf(callback, tag) {
    return function (args) {
        const msg = callback.call(this, args);
        if (!msg)
            return;
        console.log(`[${tag}]`, msg, DebugSymbol.fromAddress(this.returnAddress));
    };
}
function hookIfTag(tag, callback) {
    return hookIf(callback, dim(tag));
}
function formatCallMethod(jniEnv, nativeName, jMethodId, method, args) {
    // better than nothing ...
    if (!method) {
        return `${jniEnv}::${jMethodId}(${args})`;
    }
    // colorful mapping flow
    const mappedArgs = new Array(method.parameters.length);
    for (const i in method.parameters) {
        const param = method.parameters[i];
        const arg = args?.[i] ?? undefined;
        mappedArgs[i] = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.vs)(arg, param, jniEnv);
    }
    return ColorMethodInvoke(method, mappedArgs);
}
function formatMethodReturn(jniEnv, value, type) {
    const text = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.vs)(value, type, jniEnv);
    return `${dim('return')} ${text}`; // + `${type}[${value}: ${typeof value}]`;
}
let envWrapper;
function hookLibart(predicate) {
    envWrapper ??= new _envWrapper_js__WEBPACK_IMPORTED_MODULE_3__.EnvWrapper(Java.vm.getEnv());
    repl(envWrapper, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.GetStringUTFChars, function (retval, env, str, smth) {
        if (!predicate(this))
            return;
        const msg = _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.string(retval.readCString());
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('GetStringUTFChars')}] ${msg}`);
    });
    repl(envWrapper, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.NewStringUTF, function (retval, env, str) {
        if (!predicate(this))
            return;
        const text = str.readCString();
        switch (text) {
            case 'com/cocos/lib/CocosHelper':
            case 'org/cocos2dx/lib/CanvasRenderingContext2DImpl':
            case 'com/cocos/lib/CanvasRenderingContext2DImpl':
                return;
        }
        const msg = _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.string(text);
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('NewStringUTF')}] ${msg}`);
    });
    repl(envWrapper, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.FindClass, function (retval, env, str) {
        if (!predicate(this))
            return;
        const msg = lavender(`${str.readCString()}`);
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('FindClass')}] ${msg} ${retval}`);
    });
    repl(envWrapper, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.NewGlobalRef, function (retval, env, obj) {
        if (!predicate(this) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(obj) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(retval))
            return;
        const getObjectClass = (0,_envWrapper_js__WEBPACK_IMPORTED_MODULE_3__.asFunction)(env, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.GetObjectClass);
        const refClass = getObjectClass(env, obj);
        const typeName = Java.cast(refClass, _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Class).getName();
        if (typeName.match(/^\$Proxy[0-9]+$/) || typeName === _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.Long) {
            return;
        }
        const type = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.toPrettyType(typeName);
        const value = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.vs)(obj, type, env);
        const msg = `${_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.className(type)}: ${value}`;
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('NewGlobalRef')}] ${msg}`);
    });
    const GetMethodText = (retval, name, sig) => {
        let sigText = `${sig.readCString()}`;
        const types = (0,_tracer_js__WEBPACK_IMPORTED_MODULE_7__.signatureToPrettyTypes)(sigText);
        if (types) {
            sigText = `(${types.splice(0, 1).join(', ')})${types[0] !== 'void' ? `: ${types[0]}` : ''}`;
        }
        return `${name.readCString()}${sigText} ? ${retval}`;
    };
    repl(envWrapper, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.GetMethodID, function (retval, env, clazz, name, sig) {
        if (!predicate(this) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(clazz) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(name) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(sig))
            return;
        const method = (0,_tracer_js__WEBPACK_IMPORTED_MODULE_7__.resolveMethod)(env, clazz, retval, false);
        switch (method?.className) {
            case 'com.cocos.lib.CocosHelper':
            case 'org.cocos2dx.lib.CanvasRenderingContext2DImpl':
            case 'com.cocos.lib.CanvasRenderingContext2DImpl':
                return;
        }
        const msg = `${method ? ColorMethod(retval, method) : GetMethodText(retval, name, sig)}`;
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('GetMethodID')}] ${msg}`);
    });
    repl(envWrapper, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.GetStaticMethodID, function (retval, env, clazz, name, sig) {
        if (!predicate(this) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(clazz) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(name) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(sig))
            return;
        const method = (0,_tracer_js__WEBPACK_IMPORTED_MODULE_7__.resolveMethod)(env, clazz, retval, true);
        if (method?.className === 'com.cocos.lib.CocosHelper')
            return;
        if (method?.className === 'com.cocos.lib.CanvasRenderingContext2DImpl')
            return;
        const msg = `${method ? ColorMethod(retval, method) : GetMethodText(retval, name, sig)}`;
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('GetStaticMethodID')}] ${msg}`);
    });
    const GetFieldText = (retval, env, clazz, name, sig) => {
        const clazzName = (0,_envWrapper_js__WEBPACK_IMPORTED_MODULE_3__.getClassName)(env, clazz);
        const sigName = `${sig.readCString()}`;
        const typeName = (0,_tracer_js__WEBPACK_IMPORTED_MODULE_7__.signatureToPrettyTypes)(sigName)?.[0] ?? sigName;
        const fieldName = `${name.readCString()}`;
        const id = redBright(`${retval} -${dim('>')}`);
        return `${id}${_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.className(clazzName)}${_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.bracket('.')}${_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.field(fieldName)}: ${_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.className(typeName)}`;
    };
    repl(envWrapper, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.GetFieldID, function (retval, env, clazz, name, sig) {
        if (!predicate(this) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(clazz) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(name))
            return;
        const msg = GetFieldText(retval, env, clazz, name, sig);
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('GetFieldID')}] ${msg}`);
    });
    repl(envWrapper, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.GetStaticFieldID, function (retval, env, clazz, name, sig) {
        if (!predicate(this) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(clazz) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(name))
            return;
        const msg = GetFieldText(retval, env, clazz, name, sig);
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('GetStaticFieldID')}] ${msg}`);
    });
    repl(envWrapper, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.DefineClass, function (retval, env, name, obj, bytes, size) {
        if (!predicate(this) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(name) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(obj))
            return;
        const msg = `${orange(`${obj}`)} ${name} ${size} `;
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('DefineClass')}] ${msg}`);
    });
    repl(envWrapper, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.RegisterNatives, function (retval, env, clazz, jMethodDef, count) {
        if (!predicate(this) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(clazz) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(jMethodDef))
            return;
        const methods = [];
        for (let i = 0; i < count; i++) {
            const namePtr = jMethodDef.add(i * Process.pointerSize * 3).readPointer();
            const sigPtr = jMethodDef.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer();
            const fnPtrPtr = jMethodDef.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
            let sigText = `${sigPtr.readCString()}`;
            const types = (0,_tracer_js__WEBPACK_IMPORTED_MODULE_7__.signatureToPrettyTypes)(sigText);
            if (types) {
                sigText = `(${types.splice(0, 1).join(', ')})${types[0] && types[0] !== 'void' ? `: ${types[0]}` : ''}`;
            }
            const text = `    ${black(dim('  >'))}${orange(`${namePtr.readCString()}`)}${sigText} ? ${gray(`${(0,_clockwork_native__WEBPACK_IMPORTED_MODULE_2__.traceInModules)(fnPtrPtr)}`)}`;
            methods.push(text);
        }
        const clazzName = (0,_envWrapper_js__WEBPACK_IMPORTED_MODULE_3__.getClassName)(env, clazz);
        const msg = `${orange(`${jMethodDef}`)} ${clazzName}\n${methods.join('\n')}`;
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('RegisterNatives')}] ${msg}`);
    });
    repl(envWrapper, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.GetObjectArrayElement, function (retval, env, jarray, i) {
        if (!predicate(this) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(jarray) || !i)
            return;
        const getObjectClass = (0,_envWrapper_js__WEBPACK_IMPORTED_MODULE_3__.asFunction)(env, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.GetObjectClass);
        const refClass = !(0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(retval) ? getObjectClass(env, retval) : null;
        const typeName = refClass ? Java.cast(refClass, _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Class).getName() : null;
        const type = typeName ? _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.toPrettyType(typeName) : null;
        const value = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.vs)(retval, type ?? undefined, env);
        const msg = `${type ?? jarray}[${i}] ${value}`;
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('GetObjectArrayElement')}] ${msg}`);
    });
    // const NewObjectV = envWrapper.getFunction(JNI.NewObjectV)
    // const ExceptionCheck = envWrapper.getFunction(JNI.ExceptionCheck)
    // Interceptor.replace(NewObjectV, new NativeCallback(function (env, clazz, methodID, rawargs) {
    //     logger.info({ tag: 'check' }, `${ExceptionCheck(env)} ${env} ${clazz} ${methodID} ${rawargs}`)
    //     return NewObjectV(...arguments)
    // }, JNI.NewObjectV.retType, JNI.NewObjectV.argTypes))
    // for (const NewObject of [JNI.NewObject, JNI.NewObjectA, JNI.NewObjectV]) {
    //     repl(envWrapper, NewObject, function (retval, env, clazz, methodID, args) {
    //         if (!predicate(this) || isNully(clazz) || isNully(methodID) || isNully(retval) || isNully(env)) return;
    //         // const method = resolveMethod(env as NativePointer, clazz as NativePointer, methodID as NativePointer, false);
    //         // const jArgs = envWrapper.jniInterceptor.getCallMethodArgs(NewObject.name, [env as NativePointer, clazz as NativePointer, methodID as NativePointer, args as NativePointer], method);
    //         // const msg = formatCallMethod(env as NativePointer, NewObject.name, methodID as NativePointer, method, jArgs);
    //         const msg = `${methodID} ${retval}`
    //         gLogger.info(`[${dim(NewObject.name)}] ${msg}`);
    //     })
    // };
    const fn = (arg) => envWrapper.getFunction(arg);
    const jfn = (arg) => new _model_js__WEBPACK_IMPORTED_MODULE_6__.JNIMethod(arg.name, fn(arg));
    // for (const { name, address } of symbols) {
    //     if (
    //         name.includes('art') &&
    //         name.includes('JNI') &&
    //         name.includes('_ZN3art3JNIILb0') &&
    //         !name.includes('CheckJNI')
    //     ) {
    //         if (name.includes('GetStringUTFChars')) {
    //             logger.trace(`GetStringUTFChars is at ${name} ${address}`);
    //         } else if (name.includes('NewStringUTF')) {
    //             logger.trace(`NewStringUTF is at ${name} ${address}`);
    //         } else if (name.includes('DefineClass')) {
    //             logger.trace(`DefineClass is at ${name} ${address}`);
    //         } else if (name.includes('FindClass')) {
    //             logger.trace(`FindClass is at ${name} ${address}`);
    //         } else if (name.includes('GetMethodID')) {
    //             logger.trace(`GetMethodID is at ${name} ${address}`);
    //         } else if (name.includes('GetStaticMethodID')) {
    //             logger.trace(`GetStaticMethodID is at ${name} ${address}`);
    //         } else if (name.includes('GetFieldID')) {
    //             logger.trace(`GetFieldID is at ${name} ${address}`);
    //         } else if (name.includes('GetStaticFieldID')) {
    //             logger.trace(`GetStaticFieldID is at ${name} ${address}`);
    //         } else if (name.includes('RegisterNatives')) {
    //             logger.trace(`RegisterNatives is at ${name} ${address}`);
    //         } else if (name.includes('NewObject') && !name.includes('Array')) {
    //             logger.trace(`NewObject is at ${name} ${address}`);
    //         } else if (name.includes('CallStatic')) {
    //             logger.trace(`CallStatic is at ${name} ${address}`);
    //         } else if (name.includes('CallNonvirtual')) {
    //             logger.trace(`CallNonvirtual is at ${name} ${address}`);
    //         } else if (name.includes('Call') && name.includes('Method')) {
    //             logger.trace(`Call<>Method is at ${name} ${address}`);
    //         } else if (name.includes('ToReflectedMethod')) {
    //             logger.trace(`ToReflectedMethod is at ${name} ${address}`);
    //         } else if (name.includes('GetArrayLength')) {
    //             Interceptor.attach(address, {
    //                 onLeave: hookIfTag('GetArrayLength', (retval) => `${retval}`),
    //             });
    //         } else if (name.includes('SetByteArrayRegion')) {
    //             Interceptor.attach(address, {
    //                 onLeave: hookIfTag('SetByteArrayRegion', (retval) => `${retval}`),
    //             });
    //         } else if (name.includes('NewObjectArray')) {
    //             Interceptor.attach(address, {
    //                 onLeave: hookIfTag('NewObjectArray', (retval) => `${retval}`),
    //             });
    //         } else if (name.includes('SetObjectArrayElement')) {
    //             Interceptor.attach(address, {
    //                 onEnter: hookIfTag('SetObjectArrayElement', (args) => `${args[2]} -> ${args[3]}`),
    //             });
    //         } else if (name.includes('ReleaseByteArrayElements')) {
    //             Interceptor.attach(address, {
    //                 onEnter: hookIfTag('ReleaseByteArrayElements', (args) => `${args[2]} -> ${args[3]}`),
    //             });
    //         } else if (name.includes('GetByteArrayElements')) {
    //             Interceptor.attach(address, {
    //                 onLeave: hookIfTag('GetByteArrayElements', (retval) => `${retval}}`),
    //             });
    //         } else if (name.includes('NewGlobalRef')) {
    //             logger.trace(`NewGlobalRef is at ${name} ${address}`);
    //         }
    //     }
    // }
     false &&
        0;
    for (const Obj of [_jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.NewObject, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.NewObjectA, _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.NewObjectV]) {
        continue;
        repl(envWrapper, Obj, function (retval, env, clazz, methodID, args) {
            if (!predicate(this) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(clazz) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(methodID) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(retval) || (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(args))
                return;
            const method = (0,_tracer_js__WEBPACK_IMPORTED_MODULE_7__.resolveMethod)(env, clazz, methodID, false);
            const jArgs = envWrapper.jniInterceptor.getCallMethodArgs(Obj.name, [
                env,
                clazz,
                methodID,
                args,
            ], method);
            const msg = formatCallMethod(env, Obj.name, methodID, method, jArgs);
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim('NewObject')}] ${msg}`);
        });
    }
    // biome-ignore lint/suspicious/noSelfCompare: <explanation>
    // biome-ignore lint/correctness/noConstantCondition: <explanation>
    // if (1 === 1) return;
    // for (const { address, name } of addrsCallStatic) {
    //     const cb = JniInvokeCallbacks(envWrapper, name, JniInvokeMode.Static, predicate, {
    //         onEnter({ method, env, methodID, jArgs }) {
    //             if ((method?.className?.includes('CocosHelper') &&
    //                 method?.name?.includes('flushTasksOnGameThread')) || (method?.className === ClassesString.System && method?.name === 'nanoTime')
    //             ) {
    //                 this.ignore = true;
    //                 return;
    //             }
    //             const msg = formatCallMethod(env, name, methodID, method, jArgs);
    //             gLogger.info(`[${dim(name)}] ${msg} ${DebugSymbol.fromAddress(this.returnAddress)}`);
    //         },
    //         onLeave({ env, method }, retval) {
    //             if (this.ignore || method?.isVoid) return
    //             const msg = formatMethodReturn(env, retval, method?.returnType);
    //             gLogger.info(`[${dim(name)}] ${msg} ${DebugSymbol.fromAddress(this.returnAddress)}`);
    //         },
    //     });
    //     Interceptor.attach(address, cb);
    // }
    // for (const { address, name } of addrsCallNonvirtual) {
    //     const cb = JniInvokeCallbacks(envWrapper, name, JniInvokeMode.Nonvirtual, predicate, {
    //         onEnter({ method, env, methodID, jArgs }) {
    //             const msg = formatCallMethod(env, name, methodID, method, jArgs);
    //             gLogger.info(`[${dim(name)}] ${msg} ${DebugSymbol.fromAddress(this.returnAddress)}`);
    //         },
    //         onLeave({ env, method }, retval) {
    //             if (this.ignore || method?.isVoid) return
    //             const msg = formatMethodReturn(env, retval, method?.returnType);
    //             gLogger.info(`[${dim(name)}] ${msg} ${DebugSymbol.fromAddress(this.returnAddress)}`);
    //         },
    //     });
    //     Interceptor.attach(address, cb);
    // }
    const CallObjects = [
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallObjectMethod,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallObjectMethodA,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallObjectMethodV,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallIntMethod,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallIntMethodA,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallIntMethodV,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallBooleanMethod,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallBooleanMethodA,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallBooleanMethodV,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallDoubleMethod,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallDoubleMethodA,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallDoubleMethodV,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallFloatMethod,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallFloatMethodA,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallFloatMethodV,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallLongMethod,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallLongMethodA,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallLongMethodV,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallVoidMethod,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallVoidMethodA,
        _jni_js__WEBPACK_IMPORTED_MODULE_4__.JNI.CallVoidMethodV,
    ];
    for (const j of CallObjects) {
        const { address, name } = jfn(j);
        const cb = (0,_jniInvokeCallback_js__WEBPACK_IMPORTED_MODULE_5__.JniInvokeCallbacks)(envWrapper, j, _model_js__WEBPACK_IMPORTED_MODULE_6__.JniInvokeMode.Normal, predicate, {
            onEnter({ method, env, methodID, jArgs }) {
                const msg = formatCallMethod(env, name, methodID, method, jArgs);
                if (method?.className === _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.ClassLoader && method?.name === 'loadClass') {
                    for (const skip of [
                        'org/cocos2dx/lib/CanvasRenderingContext2DImpl',
                        'com/cocos/lib/CanvasRenderingContext2DImpl',
                        'com/cocos/lib/CocosHelper',
                    ]) {
                        if (msg.includes(skip)) {
                            this.ignore = true;
                            return;
                        }
                    }
                }
                switch (method?.className) {
                    case 'com.cocos.lib/CocosHelper':
                    case 'com.cocos.lib.CanvasRenderingContext2DImpl':
                        this.ignore = true;
                        if (this.ignore)
                            return;
                        break;
                    case "android.view.Choreographer":
                        this.ignore = method?.name === 'postFrameCallback';
                        if (this.ignore)
                            return;
                        break;
                    case "java.lang.Long":
                        this.ignore = method?.name === 'longValue';
                        if (this.ignore)
                            return;
                        break;
                }
                _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim(name)}] ${msg} ${DebugSymbol.fromAddress(this.returnAddress)}`);
            },
            onLeave({ env, method }, retval) {
                if (this.ignore || method?.isVoid)
                    return;
                const msg = formatMethodReturn(env, retval, method?.returnType);
                _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info(`[${dim(name)}] ${msg} ${DebugSymbol.fromAddress(this.returnAddress)}`);
            },
        });
        Interceptor.attach(address, cb);
    }
}
function repl(envWrapper, def, log) {
    const fn = envWrapper.getFunction(def);
    const cb = function (...args) {
        const retval = fn(...args);
        log.call(this, retval, ...args);
        return retval;
    };
    Interceptor.replace(fn, new NativeCallback(cb, def.retType, def.argTypes));
}

//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./packages/jnitrace/dist/jni.js":
/*!***************************************!*\
  !*** ./packages/jnitrace/dist/jni.js ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   JNI: () => (/* binding */ JNI)
/* harmony export */ });
const JNI = {
    NULL0: {
        jni: { ret: 'NULL', args: [] },
        retType: 'void',
        argTypes: [],
        name: 'NULL0',
        offset: 0,
    },
    NULL1: {
        jni: { ret: 'NULL', args: [] },
        retType: 'void',
        argTypes: [],
        name: 'NULL1',
        offset: 1,
    },
    NULL2: {
        jni: { ret: 'NULL', args: [] },
        retType: 'void',
        argTypes: [],
        name: 'NULL2',
        offset: 2,
    },
    NULL3: {
        jni: { ret: 'NULL', args: [] },
        retType: 'void',
        argTypes: [],
        name: 'NULL3',
        offset: 3,
    },
    GetVersion: {
        jni: { ret: 'jint', args: ['JNIEnv*'] },
        retType: 'int32',
        argTypes: ['pointer'],
        name: 'GetVersion',
        offset: 4,
    },
    DefineClass: {
        jni: {
            ret: 'jclass',
            args: ['JNIEnv*', 'char*', 'jobject', 'jbyte*', 'jsize'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'int32'],
        name: 'DefineClass',
        offset: 5,
    },
    FindClass: {
        jni: { ret: 'jclass', args: ['JNIEnv*', 'char*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'FindClass',
        offset: 6,
    },
    FromReflectedMethod: {
        jni: { ret: 'jmethodID', args: ['JNIEnv*', 'jobject'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'FromReflectedMethod',
        offset: 7,
    },
    FromReflectedField: {
        jni: { ret: 'jfieldID', args: ['JNIEnv*', 'jobject'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'FromReflectedField',
        offset: 8,
    },
    ToReflectedMethod: {
        jni: {
            ret: 'jobject',
            args: ['JNIEnv*', 'jclass', 'jmethodID', 'jboolean'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'uint8'],
        name: 'ToReflectedMethod',
        offset: 9,
    },
    GetSuperclass: {
        jni: { ret: 'jclass', args: ['JNIEnv*', 'jclass'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'GetSuperclass',
        offset: 10,
    },
    IsAssignableFrom: {
        jni: { ret: 'jboolean', args: ['JNIEnv*', 'jclass', 'jclass'] },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'IsAssignableFrom',
        offset: 11,
    },
    ToReflectedField: {
        jni: {
            ret: 'jobject',
            args: ['JNIEnv*', 'jclass', 'jfieldID', 'jboolean'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'uint8'],
        name: 'ToReflectedField',
        offset: 12,
    },
    Throw: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jthrowable'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer'],
        name: 'Throw',
        offset: 13,
    },
    ThrowNew: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jclass', 'char*'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'ThrowNew',
        offset: 14,
    },
    ExceptionOccurred: {
        jni: { ret: 'jthrowable', args: ['JNIEnv*'] },
        retType: 'pointer',
        argTypes: ['pointer'],
        name: 'ExceptionOccurred',
        offset: 15,
    },
    ExceptionDescribe: {
        jni: { ret: 'void', args: ['JNIEnv*'] },
        retType: 'void',
        argTypes: ['pointer'],
        name: 'ExceptionDescribe',
        offset: 16,
    },
    ExceptionClear: {
        jni: { ret: 'void', args: ['JNIEnv*'] },
        retType: 'void',
        argTypes: ['pointer'],
        name: 'ExceptionClear',
        offset: 17,
    },
    FatalError: {
        jni: { ret: 'void', args: ['JNIEnv*', 'char*'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer'],
        name: 'FatalError',
        offset: 18,
    },
    PushLocalFrame: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jint'] },
        retType: 'int32',
        argTypes: ['pointer', 'int32'],
        name: 'PushLocalFrame',
        offset: 19,
    },
    PopLocalFrame: {
        jni: { ret: 'jobject', args: ['JNIEnv*', 'jobject'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'PopLocalFrame',
        offset: 20,
    },
    NewGlobalRef: {
        jni: { ret: 'jobject', args: ['JNIEnv*', 'jobject'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'NewGlobalRef',
        offset: 21,
    },
    DeleteGlobalRef: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer'],
        name: 'DeleteGlobalRef',
        offset: 22,
    },
    DeleteLocalRef: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer'],
        name: 'DeleteLocalRef',
        offset: 23,
    },
    IsSameObject: {
        jni: { ret: 'jboolean', args: ['JNIEnv*', 'jobject', 'jobject'] },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'IsSameObject',
        offset: 24,
    },
    NewLocalRef: {
        jni: { ret: 'jobject', args: ['JNIEnv*', 'jobject'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'NewLocalRef',
        offset: 25,
    },
    EnsureLocalCapacity: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jint'] },
        retType: 'int32',
        argTypes: ['pointer', 'int32'],
        name: 'EnsureLocalCapacity',
        offset: 26,
    },
    AllocObject: {
        jni: { ret: 'jobject', args: ['JNIEnv*', 'jclass'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'AllocObject',
        offset: 27,
    },
    NewObject: {
        jni: { ret: 'jobject', args: ['JNIEnv*', 'jclass', 'jmethodID', '...'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'NewObject',
        offset: 28,
    },
    NewObjectV: {
        jni: {
            ret: 'jobject',
            args: ['JNIEnv*', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'NewObjectV',
        offset: 29,
    },
    NewObjectA: {
        jni: {
            ret: 'jobject',
            args: ['JNIEnv*', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'NewObjectA',
        offset: 30,
    },
    GetObjectClass: {
        jni: { ret: 'jclass', args: ['JNIEnv*', 'jobject'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'GetObjectClass',
        offset: 31,
    },
    IsInstanceOf: {
        jni: { ret: 'jboolean', args: ['JNIEnv*', 'jobject', 'jclass'] },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'IsInstanceOf',
        offset: 32,
    },
    GetMethodID: {
        jni: { ret: 'jmethodID', args: ['JNIEnv*', 'jclass', 'char*', 'char*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'GetMethodID',
        offset: 33,
    },
    CallObjectMethod: {
        jni: { ret: 'jobject', args: ['JNIEnv*', 'jobject', 'jmethodID', '...'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallObjectMethod',
        offset: 34,
    },
    CallObjectMethodV: {
        jni: {
            ret: 'jobject',
            args: ['JNIEnv*', 'jobject', 'jmethodID', 'va_list'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallObjectMethodV',
        offset: 35,
    },
    CallObjectMethodA: {
        jni: {
            ret: 'jobject',
            args: ['JNIEnv*', 'jobject', 'jmethodID', 'jvalue*'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallObjectMethodA',
        offset: 36,
    },
    CallBooleanMethod: {
        jni: { ret: 'jboolean', args: ['JNIEnv*', 'jobject', 'jmethodID', '...'] },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallBooleanMethod',
        offset: 37,
    },
    CallBooleanMethodV: {
        jni: {
            ret: 'jboolean',
            args: ['JNIEnv*', 'jobject', 'jmethodID', 'va_list'],
        },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallBooleanMethodV',
        offset: 38,
    },
    CallBooleanMethodA: {
        jni: {
            ret: 'jboolean',
            args: ['JNIEnv*', 'jobject', 'jmethodID', 'jvalue*'],
        },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallBooleanMethodA',
        offset: 39,
    },
    CallByteMethod: {
        jni: { ret: 'jbyte', args: ['JNIEnv*', 'jobject', 'jmethodID', '...'] },
        retType: 'int8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallByteMethod',
        offset: 40,
    },
    CallByteMethodV: {
        jni: { ret: 'jbyte', args: ['JNIEnv*', 'jobject', 'jmethodID', 'va_list'] },
        retType: 'int8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallByteMethodV',
        offset: 41,
    },
    CallByteMethodA: {
        jni: { ret: 'jbyte', args: ['JNIEnv*', 'jobject', 'jmethodID', 'jvalue*'] },
        retType: 'int8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallByteMethodA',
        offset: 42,
    },
    CallCharMethod: {
        jni: { ret: 'jchar', args: ['JNIEnv*', 'jobject', 'jmethodID', '...'] },
        retType: 'uint16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallCharMethod',
        offset: 43,
    },
    CallCharMethodV: {
        jni: { ret: 'jchar', args: ['JNIEnv*', 'jobject', 'jmethodID', 'va_list'] },
        retType: 'uint16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallCharMethodV',
        offset: 44,
    },
    CallCharMethodA: {
        jni: { ret: 'jchar', args: ['JNIEnv*', 'jobject', 'jmethodID', 'jvalue*'] },
        retType: 'uint16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallCharMethodA',
        offset: 45,
    },
    CallShortMethod: {
        jni: { ret: 'jshort', args: ['JNIEnv*', 'jobject', 'jmethodID', '...'] },
        retType: 'int16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallShortMethod',
        offset: 46,
    },
    CallShortMethodV: {
        jni: {
            ret: 'jshort',
            args: ['JNIEnv*', 'jobject', 'jmethodID', 'va_list'],
        },
        retType: 'int16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallShortMethodV',
        offset: 47,
    },
    CallShortMethodA: {
        jni: {
            ret: 'jshort',
            args: ['JNIEnv*', 'jobject', 'jmethodID', 'jvalue*'],
        },
        retType: 'int16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallShortMethodA',
        offset: 48,
    },
    CallIntMethod: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jobject', 'jmethodID', '...'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallIntMethod',
        offset: 49,
    },
    CallIntMethodV: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jobject', 'jmethodID', 'va_list'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallIntMethodV',
        offset: 50,
    },
    CallIntMethodA: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jobject', 'jmethodID', 'jvalue*'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallIntMethodA',
        offset: 51,
    },
    CallLongMethod: {
        jni: { ret: 'jlong', args: ['JNIEnv*', 'jobject', 'jmethodID', '...'] },
        retType: 'int64',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallLongMethod',
        offset: 52,
    },
    CallLongMethodV: {
        jni: { ret: 'jlong', args: ['JNIEnv*', 'jobject', 'jmethodID', 'va_list'] },
        retType: 'int64',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallLongMethodV',
        offset: 53,
    },
    CallLongMethodA: {
        jni: { ret: 'jlong', args: ['JNIEnv*', 'jobject', 'jmethodID', 'jvalue*'] },
        retType: 'int64',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallLongMethodA',
        offset: 54,
    },
    CallFloatMethod: {
        jni: { ret: 'jfloat', args: ['JNIEnv*', 'jobject', 'jmethodID', '...'] },
        retType: 'float',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallFloatMethod',
        offset: 55,
    },
    CallFloatMethodV: {
        jni: {
            ret: 'jfloat',
            args: ['JNIEnv*', 'jobject', 'jmethodID', 'va_list'],
        },
        retType: 'float',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallFloatMethodV',
        offset: 56,
    },
    CallFloatMethodA: {
        jni: {
            ret: 'jfloat',
            args: ['JNIEnv*', 'jobject', 'jmethodID', 'jvalue*'],
        },
        retType: 'float',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallFloatMethodA',
        offset: 57,
    },
    CallDoubleMethod: {
        jni: { ret: 'jdouble', args: ['JNIEnv*', 'jobject', 'jmethodID', '...'] },
        retType: 'double',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallDoubleMethod',
        offset: 58,
    },
    CallDoubleMethodV: {
        jni: {
            ret: 'jdouble',
            args: ['JNIEnv*', 'jobject', 'jmethodID', 'va_list'],
        },
        retType: 'double',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallDoubleMethodV',
        offset: 59,
    },
    CallDoubleMethodA: {
        jni: {
            ret: 'jdouble',
            args: ['JNIEnv*', 'jobject', 'jmethodID', 'jvalue*'],
        },
        retType: 'double',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallDoubleMethodA',
        offset: 60,
    },
    CallVoidMethod: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jmethodID', '...'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallVoidMethod',
        offset: 61,
    },
    CallVoidMethodV: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jmethodID', 'va_list'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallVoidMethodV',
        offset: 62,
    },
    CallVoidMethodA: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jmethodID', 'jvalue*'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallVoidMethodA',
        offset: 63,
    },
    CallNonvirtualObjectMethod: {
        jni: {
            ret: 'jobject',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', '...'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualObjectMethod',
        offset: 64,
    },
    CallNonvirtualObjectMethodV: {
        jni: {
            ret: 'jobject',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualObjectMethodV',
        offset: 65,
    },
    CallNonvirtualObjectMethodA: {
        jni: {
            ret: 'jobject',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualObjectMethodA',
        offset: 66,
    },
    CallNonvirtualBooleanMethod: {
        jni: {
            ret: 'jboolean',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', '...'],
        },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualBooleanMethod',
        offset: 67,
    },
    CallNonvirtualBooleanMethodV: {
        jni: {
            ret: 'jboolean',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualBooleanMethodV',
        offset: 68,
    },
    CallNonvirtualBooleanMethodA: {
        jni: {
            ret: 'jboolean',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualBooleanMethodA',
        offset: 69,
    },
    CallNonvirtualByteMethod: {
        jni: {
            ret: 'jbyte',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', '...'],
        },
        retType: 'int8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualByteMethod',
        offset: 70,
    },
    CallNonvirtualByteMethodV: {
        jni: {
            ret: 'jbyte',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'int8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualByteMethodV',
        offset: 71,
    },
    CallNonvirtualByteMethodA: {
        jni: {
            ret: 'jbyte',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'int8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualByteMethodA',
        offset: 72,
    },
    CallNonvirtualCharMethod: {
        jni: {
            ret: 'jchar',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', '...'],
        },
        retType: 'uint16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualCharMethod',
        offset: 73,
    },
    CallNonvirtualCharMethodV: {
        jni: {
            ret: 'jchar',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'uint16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualCharMethodV',
        offset: 74,
    },
    CallNonvirtualCharMethodA: {
        jni: {
            ret: 'jchar',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'uint16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualCharMethodA',
        offset: 75,
    },
    CallNonvirtualShortMethod: {
        jni: {
            ret: 'jshort',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', '...'],
        },
        retType: 'int16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualShortMethod',
        offset: 76,
    },
    CallNonvirtualShortMethodV: {
        jni: {
            ret: 'jshort',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'int16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualShortMethodV',
        offset: 77,
    },
    CallNonvirtualShortMethodA: {
        jni: {
            ret: 'jshort',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'int16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualShortMethodA',
        offset: 78,
    },
    CallNonvirtualIntMethod: {
        jni: {
            ret: 'jint',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', '...'],
        },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualIntMethod',
        offset: 79,
    },
    CallNonvirtualIntMethodV: {
        jni: {
            ret: 'jint',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualIntMethodV',
        offset: 80,
    },
    CallNonvirtualIntMethodA: {
        jni: {
            ret: 'jint',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualIntMethodA',
        offset: 81,
    },
    CallNonvirtualLongMethod: {
        jni: {
            ret: 'jlong',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', '...'],
        },
        retType: 'int64',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualLongMethod',
        offset: 82,
    },
    CallNonvirtualLongMethodV: {
        jni: {
            ret: 'jlong',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'int64',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualLongMethodV',
        offset: 83,
    },
    CallNonvirtualLongMethodA: {
        jni: {
            ret: 'jlong',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'int64',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualLongMethodA',
        offset: 84,
    },
    CallNonvirtualFloatMethod: {
        jni: {
            ret: 'jfloat',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', '...'],
        },
        retType: 'float',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualFloatMethod',
        offset: 85,
    },
    CallNonvirtualFloatMethodV: {
        jni: {
            ret: 'jfloat',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'float',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualFloatMethodV',
        offset: 86,
    },
    CallNonvirtualFloatMethodA: {
        jni: {
            ret: 'jfloat',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'float',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualFloatMethodA',
        offset: 87,
    },
    CallNonvirtualDoubleMethod: {
        jni: {
            ret: 'jdouble',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', '...'],
        },
        retType: 'double',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualDoubleMethod',
        offset: 88,
    },
    CallNonvirtualDoubleMethodV: {
        jni: {
            ret: 'jdouble',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'double',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualDoubleMethodV',
        offset: 89,
    },
    CallNonvirtualDoubleMethodA: {
        jni: {
            ret: 'jdouble',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'double',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualDoubleMethodA',
        offset: 90,
    },
    CallNonvirtualVoidMethod: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', '...'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualVoidMethod',
        offset: 91,
    },
    CallNonvirtualVoidMethodV: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualVoidMethodV',
        offset: 92,
    },
    CallNonvirtualVoidMethodA: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jobject', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallNonvirtualVoidMethodA',
        offset: 93,
    },
    GetFieldID: {
        jni: { ret: 'jfieldID', args: ['JNIEnv*', 'jclass', 'char*', 'char*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'GetFieldID',
        offset: 94,
    },
    GetObjectField: {
        jni: { ret: 'jobject', args: ['JNIEnv*', 'jobject', 'jfieldID'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetObjectField',
        offset: 95,
    },
    GetBooleanField: {
        jni: { ret: 'jboolean', args: ['JNIEnv*', 'jobject', 'jfieldID'] },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetBooleanField',
        offset: 96,
    },
    GetByteField: {
        jni: { ret: 'jbyte', args: ['JNIEnv*', 'jobject', 'jfieldID'] },
        retType: 'int8',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetByteField',
        offset: 97,
    },
    GetCharField: {
        jni: { ret: 'jchar', args: ['JNIEnv*', 'jobject', 'jfieldID'] },
        retType: 'uint16',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetCharField',
        offset: 98,
    },
    GetShortField: {
        jni: { ret: 'jshort', args: ['JNIEnv*', 'jobject', 'jfieldID'] },
        retType: 'int16',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetShortField',
        offset: 99,
    },
    GetIntField: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jobject', 'jfieldID'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetIntField',
        offset: 100,
    },
    GetLongField: {
        jni: { ret: 'jlong', args: ['JNIEnv*', 'jobject', 'jfieldID'] },
        retType: 'int64',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetLongField',
        offset: 101,
    },
    GetFloatField: {
        jni: { ret: 'jfloat', args: ['JNIEnv*', 'jobject', 'jfieldID'] },
        retType: 'float',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetFloatField',
        offset: 102,
    },
    GetDoubleField: {
        jni: { ret: 'jdouble', args: ['JNIEnv*', 'jobject', 'jfieldID'] },
        retType: 'double',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetDoubleField',
        offset: 103,
    },
    SetObjectField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jfieldID', 'jobject'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'SetObjectField',
        offset: 104,
    },
    SetBooleanField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jfieldID', 'jboolean'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'uint8'],
        name: 'SetBooleanField',
        offset: 105,
    },
    SetByteField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jfieldID', 'jbyte'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int8'],
        name: 'SetByteField',
        offset: 106,
    },
    SetCharField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jfieldID', 'jchar'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'uint16'],
        name: 'SetCharField',
        offset: 107,
    },
    SetShortField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jfieldID', 'jshort'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int16'],
        name: 'SetShortField',
        offset: 108,
    },
    SetIntField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jfieldID', 'jint'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'SetIntField',
        offset: 109,
    },
    SetLongField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jfieldID', 'jlong'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int64'],
        name: 'SetLongField',
        offset: 110,
    },
    SetFloatField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jfieldID', 'jfloat'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'float'],
        name: 'SetFloatField',
        offset: 111,
    },
    SetDoubleField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobject', 'jfieldID', 'jdouble'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'double'],
        name: 'SetDoubleField',
        offset: 112,
    },
    GetStaticMethodID: {
        jni: { ret: 'jmethodID', args: ['JNIEnv*', 'jclass', 'char*', 'char*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'GetStaticMethodID',
        offset: 113,
    },
    CallStaticObjectMethod: {
        jni: { ret: 'jobject', args: ['JNIEnv*', 'jclass', 'jmethodID', '...'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticObjectMethod',
        offset: 114,
    },
    CallStaticObjectMethodV: {
        jni: {
            ret: 'jobject',
            args: ['JNIEnv*', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticObjectMethodV',
        offset: 115,
    },
    CallStaticObjectMethodA: {
        jni: {
            ret: 'jobject',
            args: ['JNIEnv*', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticObjectMethodA',
        offset: 116,
    },
    CallStaticBooleanMethod: {
        jni: { ret: 'jboolean', args: ['JNIEnv*', 'jclass', 'jmethodID', '...'] },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticBooleanMethod',
        offset: 117,
    },
    CallStaticBooleanMethodV: {
        jni: {
            ret: 'jboolean',
            args: ['JNIEnv*', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticBooleanMethodV',
        offset: 118,
    },
    CallStaticBooleanMethodA: {
        jni: {
            ret: 'jboolean',
            args: ['JNIEnv*', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticBooleanMethodA',
        offset: 119,
    },
    CallStaticByteMethod: {
        jni: { ret: 'jbyte', args: ['JNIEnv*', 'jclass', 'jmethodID', '...'] },
        retType: 'int8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticByteMethod',
        offset: 120,
    },
    CallStaticByteMethodV: {
        jni: { ret: 'jbyte', args: ['JNIEnv*', 'jclass', 'jmethodID', 'va_list'] },
        retType: 'int8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticByteMethodV',
        offset: 121,
    },
    CallStaticByteMethodA: {
        jni: { ret: 'jbyte', args: ['JNIEnv*', 'jclass', 'jmethodID', 'jvalue*'] },
        retType: 'int8',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticByteMethodA',
        offset: 122,
    },
    CallStaticCharMethod: {
        jni: { ret: 'jchar', args: ['JNIEnv*', 'jclass', 'jmethodID', '...'] },
        retType: 'uint16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticCharMethod',
        offset: 123,
    },
    CallStaticCharMethodV: {
        jni: { ret: 'jchar', args: ['JNIEnv*', 'jclass', 'jmethodID', 'va_list'] },
        retType: 'uint16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticCharMethodV',
        offset: 124,
    },
    CallStaticCharMethodA: {
        jni: { ret: 'jchar', args: ['JNIEnv*', 'jclass', 'jmethodID', 'jvalue*'] },
        retType: 'uint16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticCharMethodA',
        offset: 125,
    },
    CallStaticShortMethod: {
        jni: { ret: 'jshort', args: ['JNIEnv*', 'jclass', 'jmethodID', '...'] },
        retType: 'int16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticShortMethod',
        offset: 126,
    },
    CallStaticShortMethodV: {
        jni: { ret: 'jshort', args: ['JNIEnv*', 'jclass', 'jmethodID', 'va_list'] },
        retType: 'int16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticShortMethodV',
        offset: 127,
    },
    CallStaticShortMethodA: {
        jni: { ret: 'jshort', args: ['JNIEnv*', 'jclass', 'jmethodID', 'jvalue*'] },
        retType: 'int16',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticShortMethodA',
        offset: 128,
    },
    CallStaticIntMethod: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jclass', 'jmethodID', '...'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticIntMethod',
        offset: 129,
    },
    CallStaticIntMethodV: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jclass', 'jmethodID', 'va_list'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticIntMethodV',
        offset: 130,
    },
    CallStaticIntMethodA: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jclass', 'jmethodID', 'jvalue*'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticIntMethodA',
        offset: 131,
    },
    CallStaticLongMethod: {
        jni: { ret: 'jlong', args: ['JNIEnv*', 'jclass', 'jmethodID', '...'] },
        retType: 'int64',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticLongMethod',
        offset: 132,
    },
    CallStaticLongMethodV: {
        jni: { ret: 'jlong', args: ['JNIEnv*', 'jclass', 'jmethodID', 'va_list'] },
        retType: 'int64',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticLongMethodV',
        offset: 133,
    },
    CallStaticLongMethodA: {
        jni: { ret: 'jlong', args: ['JNIEnv*', 'jclass', 'jmethodID', 'jvalue*'] },
        retType: 'int64',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticLongMethodA',
        offset: 134,
    },
    CallStaticFloatMethod: {
        jni: { ret: 'jfloat', args: ['JNIEnv*', 'jclass', 'jmethodID', '...'] },
        retType: 'float',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticFloatMethod',
        offset: 135,
    },
    CallStaticFloatMethodV: {
        jni: { ret: 'jfloat', args: ['JNIEnv*', 'jclass', 'jmethodID', 'va_list'] },
        retType: 'float',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticFloatMethodV',
        offset: 136,
    },
    CallStaticFloatMethodA: {
        jni: { ret: 'jfloat', args: ['JNIEnv*', 'jclass', 'jmethodID', 'jvalue*'] },
        retType: 'float',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticFloatMethodA',
        offset: 137,
    },
    CallStaticDoubleMethod: {
        jni: { ret: 'jdouble', args: ['JNIEnv*', 'jclass', 'jmethodID', '...'] },
        retType: 'double',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticDoubleMethod',
        offset: 138,
    },
    CallStaticDoubleMethodV: {
        jni: {
            ret: 'jdouble',
            args: ['JNIEnv*', 'jclass', 'jmethodID', 'va_list'],
        },
        retType: 'double',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticDoubleMethodV',
        offset: 139,
    },
    CallStaticDoubleMethodA: {
        jni: {
            ret: 'jdouble',
            args: ['JNIEnv*', 'jclass', 'jmethodID', 'jvalue*'],
        },
        retType: 'double',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticDoubleMethodA',
        offset: 140,
    },
    CallStaticVoidMethod: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jmethodID', '...'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticVoidMethod',
        offset: 141,
    },
    CallStaticVoidMethodV: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jmethodID', 'va_list'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticVoidMethodV',
        offset: 142,
    },
    CallStaticVoidMethodA: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jmethodID', 'jvalue*'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'CallStaticVoidMethodA',
        offset: 143,
    },
    GetStaticFieldID: {
        jni: { ret: 'jfieldID', args: ['JNIEnv*', 'jclass', 'char*', 'char*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'GetStaticFieldID',
        offset: 144,
    },
    GetStaticObjectField: {
        jni: { ret: 'jobject', args: ['JNIEnv*', 'jclass', 'jfieldID'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStaticObjectField',
        offset: 145,
    },
    GetStaticBooleanField: {
        jni: { ret: 'jboolean', args: ['JNIEnv*', 'jclass', 'jfieldID'] },
        retType: 'uint8',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStaticBooleanField',
        offset: 146,
    },
    GetStaticByteField: {
        jni: { ret: 'jbyte', args: ['JNIEnv*', 'jclass', 'jfieldID'] },
        retType: 'int8',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStaticByteField',
        offset: 147,
    },
    GetStaticCharField: {
        jni: { ret: 'jchar', args: ['JNIEnv*', 'jclass', 'jfieldID'] },
        retType: 'uint16',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStaticCharField',
        offset: 148,
    },
    GetStaticShortField: {
        jni: { ret: 'jshort', args: ['JNIEnv*', 'jclass', 'jfieldID'] },
        retType: 'int16',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStaticShortField',
        offset: 149,
    },
    GetStaticIntField: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jclass', 'jfieldID'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStaticIntField',
        offset: 150,
    },
    GetStaticLongField: {
        jni: { ret: 'jlong', args: ['JNIEnv*', 'jclass', 'jfieldID'] },
        retType: 'int64',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStaticLongField',
        offset: 151,
    },
    GetStaticFloatField: {
        jni: { ret: 'jfloat', args: ['JNIEnv*', 'jclass', 'jfieldID'] },
        retType: 'float',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStaticFloatField',
        offset: 152,
    },
    GetStaticDoubleField: {
        jni: { ret: 'jdouble', args: ['JNIEnv*', 'jclass', 'jfieldID'] },
        retType: 'double',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStaticDoubleField',
        offset: 153,
    },
    SetStaticObjectField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jfieldID', 'jobject'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'pointer'],
        name: 'SetStaticObjectField',
        offset: 154,
    },
    SetStaticBooleanField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jfieldID', 'jboolean'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'uint8'],
        name: 'SetStaticBooleanField',
        offset: 155,
    },
    SetStaticByteField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jfieldID', 'jbyte'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int8'],
        name: 'SetStaticByteField',
        offset: 156,
    },
    SetStaticCharField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jfieldID', 'jchar'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'uint16'],
        name: 'SetStaticCharField',
        offset: 157,
    },
    SetStaticShortField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jfieldID', 'jshort'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int16'],
        name: 'SetStaticShortField',
        offset: 158,
    },
    SetStaticIntField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jfieldID', 'jint'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'SetStaticIntField',
        offset: 159,
    },
    SetStaticLongField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jfieldID', 'jlong'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int64'],
        name: 'SetStaticLongField',
        offset: 160,
    },
    SetStaticFloatField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jfieldID', 'jfloat'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'float'],
        name: 'SetStaticFloatField',
        offset: 161,
    },
    SetStaticDoubleField: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jclass', 'jfieldID', 'jdouble'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'double'],
        name: 'SetStaticDoubleField',
        offset: 162,
    },
    NewString: {
        jni: { ret: 'jstring', args: ['JNIEnv*', 'jchar*', 'jsize'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'int32'],
        name: 'NewString',
        offset: 163,
    },
    GetStringLength: {
        jni: { ret: 'jsize', args: ['JNIEnv*', 'jstring'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer'],
        name: 'GetStringLength',
        offset: 164,
    },
    GetStringChars: {
        jni: { ret: 'jchar*', args: ['JNIEnv*', 'jstring', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStringChars',
        offset: 165,
    },
    ReleaseStringChars: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jstring', 'jchar*'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'ReleaseStringChars',
        offset: 166,
    },
    NewStringUTF: {
        jni: { ret: 'jstring', args: ['JNIEnv*', 'char*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'NewStringUTF',
        offset: 167,
    },
    GetStringUTFLength: {
        jni: { ret: 'jsize', args: ['JNIEnv*', 'jstring'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer'],
        name: 'GetStringUTFLength',
        offset: 168,
    },
    GetStringUTFChars: {
        jni: { ret: 'char*', args: ['JNIEnv*', 'jstring', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStringUTFChars',
        offset: 169,
    },
    ReleaseStringUTFChars: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jstring', 'char*'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'ReleaseStringUTFChars',
        offset: 170,
    },
    GetArrayLength: {
        jni: { ret: 'jsize', args: ['JNIEnv*', 'jarray'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer'],
        name: 'GetArrayLength',
        offset: 171,
    },
    NewObjectArray: {
        jni: {
            ret: 'jobjectArray',
            args: ['JNIEnv*', 'jsize', 'jclass', 'jobject'],
        },
        retType: 'pointer',
        argTypes: ['pointer', 'int32', 'pointer', 'pointer'],
        name: 'NewObjectArray',
        offset: 172,
    },
    GetObjectArrayElement: {
        jni: { ret: 'jobject', args: ['JNIEnv*', 'jobjectArray', 'jsize'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'int32'],
        name: 'GetObjectArrayElement',
        offset: 173,
    },
    SetObjectArrayElement: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jobjectArray', 'jsize', 'jobject'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'pointer'],
        name: 'SetObjectArrayElement',
        offset: 174,
    },
    NewBooleanArray: {
        jni: { ret: 'jbooleanArray', args: ['JNIEnv*', 'jsize'] },
        retType: 'pointer',
        argTypes: ['pointer', 'int32'],
        name: 'NewBooleanArray',
        offset: 175,
    },
    NewByteArray: {
        jni: { ret: 'jbyteArray', args: ['JNIEnv*', 'jsize'] },
        retType: 'pointer',
        argTypes: ['pointer', 'int32'],
        name: 'NewByteArray',
        offset: 176,
    },
    NewCharArray: {
        jni: { ret: 'jcharArray', args: ['JNIEnv*', 'jsize'] },
        retType: 'pointer',
        argTypes: ['pointer', 'int32'],
        name: 'NewCharArray',
        offset: 177,
    },
    NewShortArray: {
        jni: { ret: 'jshortArray', args: ['JNIEnv*', 'jsize'] },
        retType: 'pointer',
        argTypes: ['pointer', 'int32'],
        name: 'NewShortArray',
        offset: 178,
    },
    NewIntArray: {
        jni: { ret: 'jintArray', args: ['JNIEnv*', 'jsize'] },
        retType: 'pointer',
        argTypes: ['pointer', 'int32'],
        name: 'NewIntArray',
        offset: 179,
    },
    NewLongArray: {
        jni: { ret: 'jlongArray', args: ['JNIEnv*', 'jsize'] },
        retType: 'pointer',
        argTypes: ['pointer', 'int32'],
        name: 'NewLongArray',
        offset: 180,
    },
    NewFloatArray: {
        jni: { ret: 'jfloatArray', args: ['JNIEnv*', 'jsize'] },
        retType: 'pointer',
        argTypes: ['pointer', 'int32'],
        name: 'NewFloatArray',
        offset: 181,
    },
    NewDoubleArray: {
        jni: { ret: 'jdoubleArray', args: ['JNIEnv*', 'jsize'] },
        retType: 'pointer',
        argTypes: ['pointer', 'int32'],
        name: 'NewDoubleArray',
        offset: 182,
    },
    GetBooleanArrayElements: {
        jni: { ret: 'jboolean*', args: ['JNIEnv*', 'jbooleanArray', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetBooleanArrayElements',
        offset: 183,
    },
    GetByteArrayElements: {
        jni: { ret: 'jbyte*', args: ['JNIEnv*', 'jbyteArray', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetByteArrayElements',
        offset: 184,
    },
    GetCharArrayElements: {
        jni: { ret: 'jchar*', args: ['JNIEnv*', 'jcharArray', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetCharArrayElements',
        offset: 185,
    },
    GetShortArrayElements: {
        jni: { ret: 'jshort*', args: ['JNIEnv*', 'jshortArray', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetShortArrayElements',
        offset: 186,
    },
    GetIntArrayElements: {
        jni: { ret: 'jint*', args: ['JNIEnv*', 'jintArray', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetIntArrayElements',
        offset: 187,
    },
    GetLongArrayElements: {
        jni: { ret: 'jlong*', args: ['JNIEnv*', 'jlongArray', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetLongArrayElements',
        offset: 188,
    },
    GetFloatArrayElements: {
        jni: { ret: 'jfloat*', args: ['JNIEnv*', 'jfloatArray', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetFloatArrayElements',
        offset: 189,
    },
    GetDoubleArrayElements: {
        jni: { ret: 'jdouble*', args: ['JNIEnv*', 'jdoubleArray', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetDoubleArrayElements',
        offset: 190,
    },
    ReleaseBooleanArrayElements: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jbooleanArray', 'jboolean*', 'jint'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'ReleaseBooleanArrayElements',
        offset: 191,
    },
    ReleaseByteArrayElements: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jbyteArray', 'jbyte*', 'jint'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'ReleaseByteArrayElements',
        offset: 192,
    },
    ReleaseCharArrayElements: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jcharArray', 'jchar*', 'jint'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'ReleaseCharArrayElements',
        offset: 193,
    },
    ReleaseShortArrayElements: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jshortArray', 'jshort*', 'jint'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'ReleaseShortArrayElements',
        offset: 194,
    },
    ReleaseIntArrayElements: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jintArray', 'jint*', 'jint'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'ReleaseIntArrayElements',
        offset: 195,
    },
    ReleaseLongArrayElements: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jlongArray', 'jlong*', 'jint'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'ReleaseLongArrayElements',
        offset: 196,
    },
    ReleaseFloatArrayElements: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jfloatArray', 'jfloat*', 'jint'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'ReleaseFloatArrayElements',
        offset: 197,
    },
    ReleaseDoubleArrayElements: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jdoubleArray', 'jdouble*', 'jint'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'ReleaseDoubleArrayElements',
        offset: 198,
    },
    GetBooleanArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jbooleanArray', 'jsize', 'jsize', 'jboolean*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'GetBooleanArrayRegion',
        offset: 199,
    },
    GetByteArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jbyteArray', 'jsize', 'jsize', 'jbyte*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'GetByteArrayRegion',
        offset: 200,
    },
    GetCharArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jcharArray', 'jsize', 'jsize', 'jchar*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'GetCharArrayRegion',
        offset: 201,
    },
    GetShortArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jshortArray', 'jsize', 'jsize', 'jshort*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'GetShortArrayRegion',
        offset: 202,
    },
    GetIntArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jintArray', 'jsize', 'jsize', 'jint*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'GetIntArrayRegion',
        offset: 203,
    },
    GetLongArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jlongArray', 'jsize', 'jsize', 'jlong*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'GetLongArrayRegion',
        offset: 204,
    },
    GetFloatArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jfloatArray', 'jsize', 'jsize', 'jfloat*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'GetFloatArrayRegion',
        offset: 205,
    },
    GetDoubleArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jdoubleArray', 'jsize', 'jsize', 'jdouble*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'GetDoubleArrayRegion',
        offset: 206,
    },
    SetBooleanArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jbooleanArray', 'jsize', 'jsize', 'jboolean*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'SetBooleanArrayRegion',
        offset: 207,
    },
    SetByteArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jbyteArray', 'jsize', 'jsize', 'jbyte*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'SetByteArrayRegion',
        offset: 208,
    },
    SetCharArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jcharArray', 'jsize', 'jsize', 'jchar*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'SetCharArrayRegion',
        offset: 209,
    },
    SetShortArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jshortArray', 'jsize', 'jsize', 'jshort*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'SetShortArrayRegion',
        offset: 210,
    },
    SetIntArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jintArray', 'jsize', 'jsize', 'jint*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'SetIntArrayRegion',
        offset: 211,
    },
    SetLongArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jlongArray', 'jsize', 'jsize', 'jlong*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'SetLongArrayRegion',
        offset: 212,
    },
    SetFloatArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jfloatArray', 'jsize', 'jsize', 'jfloat*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'SetFloatArrayRegion',
        offset: 213,
    },
    SetDoubleArrayRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jdoubleArray', 'jsize', 'jsize', 'jdouble*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'SetDoubleArrayRegion',
        offset: 214,
    },
    RegisterNatives: {
        jni: {
            ret: 'jint',
            args: ['JNIEnv*', 'jclass', 'JNINativeMethod*', 'jint'],
        },
        retType: 'int32',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'RegisterNatives',
        offset: 215,
    },
    UnregisterNatives: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jclass'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer'],
        name: 'UnregisterNatives',
        offset: 216,
    },
    MonitorEnter: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jobject'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer'],
        name: 'MonitorEnter',
        offset: 217,
    },
    MonitorExit: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'jobject'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer'],
        name: 'MonitorExit',
        offset: 218,
    },
    GetJavaVM: {
        jni: { ret: 'jint', args: ['JNIEnv*', 'JavaVM**'] },
        retType: 'int32',
        argTypes: ['pointer', 'pointer'],
        name: 'GetJavaVM',
        offset: 219,
    },
    GetStringRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jstring', 'jsize', 'jsize', 'jchar*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'GetStringRegion',
        offset: 220,
    },
    GetStringUTFRegion: {
        jni: {
            ret: 'void',
            args: ['JNIEnv*', 'jstring', 'jsize', 'jsize', 'char*'],
        },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'int32', 'int32', 'pointer'],
        name: 'GetStringUTFRegion',
        offset: 221,
    },
    GetPrimitiveArrayCritical: {
        jni: { ret: 'void*', args: ['JNIEnv*', 'jarray', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetPrimitiveArrayCritical',
        offset: 222,
    },
    ReleasePrimitiveArrayCritical: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jarray', 'void*', 'jint'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer', 'int32'],
        name: 'ReleasePrimitiveArrayCritical',
        offset: 223,
    },
    GetStringCritical: {
        jni: { ret: 'jchar*', args: ['JNIEnv*', 'jstring', 'jboolean*'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'GetStringCritical',
        offset: 224,
    },
    ReleaseStringCritical: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jstring', 'jchar*'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer', 'pointer'],
        name: 'ReleaseStringCritical',
        offset: 225,
    },
    NewWeakGlobalRef: {
        jni: { ret: 'jweak', args: ['JNIEnv*', 'jobject'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'NewWeakGlobalRef',
        offset: 226,
    },
    DeleteWeakGlobalRef: {
        jni: { ret: 'void', args: ['JNIEnv*', 'jweak'] },
        retType: 'void',
        argTypes: ['pointer', 'pointer'],
        name: 'DeleteWeakGlobalRef',
        offset: 227,
    },
    ExceptionCheck: {
        jni: { ret: 'jboolean', args: ['JNIEnv*'] },
        retType: 'uint8',
        argTypes: ['pointer'],
        name: 'ExceptionCheck',
        offset: 228,
    },
    NewDirectByteBuffer: {
        jni: { ret: 'jobject', args: ['JNIEnv*', 'void*', 'jlong'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer', 'int64'],
        name: 'NewDirectByteBuffer',
        offset: 229,
    },
    GetDirectBufferAddress: {
        jni: { ret: 'void*', args: ['JNIEnv*', 'jobject'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'GetDirectBufferAddress',
        offset: 230,
    },
    GetDirectBufferCapacity: {
        jni: { ret: 'jlong', args: ['JNIEnv*', 'jobject'] },
        retType: 'int64',
        argTypes: ['pointer', 'pointer'],
        name: 'GetDirectBufferCapacity',
        offset: 231,
    },
    GetObjectRefType: {
        jni: { ret: 'jobjectRefType', args: ['JNIEnv*', 'jobject'] },
        retType: 'pointer',
        argTypes: ['pointer', 'pointer'],
        name: 'GetObjectRefType',
        offset: 232,
    },
};
function convertToFrida(type) {
    if (type.includes('*'))
        return 'pointer';
    if (type.endsWith('Array'))
        return 'pointer';
    switch (type) {
        case 'void':
            return 'void';
        case 'jboolean':
            return 'uint8';
        case 'jbyte':
            return 'int8';
        case 'jchar':
            return 'uint16';
        case 'jshort':
            return 'int16';
        case 'jint':
        case 'jsize':
            return 'int32';
        case 'jlong':
            return 'int64';
        case 'jfloat':
            return 'float';
        case 'jdouble':
            return 'double';
        case 'jthrowable':
        case 'jclass':
        case 'jstring':
        case 'jarray':
        case 'jweak':
        case 'jobject':
            return 'pointer';
        case 'jfieldID':
        case 'jmethodID':
        case 'jobjectRefType':
        case 'va_list':
        case '...':
            return 'pointer';
    }
    throw new Error(`convert: illegal type ${type}`);
}

//# sourceMappingURL=jni.js.map

/***/ }),

/***/ "./packages/jnitrace/dist/jniEnvInterceptor.js":
/*!*****************************************************!*\
  !*** ./packages/jnitrace/dist/jniEnvInterceptor.js ***!
  \*****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   JNIEnvInterceptor: () => (/* binding */ JNIEnvInterceptor)
/* harmony export */ });
const UNION_SIZE = 8;
const METHOD_ID_INDEX = 2;
const NON_VIRTUAL_METHOD_ID_INDEX = 3;
class JNIEnvInterceptor {
    #missingIds = new Set();
    getCallMethodArgs(caller, args, method) {
        // instant skip when method is missing
        if (!method)
            return [];
        //
        //// simplified by a lot over previous flow
        //if (caller.endsWith('jmethodIDz')) return [];
        //if (!caller.endsWith('va_list') && !caller.endsWith('jvalue')) {
        //    return null;
        //}
        const isVaList = caller.endsWith('va_list') || caller.endsWith('V');
        const callArgs = [];
        const callArgsPtr = args[args.length - 1];
        if (isVaList)
            this.setUpVaListArgExtract(callArgsPtr);
        for (let i = 0; i < method.jParameterTypes.length; i++) {
            const type = method.jParameterTypes[i];
            let value;
            if (isVaList) {
                const currentPtr = this.extractVaListArgValue(method, i);
                value = this.readValue(currentPtr, type, true);
            }
            else {
                value = this.readValue(callArgsPtr.add(UNION_SIZE * i), type);
            }
            callArgs.push(value);
        }
        if (isVaList)
            this.resetVaListArgExtract();
        return callArgs;
    }
    readValue(currentPtr, type, extend) {
        let value;
        switch (type) {
            case 'boolean': {
                value = currentPtr.readU8();
                break;
            }
            case 'byte': {
                value = currentPtr.readS8();
                break;
            }
            case 'char': {
                value = currentPtr.readU16();
                break;
            }
            case 'short': {
                value = currentPtr.readS16();
                break;
            }
            case 'int': {
                value = currentPtr.readS32();
                break;
            }
            case 'long': {
                value = currentPtr.readS64();
                break;
            }
            case 'double': {
                value = currentPtr.readDouble();
                break;
            }
            case 'float': {
                value = extend === true ? currentPtr.readDouble() : currentPtr.readFloat();
                break;
            }
            // case 'pointer':
            default: {
                value = currentPtr.readPointer();
                break;
            }
        }
        return value;
    }
}

//# sourceMappingURL=jniEnvInterceptor.js.map

/***/ }),

/***/ "./packages/jnitrace/dist/jniEnvInterceptorArm64.js":
/*!**********************************************************!*\
  !*** ./packages/jnitrace/dist/jniEnvInterceptorArm64.js ***!
  \**********************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   JNIEnvInterceptorARM64: () => (/* binding */ JNIEnvInterceptorARM64)
/* harmony export */ });
/* harmony import */ var _jniEnvInterceptor_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./jniEnvInterceptor.js */ "./packages/jnitrace/dist/jniEnvInterceptor.js");

class JNIEnvInterceptorARM64 extends _jniEnvInterceptor_js__WEBPACK_IMPORTED_MODULE_0__.JNIEnvInterceptor {
    stack = NULL;
    stackIndex = 0;
    grTop = NULL;
    vrTop = NULL;
    grOffs = 0;
    grOffsIndex = 0;
    vrOffs = 0;
    vrOffsIndex = 0;
    setUpVaListArgExtract(vaList) {
        const vrStart = 2;
        const grOffset = 3;
        const vrOffset = 4;
        this.stack = vaList.readPointer();
        this.stackIndex = 0;
        this.grTop = vaList.add(Process.pointerSize).readPointer();
        this.vrTop = vaList.add(Process.pointerSize * vrStart).readPointer();
        this.grOffs = vaList.add(Process.pointerSize * grOffset).readS32();
        this.grOffsIndex = 0;
        this.vrOffs = vaList.add(Process.pointerSize * grOffset + vrOffset).readS32();
        this.vrOffsIndex = 0;
    }
    extractVaListArgValue(method, paramId) {
        const MAX_VR_REG_NUM = 8;
        const VR_REG_SIZE = 2;
        const MAX_GR_REG_NUM = 4;
        let currentPtr = NULL;
        if (method.jParameterTypes[paramId] === 'float' || method.jParameterTypes[paramId] === 'double') {
            if (this.vrOffsIndex < MAX_VR_REG_NUM) {
                currentPtr = this.vrTop
                    .add(this.vrOffs)
                    .add(this.vrOffsIndex * Process.pointerSize * VR_REG_SIZE);
                this.vrOffsIndex++;
            }
            else {
                currentPtr = this.stack.add(this.stackIndex * Process.pointerSize);
                this.stackIndex++;
            }
        }
        else {
            if (this.grOffsIndex < MAX_GR_REG_NUM) {
                currentPtr = this.grTop.add(this.grOffs).add(this.grOffsIndex * Process.pointerSize);
                this.grOffsIndex++;
            }
            else {
                currentPtr = this.stack.add(this.stackIndex * Process.pointerSize);
                this.stackIndex++;
            }
        }
        return currentPtr;
    }
    resetVaListArgExtract() {
        this.stack = NULL;
        this.stackIndex = 0;
        this.grTop = NULL;
        this.vrTop = NULL;
        this.grOffs = 0;
        this.grOffsIndex = 0;
        this.vrOffs = 0;
        this.vrOffsIndex = 0;
    }
}

//# sourceMappingURL=jniEnvInterceptorArm64.js.map

/***/ }),

/***/ "./packages/jnitrace/dist/jniInvokeCallback.js":
/*!*****************************************************!*\
  !*** ./packages/jnitrace/dist/jniInvokeCallback.js ***!
  \*****************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   JniInvokeCallbacks: () => (/* binding */ JniInvokeCallbacks),
/* harmony export */   JniInvokeMode: () => (/* reexport safe */ _model_js__WEBPACK_IMPORTED_MODULE_0__.JniInvokeMode)
/* harmony export */ });
/* harmony import */ var _model_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./model.js */ "./packages/jnitrace/dist/model.js");
/* harmony import */ var _tracer_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./tracer.js */ "./packages/jnitrace/dist/tracer.js");


function hasThisRef(mode) {
    switch (mode) {
        case _model_js__WEBPACK_IMPORTED_MODULE_0__.JniInvokeMode.Normal:
        case _model_js__WEBPACK_IMPORTED_MODULE_0__.JniInvokeMode.Nonvirtual:
            return true;
        case _model_js__WEBPACK_IMPORTED_MODULE_0__.JniInvokeMode.Static:
        case _model_js__WEBPACK_IMPORTED_MODULE_0__.JniInvokeMode.Constructor:
            return false;
    }
}
function JniInvokeCallbacks(envWrapper, def, mode, predicate, callback) {
    const name = def.name;
    const cb = {
        onEnter(rawargs) {
            if (!predicate(this))
                return;
            let env;
            let obj;
            let clazz;
            let methodID;
            let args;
            if (mode === _model_js__WEBPACK_IMPORTED_MODULE_0__.JniInvokeMode.Constructor || mode === _model_js__WEBPACK_IMPORTED_MODULE_0__.JniInvokeMode.Static) {
                // const { 0: env, 1: clazz, 2: methodID, 3: args } = rawargs
                env = rawargs[0];
                obj = NULL;
                clazz = rawargs[1];
                methodID = rawargs[2];
                args = rawargs[3];
            }
            else if (mode === _model_js__WEBPACK_IMPORTED_MODULE_0__.JniInvokeMode.Normal) {
                // const { 0: env, 1: obj, 2: methodID, 3: args } = rawargs
                env = rawargs[0];
                obj = rawargs[1];
                clazz = NULL;
                methodID = rawargs[2];
                args = rawargs[3];
            }
            else {
                // const { 0: env, 1: obj, 2: clazz, 3: methodID, 4: args } = rawargs
                env = rawargs[0];
                obj = rawargs[1];
                clazz = rawargs[2];
                methodID = rawargs[3];
                args = rawargs[4];
            }
            const context = {
                ...this,
                env: env,
                obj: obj,
                clazz: clazz,
                methodID: methodID,
                argStruct: args,
                method: null,
                jArgs: null,
            };
            const isStatic = (context.isStatic = mode === _model_js__WEBPACK_IMPORTED_MODULE_0__.JniInvokeMode.Static);
            const method = (context.method = (0,_tracer_js__WEBPACK_IMPORTED_MODULE_1__.resolveMethod)(env, clazz, methodID, isStatic));
            context.jArgs = envWrapper.jniInterceptor.getCallMethodArgs(name, [env, clazz, methodID, args], method);
            this._key = context;
            callback.onEnter?.call(this, context);
        },
        onLeave(retval) {
            if (!predicate(this))
                return;
            const context = this._key;
            callback?.onLeave?.call(this, context, retval);
            try {
                this._key = null;
                context.env = null;
                context.obj = null;
                context.clazz = null;
                context.methodID = null;
                context.argStruct = null;
                context.method = null;
                context.jArgs = null;
            }
            catch (e) { }
        },
    };
    return cb;
}

//# sourceMappingURL=jniInvokeCallback.js.map

/***/ }),

/***/ "./packages/jnitrace/dist/model.js":
/*!*****************************************!*\
  !*** ./packages/jnitrace/dist/model.js ***!
  \*****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Fields: () => (/* binding */ Fields),
/* harmony export */   JNIMethod: () => (/* binding */ JNIMethod),
/* harmony export */   JavaField: () => (/* binding */ JavaField),
/* harmony export */   JavaMethod: () => (/* binding */ JavaMethod),
/* harmony export */   JniInvokeMode: () => (/* binding */ JniInvokeMode),
/* harmony export */   Methods: () => (/* binding */ Methods)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");

var JniInvokeMode;
(function (JniInvokeMode) {
    JniInvokeMode[JniInvokeMode["Normal"] = 0] = "Normal";
    JniInvokeMode[JniInvokeMode["Nonvirtual"] = 1] = "Nonvirtual";
    JniInvokeMode[JniInvokeMode["Static"] = 2] = "Static";
    JniInvokeMode[JniInvokeMode["Constructor"] = 3] = "Constructor";
})(JniInvokeMode || (JniInvokeMode = {}));
class JavaMethod {
    className;
    name;
    parameters;
    returnType;
    isStatic;
    #jParameterTypes = null;
    #jReturnType = null;
    constructor(className, name, parameters, returnType, isStatic) {
        this.className = className;
        this.name = name;
        this.parameters = parameters;
        this.returnType = returnType;
        this.isStatic = isStatic;
    }
    get jParameterTypes() {
        return (this.#jParameterTypes ??= this.parameters.map(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.toPrettyType));
    }
    get jReturnType() {
        return (this.#jReturnType ??= _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.toPrettyType(this.returnType));
    }
    get isVoid() {
        return this.returnType === 'void';
    }
    get isConstructor() {
        return this.name === '<init>' && this.isVoid;
    }
}
class JavaField {
    className;
    name;
    type;
    isStatic;
    #jType = null;
    #jClassName = null;
    constructor(className, name, type, isStatic) {
        this.className = className;
        this.name = name;
        this.type = type;
        this.isStatic = isStatic;
    }
    get jType() {
        return (this.#jType ??= _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.toPrettyType(this.type));
    }
    get jClassName() {
        return (this.#jClassName ??= _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Text.toPrettyType(this.className));
    }
}
const Methods = {
    storage: new Map(),
    staticStorage: new Map(),
    get(jMethodId, isStatic) {
        return (isStatic ? this.staticStorage : this.storage)[`${jMethodId}`] ?? null;
    },
    set(jMethodId, isStatic, method) {
        return (method.isStatic ? this.staticStorage : this.storage)[`${jMethodId}`] = method;
    },
};
const Fields = {
    storage: new Map(),
    staticStorage: new Map(),
    get(jFieldId, isStatic) {
        const key = typeof jFieldId === 'number' ? jFieldId : jFieldId.toInt32();
        return (isStatic ? this.staticStorage : this.storage)[key] ?? null;
    },
    set(jFieldId, isStatic, method) {
        const key = typeof jFieldId === 'number' ? jFieldId : jFieldId.toInt32();
        return (method.isStatic ? this.staticStorage : this.storage)[key] = method;
    },
};
class JNIMethod {
    name;
    address;
    constructor(name, address) {
        this.name = name;
        this.address = address;
    }
}

//# sourceMappingURL=model.js.map

/***/ }),

/***/ "./packages/jnitrace/dist/tracer.js":
/*!******************************************!*\
  !*** ./packages/jnitrace/dist/tracer.js ***!
  \******************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   fastpathMethod: () => (/* binding */ fastpathMethod),
/* harmony export */   resolveMethod: () => (/* binding */ resolveMethod),
/* harmony export */   signatureToPrettyTypes: () => (/* binding */ signatureToPrettyTypes)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _envWrapper_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./envWrapper.js */ "./packages/jnitrace/dist/envWrapper.js");
/* harmony import */ var _jni_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./jni.js */ "./packages/jnitrace/dist/jni.js");
/* harmony import */ var _model_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./model.js */ "./packages/jnitrace/dist/model.js");




let FindClass = null;
let ToReflectedMethod = null;
let getDeclaringClassDesc = null;
const PrimitiveTypes = {
    Z: 'boolean',
    B: 'byte',
    C: 'char',
    D: 'double',
    F: 'float',
    I: 'int',
    J: 'long',
    S: 'short',
    V: 'void',
};
function resolveMethod(env, clazz, methodID, isStatic) {
    const method = _model_js__WEBPACK_IMPORTED_MODULE_3__.Methods.get(methodID, isStatic);
    if (method)
        return method;
    if (FindClass === null && env)
        FindClass = (0,_envWrapper_js__WEBPACK_IMPORTED_MODULE_1__.asFunction)(env, _jni_js__WEBPACK_IMPORTED_MODULE_2__.JNI.FindClass);
    if (ToReflectedMethod === null && env)
        ToReflectedMethod = (0,_envWrapper_js__WEBPACK_IMPORTED_MODULE_1__.asFunction)(env, _jni_js__WEBPACK_IMPORTED_MODULE_2__.JNI.ToReflectedMethod);
    if (ToReflectedMethod && clazz && methodID && `${clazz}` !== '0x0' && `${methodID}` !== '0x0') {
        const jniMethod = ToReflectedMethod(env, clazz, methodID, isStatic ? 1 : 0);
        const javaExecutable = Java.cast(jniMethod, _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Executable);
        let name = javaExecutable.getName();
        const declaringClass = javaExecutable.getDeclaringClass();
        const parameterTypes = javaExecutable.getParameterTypes();
        const declaringClassType = declaringClass.getTypeName();
        let returnTypeName = 'void';
        if (javaExecutable.$className === _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.Method) {
            const javaMethod = Java.cast(javaExecutable, _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Classes.Method);
            const returnType = javaMethod.getReturnType();
            returnTypeName = returnType.getTypeName();
            returnType.$dispose();
        }
        else if (javaExecutable.$className === _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.ClassesString.Constructor) {
            name = '<init>';
            returnTypeName = declaringClassType;
        }
        const method = new _model_js__WEBPACK_IMPORTED_MODULE_3__.JavaMethod(declaringClassType, name, parameterTypes.map((x) => x.getTypeName()), returnTypeName, isStatic);
        // declaringClass.$dispose();
        // for (const parameterType of parameterTypes) {
        //     parameterType.$dispose();
        // }
        return _model_js__WEBPACK_IMPORTED_MODULE_3__.Methods.set(methodID, isStatic, method);
    }
    if (getDeclaringClassDesc === null) {
        // const getDeclaringClassDescSym = Process.getModuleByName('libart.so')
        //     .enumerateSymbols()
        //     .filter((x) => x.name.includes('DeclaringClassDesc'))[0];
        const getDeclaringClassDescSym = new ApiResolver('module')?.enumerateMatches('exports:libart.so!*DeclaringClassDesc*')?.[0];
        if (!getDeclaringClassDescSym)
            return null;
        getDeclaringClassDesc = new NativeFunction(getDeclaringClassDescSym.address, 'pointer', ['pointer'], {
            exceptions: 'propagate',
        });
    }
    const thisSigPtr = getDeclaringClassDesc(methodID);
    let thisSig = thisSigPtr.readCString();
    thisSig =
        thisSig?.startsWith('L') && thisSig.endsWith(';')
            ? thisSig.substring(1, thisSig.length - 1)
            : thisSig;
    thisSig = thisSig?.replaceAll('/', '.') ?? thisSig;
    const cls = thisSig ? (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.findClass)(thisSig) : null;
    if (!thisSig || !cls)
        return null;
    let matched = null;
    (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.enumerateMembers)(cls, {
        onMatchMethod(clazz, member) {
            const method = clazz[member];
            for (const overload of method.overloads) {
                if (`${overload.handle}` === `${methodID}`) {
                    matched = overload;
                    return _model_js__WEBPACK_IMPORTED_MODULE_3__.Methods.set(methodID, isStatic, new _model_js__WEBPACK_IMPORTED_MODULE_3__.JavaMethod(thisSig ?? '', method.methodName, overload.argumentTypes.map((x) => x.className ?? x.name), overload.returnType.className ?? overload.returnType.name, isStatic));
                }
            }
        },
    });
    return null;
}
function signatureToPrettyTypes(sig) {
    let isArray = false;
    const arr = [];
    const addType = (raw) => {
        if (raw.length === 1) {
            raw = PrimitiveTypes[raw];
        }
        else {
            raw = raw.replaceAll('/', '.');
        }
        raw = isArray ? `${raw}[]` : raw;
        isArray = false;
        arr.push(raw);
    };
    let isOpen = null;
    for (let i = 0; i < sig.length; i++) {
        const c = sig.charAt(i);
        if (c === '[') {
            isArray = true;
            continue;
        }
        if (!isOpen && c === 'L') {
            isOpen = i + 1;
            continue;
        }
        if (isOpen && c === ';') {
            addType(sig.substring(isOpen, i));
            isOpen = null;
            continue;
        }
        if (!isOpen && c in PrimitiveTypes) {
            addType(c);
        }
    }
    return arr;
}
function fastpathMethod(methodId, className, name, sig, isStatic) {
    const arr = signatureToPrettyTypes(sig);
    const ret = arr.pop() ?? 'void';
    const method = new _model_js__WEBPACK_IMPORTED_MODULE_3__.JavaMethod(className, name, arr, ret, isStatic);
    return global.set(methodId, method);
}
let thunkPage = null;
let thunkOffset = ptr(0x0);
function makeThunk(size, write) {
    thunkPage ??= Memory.alloc(Process.pageSize);
    const thunk = thunkPage.add(thunkOffset);
    const arch = Process.arch;
    const Writer = Arm64Writer;
    Memory.patchCode(thunk, size, (code) => {
        const writer = new Writer(code, { pc: thunk });
        write(writer);
        writer.flush();
        if (writer.offset > size) {
            throw new Error(`Wrote ${writer.offset}, exceeding maximum of ${size}`);
        }
    });
    thunkOffset.add(size);
    return arch === 'arm' ? thunk.or(1) : thunk;
}
function makeCxxMethodWrapperReturningStdStringByValue(impl, argTypes) {
    const thunk = makeThunk(32, (writer) => {
        writer.putMovRegReg('x8', 'x0');
        argTypes.forEach((t, i) => {
            writer.putMovRegReg(`x${i}`, `x${i + 1}`);
        });
        writer.putLdrRegAddress('x7', impl);
        writer.putBrReg('x7');
    });
    const argumentsTypes = ['pointer'] + argTypes;
    const invokeThunk = new NativeFunction(thunk, 'void', argumentsTypes);
    const wrapper = (...args) => {
        //@ts-ignore
        invokeThunk(...args);
    };
    wrapper.handle = thunk;
    wrapper.impl = impl;
    return wrapper;
}
function makeCxxMethodWrapperReturningPointerByValueGeneric(address, argTypes) {
    return new NativeFunction(address, 'pointer', argTypes, {
        exceptions: 'propagate',
    });
}
function atleasttry() {
    // resolveMethod(Classes.String.concat.handle, false);
    // const base = Java.vm.getEnv().handle.readPointer();
    // const GetMethodID = asFunction(base, 'GetMethodID');
    // console.warn('GetMethodID', GetMethodID);
    // Interceptor.attach(GetMethodID, {
    //     onEnter(args) {},
    //     onLeave(retval) {
    //         //console.log('on methodId', retval);
    //     },
    // });
    // const RegisterNatives = asFunction(base, 'RegisterNatives');
    // console.warn('RegisterNatives', RegisterNatives);
    // Interceptor.attach(RegisterNatives, {
    //     onEnter(args) {},
    //     onLeave(retval) {
    //         console.log('on RegisterNatives', retval);
    //     },
    // });
    // const FindClass = asFunction(base, 'FindClass');
    // const ToReflectedMethod = asFunction(base, 'ToReflectedMethod');
    // // methodId -> char *
    // const getDeclaringClassDesc = Process.getModuleByName('libart.so')
    //     .enumerateSymbols()
    //     .filter((x) => x.name.includes('DeclaringClassDesc'))[0];
    // const decClassDesc = makeCxxMethodWrapperReturningPointerByValueGeneric(getDeclaringClassDesc.address, ['pointer']);
    // // // methodId -> char *
    // const getSignatureSym = Process.getModuleByName('libart.so')
    //     .enumerateSymbols()
    //     .filter((x) => x.name.includes('_ZN3art9ArtMethod12GetSignatureEv'))[0];
    // const getSignature = makeCxxMethodWrapperReturningPointerByValueGeneric(getSignatureSym.address, ['pointer']);
    // const signatureToStringSym = Process.getModuleByName('libart.so')
    //     .enumerateSymbols()
    //     .filter((x) => x.name.includes('_ZNK3art9Signature8ToStringEv'))[0];
    // const sigToStr = makeCxxMethodWrapperReturningStdStringByValue(signatureToStringSym.address, ['pointer']);
    // (rpc as any).decClassDesc = decClassDesc;
    // (rpc as any).getSignature = getSignature;
    // (rpc as any).prettyMethod = prettyMethod;
    // (rpc as any).sigToStr = sigToStr;
    const cleanup = (str) => {
        str = str.startsWith('L') && str.endsWith(';') ? str.substring(1, str.length - 1) : str;
        return str.replaceAll('/', '.');
    };
    // console.warn('begin:', (w = Java.use('java.lang.String')));
    // console.warn('begin:', (w = w.substring._o[1]));
    // console.warn('begin:', (h = w.handle));
    // console.warn('begin:', (w = (decClassDesc as any)(h)));
    // console.warn('begin:', (w = w.readCString()));
    // console.warn('begin:', (w = Memory.allocUtf8String(cleanup(w))));
    // console.warn('begin:', w.readCString());
    // console.warn('begin:', (w = (FindClass as any)(Java.vm.getEnv(), w)));
    // console.warn('begin:', (w = (ToReflectedMethod as any)(Java.vm.getEnv(), w, h, 0)));
    // console.warn('begin:', (w = (ToReflectedMethod as any)(Java.vm.getEnv(), w, h, 1)));
    // console.warn('begin:', (w = Java.cast(w, Java.use('java.lang.reflect.Method'))))_;
    // console.warn('begin:', w = (getSignature as any)(h))
    // console.warn('begin:', w = (sigToStr as any)(w))
}

//# sourceMappingURL=tracer.js.map

/***/ }),

/***/ "./packages/logging/dist/autocolor.js":
/*!********************************************!*\
  !*** ./packages/logging/dist/autocolor.js ***!
  \********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   getColor: () => (/* binding */ getColor)
/* harmony export */ });
/* harmony import */ var _color_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./color.js */ "./packages/logging/dist/color.js");

const colors = (0,_color_js__WEBPACK_IMPORTED_MODULE_0__.use)();
const array = [
    colors.red,
    colors.green,
    colors.yellow,
    colors.blue,
    colors.magenta,
    colors.cyan,
    colors.gray,
];
const colormap = new Map();
colormap.set('encrypt', colors.blueBright);
colormap.set('decrypt', colors.redBright);
colormap.set('strstr', colors.blueBright);
colormap.set('strcasestr', colors.blueBright);
function getColor(tag) {
    let roll = colormap.get(tag);
    if (roll)
        return roll;
    const hash = hashCode(tag);
    roll = array[Math.abs(hash % array.length)];
    colormap.set(tag, roll);
    return roll;
}
function hashCode(str) {
    let hash = 0;
    let i;
    let chr;
    if (str.length === 0)
        return hash;
    for (i = 0; i < str.length; i++) {
        chr = str.charCodeAt(i);
        hash = (hash << 5) - hash + chr;
        hash |= 0;
    }
    return hash;
}

//# sourceMappingURL=autocolor.js.map

/***/ }),

/***/ "./packages/logging/dist/color.js":
/*!****************************************!*\
  !*** ./packages/logging/dist/color.js ***!
  \****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   args: () => (/* binding */ args),
/* harmony export */   bracket: () => (/* binding */ bracket),
/* harmony export */   char: () => (/* binding */ char),
/* harmony export */   className: () => (/* binding */ className),
/* harmony export */   field: () => (/* binding */ field),
/* harmony export */   keyword: () => (/* binding */ keyword),
/* harmony export */   method: () => (/* binding */ method),
/* harmony export */   number: () => (/* binding */ number),
/* harmony export */   string: () => (/* binding */ string),
/* harmony export */   url: () => (/* binding */ url),
/* harmony export */   use: () => (/* binding */ use)
/* harmony export */ });
/* harmony import */ var colorette__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! colorette */ "./node_modules/colorette/index.js");

const Colors = Object.assign((0,colorette__WEBPACK_IMPORTED_MODULE_0__.createColors)({ useColor: true }), {
    orange: (text) => `\x1b[38;2;250;179;135m${text}\x1b[39m`,
    lavender: (text) => `\x1b[38;2;180;190;254m${text}\x1b[39m`,
});
const { cyan, green, gray, blue, underline, yellow, magenta, orange } = use();
function use() {
    return Colors;
}
const className = (className) => {
    if (!className)
        return className;
    const splits = `${className}`.split('.');
    return splits.map(cyan).join('.');
};
const method = (methodName) => {
    if (!methodName)
        return methodName;
    return green(`${methodName}`);
};
const field = (fieldName) => {
    if (!fieldName)
        return fieldName;
    return magenta(`${fieldName}`);
};
const keyword = (value) => {
    return gray(`${value}`);
};
const args = (args) => {
    if (args.length === 0)
        return '';
    const joinBy =  true ? ', \n' : 0;
    const joined = args.map((arg) => `    ${arg}`).join(joinBy);
    return `\n${joined}\n`;
};
const bracket = (char) => {
    if (!char)
        return char;
    return blue(`${char}`);
};
const url = (url) => {
    return underline(`${url}`);
};
const string = (string) => {
    return yellow(`"${string}"`);
};
const char = (char) => {
    return yellow(`'${string}'`);
};
const number = (number) => {
    return magenta(`${number}`);
};

//# sourceMappingURL=color.js.map

/***/ }),

/***/ "./packages/logging/dist/index.js":
/*!****************************************!*\
  !*** ./packages/logging/dist/index.js ***!
  \****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Color: () => (/* reexport module object */ _color_js__WEBPACK_IMPORTED_MODULE_2__),
/* harmony export */   error: () => (/* binding */ error),
/* harmony export */   log: () => (/* binding */ log),
/* harmony export */   logger: () => (/* binding */ logger),
/* harmony export */   subLogger: () => (/* binding */ subLogger)
/* harmony export */ });
/* harmony import */ var pino__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! pino */ "./node_modules/pino/browser.js");
/* harmony import */ var _autocolor_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./autocolor.js */ "./packages/logging/dist/autocolor.js");
/* harmony import */ var _color_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./color.js */ "./packages/logging/dist/color.js");



const logger = (0,pino__WEBPACK_IMPORTED_MODULE_0__.pino)({
    browser: {
        write: (o) => {
            const msg = o['msg'], level = o['level'], tag = o['tag'], id = o['id'];
            let print = `${msg}`;
            if (tag) {
                const color = (0,_autocolor_js__WEBPACK_IMPORTED_MODULE_1__.getColor)(tag);
                const ctag = `[${color(`${tag}`)}${id ? `:${id}` : ''}] `;
                print = `${msg}`.replaceAll(/^/g, ctag);
            }
            if (print)
                console.log(print);
        },
    },
});
function log(message, ...optionalParams) {
    logger.info(message, ...optionalParams);
}
function error(message) {
    logger.error(message);
}
function subLogger(tag) {
    return logger.child({ tag: tag });
}

//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./packages/native/dist/files.js":
/*!***************************************!*\
  !*** ./packages/native/dist/files.js ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   hookAccess: () => (/* binding */ hookAccess),
/* harmony export */   hookFopen: () => (/* binding */ hookFopen),
/* harmony export */   hookOpen: () => (/* binding */ hookOpen),
/* harmony export */   hookOpendir: () => (/* binding */ hookOpendir),
/* harmony export */   hookReadlink: () => (/* binding */ hookReadlink),
/* harmony export */   hookRemove: () => (/* binding */ hookRemove),
/* harmony export */   hookStat: () => (/* binding */ hookStat)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _index_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./index.js */ "./packages/native/dist/index.js");
/* harmony import */ var _utils_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./utils.js */ "./packages/native/dist/utils.js");




// import { constants } from 'frida-fs';
const [R_OK, W_OK, X_OK] = [1, 2, 4];
const { bold, dim, green, red, gray, bgRed } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.use();
function ofResultColor(path, ret) {
    if (typeof path === 'number')
        path = `<fd:${path}>`;
    if (typeof path === 'object')
        path = path.readCString() ?? '';
    const isOk = ret !== -1 && ret !== ptr(-1);
    const uri = isOk ? dim(green(`${path}`)) : dim(red(`${path}`));
    return uri;
}
function hookAccess(predicate) {
    const empty = dim('-');
    function log(path, mode, ret, tag) {
        const isOk = ret !== -1;
        mode ??= 0;
        const mask = `?${mode & R_OK ? 'R' : empty}${mode & W_OK ? 'W' : empty}${mode & X_OK ? 'X' : empty}`;
        const uri = isOk ? dim(green(`${path}`)) : dim(red(`${path}`));
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: tag }, `${uri} ${mask} ${DebugSymbol.fromAddress(this.returnAddress)}`);
    }
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.access, new NativeCallback(function (pathname, mode) {
        let ret;
        if (predicate(this.returnAddress)) {
            const path = pathname.readCString();
            if (path?.endsWith('/su') || path?.startsWith('/system/bin/ls')) {
                // Memory.proect(pathname, Process.pageSize, 'rw-');
                pathname = Memory.allocUtf8String('/nya');
            }
            ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.access(pathname, mode);
            log.call(this, pathname.readCString(), mode, ret, 'access');
        }
        return (ret ??= _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.access(pathname, mode));
    }, 'int', ['pointer', 'int']));
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.faccessat, new NativeCallback(function (fd, path, mode, flag) {
        if (predicate(this.returnAddress)) {
            const strPath = path.readCString();
            const iPath = `${strPath}`.toLowerCase();
            if (iPath.endsWith('bin/su') || iPath.includes('termux') || iPath.includes('magisk') || iPath.includes('supersu')) {
                return -1;
            }
            // const regExp = /^\/apex\/com.android.conscrypt\/cacerts\/[a-f0-9]{8}\.0/;
            // if (regExp.test(strPath ?? '')) {
            //     Memory.protect(path, Process.pageSize, 'rw-');
            //     path.writeUtf8String('/data/local/tmp/9a5ba575.0');
            // }
            const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.faccessat(fd, path, mode, flag);
            log.call(this, strPath, mode, ret, 'faccessat');
            return ret;
        }
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.faccessat(fd, path, mode, flag);
        return ret;
    }, 'int', ['int', 'pointer', 'int', 'int']));
}
function hookOpen(predicate, fn) {
    function log(uri, flags, mode, errno, key) {
        const isOk = errno === 0;
        const errstr = !isOk ? ` ${gray(dim(`{${errno}: "${_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.strerror(errno).readCString()}}"`))}` : '';
        const struri = !isOk ? red(gray(`${uri}`)) : gray(`${uri}`);
        const flagsEnum = flags ? `0b${flags?.toString(2).padStart(16, '0')}` : null;
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: key }, `${struri} flags: ${flagsEnum}, ${mode ? `mode: ${mode} ${errstr}` : ''} ${DebugSymbol.fromAddress(this.returnAddress)}`);
    }
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.open, new NativeCallback(function (pathname, flags) {
        if (predicate(this.returnAddress)) {
            const pathnameStr = pathname.readCString();
            const replaceStr = fn?.call(this, pathnameStr);
            const pathArg = replaceStr ? Memory.allocUtf8String(replaceStr) : pathname;
            const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.open(pathArg, flags);
            log.call(this, replaceStr ? `${pathnameStr} -> ${replaceStr}` : pathnameStr, flags, null, 
            //@ts-ignore
            ret.errno, 'open');
            return ret.value;
        }
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.open(pathname, flags);
        return ret.value;
    }, 'int', ['pointer', 'int']));
    // Interceptor.attach(Libc.open, {
    //     onEnter(args) {
    //         this.pathname = args[0];
    //         this.flags = args[1].toInt32();
    //     },
    //     onLeave(retval) {
    //         if (predicate(this.returnAddress)) {
    //             log.call(this, this.pathname.readCString(), this.flags, retval.toInt32(), 0, 'open');
    //         }
    //     },
    // });
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.creat, new NativeCallback(function (pathname, mode) {
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.creat(pathname, mode);
        if (predicate(this.returnAddress)) {
            log.call(this, pathname.readCString(), null, mode, ret, 'creat');
        }
        return ret;
    }, 'int', ['pointer', 'int']));
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.openat, new NativeCallback(function (dirfd, pathname, flags, ...any) {
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.openat(dirfd, pathname, flags, ...any);
        if (predicate(this.returnAddress)) {
            log.call(this, pathname.readCString(), flags, null, ret, 'openat');
        }
        return ret;
    }, 'int', ['int', 'pointer', 'int']));
}
function hookFopen(predicate, statfd = false, fn) {
    function log(uri, mode, stream, errno, key) {
        const isFd = typeof uri === 'number';
        let strpath = isFd ? `<fd:${uri}>` : `${uri}`;
        const isOk = `${errno}` === '0';
        if (isFd && statfd) {
            const infs = (0,_utils_js__WEBPACK_IMPORTED_MODULE_3__.readFdPath)(uri);
            strpath += ` -> "${infs}"`;
        }
        const struri = isOk ? dim(`${strpath}`) : dim(red(`${strpath}`));
        const strmod = `${mode}`.padEnd(2);
        const errstr = !isOk ? ` ${gray(dim(`{${errno}: "${_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.strerror(errno).readCString()}}"`))}` : '';
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: key }, `${struri} ${strmod} ${!stream ? '' : `->${stream}`}${errstr}`);
    }
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fopen, new NativeCallback(function (pathname, mode) {
        if (predicate(this.returnAddress)) {
            const pathnameStr = pathname.readCString();
            const replaceStr = fn?.(pathnameStr);
            const pathArg = replaceStr ? Memory.allocUtf8String(replaceStr) : pathname;
            const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fopen(pathArg, mode);
            log.call(this, replaceStr ? `${pathnameStr} -> ${replaceStr}` : pathnameStr, mode.readCString(), null, 
            //@ts-ignore
            ret.errno, 'fopen');
            return ret.value;
        }
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fopen(pathname, mode);
        return ret.value;
    }, 'pointer', ['pointer', 'pointer']));
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fdopen, new NativeCallback(function (fd, mode) {
        const [ret, errno] = (0,_index_js__WEBPACK_IMPORTED_MODULE_2__.unbox)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fdopen(fd, mode));
        if (predicate(this.returnAddress)) {
            log.call(this, fd, mode.readCString(), null, errno, 'fdopen');
        }
        return ret;
    }, 'pointer', ['int', 'pointer']));
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.freopen, new NativeCallback(function (pathname, mode, stream) {
        const [ret, errno] = (0,_index_js__WEBPACK_IMPORTED_MODULE_2__.unbox)(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.freopen(pathname, mode, stream));
        if (predicate(this.returnAddress)) {
            log.call(this, pathname.readCString(), mode.readCString(), stream, errno, 'freopen');
        }
        return ret;
    }, 'pointer', ['pointer', 'pointer', 'pointer']));
}
function hookOpendir(predicate) {
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.opendir, new NativeCallback(function (pathname) {
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.opendir(pathname);
        if (predicate(this.returnAddress)) {
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'opendir' }, ofResultColor(pathname, ret));
        }
        return ret;
    }, 'pointer', ['pointer']));
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fdopendir, new NativeCallback(function (fd) {
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fdopendir(fd);
        if (predicate(this.returnAddress)) {
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'fdopendir' }, ofResultColor(fd, ret));
        }
        return ret;
    }, 'pointer', ['int']));
}
function hookStat(predicate) {
    function log(uri, statbuf, ret, tag) {
        const isFd = typeof uri === 'number';
        const strpath = isFd ? `<fd:${uri}>` : `${uri}`;
        const isOk = ret === 0;
        let strmsg = isOk ? dim(`${strpath}`) : dim(red(`${strpath}`));
        if (isFd) {
            const target = (0,_utils_js__WEBPACK_IMPORTED_MODULE_3__.readFdPath)(uri);
            strmsg += ` -> "${gray(`${target}`)}"`;
        }
        strmsg += ` @${statbuf}`;
        // const stat = Struct.Stat.stat(statbuf);
        // strmsg += ` ${JSON.stringify(Struct.toObject(stat))}`
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: tag }, strmsg);
    }
    const array = ['stat', 'lstat'];
    for (const key of array) {
        const func = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc[key];
        Interceptor.replace(func, new NativeCallback(function (pathname, statbuf) {
            const ret = func(pathname, statbuf);
            if (predicate(this.returnAddress)) {
                log.call(this, pathname.readCString(), statbuf, ret, key);
            }
            return ret;
        }, 'int', ['pointer', 'pointer']));
    }
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fstat, new NativeCallback(function (fd, statbuf) {
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fstat(fd, statbuf);
        if (predicate(this.returnAddress)) {
            log.call(this, fd, statbuf, ret, 'fstat');
        }
        return ret;
    }, 'int', ['int', 'pointer']));
}
function hookRemove(predicate, ignore) {
    const array = ['remove', 'unlink'];
    for (const key of array) {
        const func = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc[key];
        Interceptor.replace(func, new NativeCallback(function (pathname) {
            let ret;
            if (predicate(this.returnAddress)) {
                const strpath = pathname.readCString();
                const replace = ignore?.(`${pathname}`) === true;
                const fmt = replace ? bgRed : String;
                _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: key }, `${fmt(bold(gray(`${strpath}`)))}` + ` ${DebugSymbol.fromAddress(this.returnAddress)}`);
            }
            return (ret ??= func(pathname));
        }, 'int', ['pointer']));
    }
}
function hookReadlink(predicate) {
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.readlink, new NativeCallback(function (pathname, buf, bufsize) {
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.readlink(pathname, buf, bufsize);
        if (predicate(this.returnAddress)) {
            const lnstring = pathname.readCString();
            const rlstring = buf.readCString(ret);
            const frlstring = rlstring; // .replace(/�.*$/g, '')
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'readlink' }, `"${lnstring}" -> "${frlstring}"`);
        }
        return ret;
    }, 'int', ['pointer', 'pointer', 'int']));
}

//# sourceMappingURL=files.js.map

/***/ }),

/***/ "./packages/native/dist/hooah.js":
/*!***************************************!*\
  !*** ./packages/native/dist/hooah.js ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   HooahTrace: () => (/* binding */ HooahTrace)
/* harmony export */ });
/* harmony import */ var _inject_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./inject.js */ "./packages/native/dist/inject.js");

var Utils;
(function (Utils) {
    const callMnemonics = ['call', 'bl', 'blx', 'blr', 'bx'];
    Utils.insertAt = (str, sub, pos) => `${str.slice(0, pos)}${sub}${str.slice(pos)}`;
    function ba2hex(b) {
        const uint8arr = new Uint8Array(b);
        if (!uint8arr) {
            return '';
        }
        let hexStr = '';
        for (let i = 0; i < uint8arr.length; i++) {
            let hex = (uint8arr[i] & 0xff).toString(16);
            hex = hex.length === 1 ? `0${hex}` : hex;
            hexStr += hex;
        }
        return hexStr;
    }
    Utils.ba2hex = ba2hex;
    function getSpacer(space) {
        if (space < 0)
            return '';
        return ' '.repeat(space);
    }
    Utils.getSpacer = getSpacer;
    function isCallInstruction(instruction) {
        return callMnemonics.indexOf(instruction.mnemonic) >= 0;
    }
    Utils.isCallInstruction = isCallInstruction;
    function isJumpInstruction(instruction) {
        return instruction.groups.indexOf('jump') >= 0 || instruction.groups.indexOf('ret') >= 0;
    }
    Utils.isJumpInstruction = isJumpInstruction;
    function isRetInstruction(instuction) {
        return instuction.groups.indexOf('return') >= 0;
    }
    Utils.isRetInstruction = isRetInstruction;
})(Utils || (Utils = {}));
var Color;
(function (Color) {
    const _red = '\x1b[0;31m';
    const _green = '\x1b[0;32m';
    const _yellow = '\x1b[0;33m';
    const _blue = '\x1b[0;34m';
    const _pink = '\x1b[0;35m';
    const _cyan = '\x1b[0;36m';
    const _bold = '\x1b[0;1m';
    const _highlight = '\x1b[0;3m';
    const _highlight_off = '\x1b[0;23m';
    const _resetColor = '\x1b[0m';
    function applyColorFilters(text) {
        text = text.toString();
        text = text.replace(/(\W|^)([a-z]{1,4}\d{0,2})(\W|$)/gm, `$1${colorify('$2', 'blue')}$3`);
        text = text.replace(/(0x[0123456789abcdef]+)/gm, colorify('$1', 'red'));
        text = text.replace(/#(\d+)/gm, `#${colorify('$1', 'red')}`);
        return text;
    }
    Color.applyColorFilters = applyColorFilters;
    function colorify(what, pat) {
        if (pat === 'filter') {
            return applyColorFilters(what);
        }
        let ret = '';
        if (pat.indexOf('red') >= 0) {
            ret += _red;
        }
        else if (pat.indexOf('green') >= 0) {
            ret += _green;
        }
        else if (pat.indexOf('yellow') >= 0) {
            ret += _yellow;
        }
        else if (pat.indexOf('blue') >= 0) {
            ret += _blue;
        }
        else if (pat.indexOf('pink') >= 0) {
            ret += _pink;
        }
        else if (pat.indexOf('cyan') >= 0) {
            ret += _cyan;
        }
        if (pat.indexOf('bold') >= 0) {
            ret += _bold;
        }
        else if (pat.indexOf('highlight') >= 0) {
            ret += _highlight;
        }
        ret += what;
        if (pat.indexOf('highlight') >= 0) {
            ret += _highlight_off;
        }
        ret += _resetColor;
        return ret;
    }
    Color.colorify = colorify;
})(Color || (Color = {}));
var HooahTrace;
(function (HooahTrace) {
    const getSpacer = Utils.getSpacer;
    const treeTrace = [];
    let targetTid = 0;
    let onInstructionCallback = null;
    const moduleMap = new ModuleMap();
    let filtersModuleMap = null;
    const currentExecutionBlockStackRegisters = [];
    const currentExecutionBlock = [];
    let currentBlockStartWidth = 0;
    let currentBlockMaxWidth = 0;
    let hitRetInstruction = false;
    let sessionPrintBlocks = true;
    let sessionPrintOptions;
    let sessionPrevSepCount = 0;
    function trace(params = {}, callback = undefined) {
        if (targetTid > 0) {
            console.log(`Hooah is already tracing thread: ${targetTid}`);
            return 1;
        }
        if (targetTid > 0) {
            console.log(`Hooah is already tracing thread: ${targetTid}`);
            return;
        }
        const { printBlocks = true, count = -1, filterModules = [], instructions = [], printOptions = {}, } = params;
        sessionPrintBlocks = printBlocks;
        sessionPrintOptions = printOptions;
        if (sessionPrintOptions.treeSpaces && sessionPrintOptions.treeSpaces < 4) {
            sessionPrintOptions.treeSpaces = 4;
        }
        targetTid = Process.getCurrentThreadId();
        if (callback) {
            onInstructionCallback = callback;
        }
        else {
            onInstructionCallback = null;
        }
        moduleMap.update();
        filtersModuleMap = new ModuleMap((module) => {
            // do not follow frida agent
            if (module.name.includes('frida-agent') || module.name.includes('hluda-agent')) {
                return true;
            }
            let found = false;
            for (const filter of filterModules) {
                if (module.name.indexOf(filter) >= 0) {
                    found = true;
                }
            }
            return found;
        });
        _inject_js__WEBPACK_IMPORTED_MODULE_0__.Inject.afterInitArray(() => {
            moduleMap.update();
            if (filtersModuleMap) {
                filtersModuleMap.update();
            }
        });
        let instructionsCount = 0;
        let startAddress = NULL;
        Stalker.follow(targetTid, {
            transform: (iterator) => {
                let instruction;
                let moduleFilterLocker = false;
                while ((instruction = iterator.next()) !== null) {
                    currentExecutionBlockStackRegisters.length = 0;
                    if (moduleFilterLocker) {
                        iterator.keep();
                        continue;
                    }
                    if (filtersModuleMap?.has(instruction?.address)) {
                        moduleFilterLocker = true;
                    }
                    if (!moduleFilterLocker) {
                        // basically skip the first block of code (from frida)
                        if (startAddress.compare(NULL) === 0) {
                            startAddress = instruction.address;
                            moduleFilterLocker = true;
                        }
                        else {
                            if (instructions.length > 0 && instructions.indexOf(instruction.mnemonic) < 0) {
                                iterator.keep();
                                continue;
                            }
                            iterator.putCallout(onHitInstruction);
                        }
                    }
                    if (count > 0) {
                        instructionsCount++;
                        if (instructionsCount === count) {
                            stop();
                        }
                    }
                    iterator.keep();
                }
            },
        });
        return 0;
    }
    HooahTrace.trace = trace;
    function stop() {
        Stalker.unfollow(targetTid);
        filtersModuleMap = null;
        onInstructionCallback = null;
        treeTrace.length = 0;
        targetTid = 0;
        currentExecutionBlockStackRegisters.length = 0;
        currentExecutionBlock.length = 0;
        currentBlockMaxWidth = 0;
        sessionPrevSepCount = 0;
    }
    HooahTrace.stop = stop;
    function onHitInstruction(context) {
        const address = context.pc;
        const instruction = Instruction.parse(address);
        const treeTraceLength = treeTrace.length;
        if (onInstructionCallback !== null) {
            if (hitRetInstruction) {
                hitRetInstruction = false;
                if (treeTraceLength > 0) {
                    treeTrace.pop();
                }
            }
            onInstructionCallback.apply({}, [context, instruction]);
            if (sessionPrintBlocks) {
                const { details = false, colored = false, treeSpaces = 4 } = sessionPrintOptions;
                const isCall = Utils.isCallInstruction(instruction);
                const isJump = Utils.isJumpInstruction(instruction);
                const isRet = Utils.isRetInstruction(instruction);
                const printInfo = formatInstruction(context, address, instruction, details, colored, treeSpaces, isJump);
                currentExecutionBlock.push(printInfo);
                if (isJump || isRet) {
                    if (currentExecutionBlock.length > 0) {
                        blockifyBlock(details);
                    }
                    currentExecutionBlock.length = 0;
                    currentBlockMaxWidth = 0;
                }
                if (isCall) {
                    treeTrace.push(instruction.next);
                }
                else if (isRet) {
                    hitRetInstruction = true;
                }
            }
        }
    }
    function blockifyBlock(details) {
        const divMod = currentBlockMaxWidth % 8;
        if (divMod !== 0) {
            currentBlockMaxWidth -= divMod;
            currentBlockMaxWidth += 8;
        }
        const realLineWidth = currentBlockMaxWidth - currentBlockStartWidth;
        const startSpacer = Utils.getSpacer(currentBlockStartWidth + 1);
        const sepCount = (realLineWidth + 8) / 4;
        const topSep = ' _'.repeat(sepCount).substring(1);
        const botSep = ' \u00AF'.repeat(sepCount).substring(1);
        const nextSepCount = currentBlockStartWidth + 1 + botSep.length;
        const emptyLine = formatLine({
            data: ' '.repeat(currentBlockMaxWidth),
            lineLength: currentBlockMaxWidth,
        });
        let topMid = ' ';
        if (sessionPrevSepCount > 0) {
            topMid = '|';
            const sepDiff = sessionPrevSepCount - nextSepCount;
            if (sepDiff < 0) {
                const spacer = Utils.getSpacer(sessionPrevSepCount);
                if (details) {
                    console.log(`${spacer}|`);
                }
                console.log(`${spacer}|${'_ '.repeat(-sepDiff / 2)}`);
                console.log(`${spacer + Utils.getSpacer(-sepDiff)}|`);
            }
            else if (sepDiff > 0) {
                const spacer = Utils.getSpacer(nextSepCount);
                console.log(`${spacer}|${'\u00AF '.repeat(sepDiff / 2)}`);
                if (details) {
                    console.log(`${spacer}|`);
                }
            }
        }
        console.log(startSpacer + topSep + topMid + topSep);
        currentExecutionBlock.forEach((printInfo) => {
            if (details && printInfo.details) {
                console.log(emptyLine);
                printInfo.details.forEach((detailPrintInfo) => {
                    console.log(formatLine(detailPrintInfo));
                });
            }
            console.log(formatLine(printInfo));
            if (details) {
                if (printInfo.postDetails) {
                    printInfo.postDetails.forEach((postPrintInfo) => {
                        console.log(formatLine(postPrintInfo));
                    });
                }
                console.log(emptyLine);
            }
        });
        console.log(`${startSpacer + botSep}|${botSep}`);
        sessionPrevSepCount = nextSepCount;
        console.log(`${Utils.getSpacer(sessionPrevSepCount)}|`);
        if (details) {
            console.log(`${Utils.getSpacer(sessionPrevSepCount)}|`);
        }
    }
    function formatLine(printInfo) {
        let toPrint = printInfo.data;
        toPrint = Utils.insertAt(toPrint, '|    ', currentBlockStartWidth);
        toPrint += Utils.getSpacer(currentBlockMaxWidth - printInfo.lineLength);
        toPrint += '    |';
        return toPrint;
    }
    function formatInstruction(context, address, instruction, details, colored, treeSpaces, isJump) {
        const anyCtx = context;
        let line = '';
        let coloredLine = '';
        let part;
        let intTreeSpace = 0;
        let spaceAtOpStr;
        const append = (what, color) => {
            line += what;
            if (colored) {
                if (color) {
                    coloredLine += Color.colorify(what, color);
                }
                else {
                    coloredLine += what;
                }
            }
        };
        const appendModuleInfo = (address) => {
            const module = moduleMap.find(address);
            if (module !== null) {
                append(' (');
                append(module.name, 'green bold');
                part = '#';
                append(part);
                part = address.sub(module.base).toString();
                append(part, 'red');
                part = ')';
                append(part);
            }
        };
        const addSpace = (count) => {
            append(Utils.getSpacer(count + intTreeSpace - line.length));
        };
        if (treeSpaces > 0 && treeTrace.length > 0) {
            intTreeSpace = treeTrace.length * treeSpaces;
            append(Utils.getSpacer(intTreeSpace));
        }
        currentBlockStartWidth = line.length;
        append(address.toString(), 'red bold');
        appendModuleInfo(address);
        addSpace(40);
        const bytes = instruction.address.readByteArray(instruction.size);
        if (bytes) {
            part = Utils.ba2hex(bytes);
            append(part, 'yellow');
        }
        else {
            let _fix = '';
            for (let i = 0; i < instruction.size; i++) {
                _fix += '00';
            }
            append(_fix, 'yellow');
        }
        addSpace(50);
        append(instruction.mnemonic, 'green bold');
        addSpace(60);
        spaceAtOpStr = line.length;
        append(instruction.opStr, 'filter');
        if (isJump) {
            try {
                const jumpInsn = getJumpInstruction(instruction, anyCtx);
                if (jumpInsn) {
                    appendModuleInfo(jumpInsn.address);
                }
            }
            catch (e) { }
        }
        const lineLength = line.length;
        if (lineLength > currentBlockMaxWidth) {
            currentBlockMaxWidth = lineLength;
        }
        let detailsData = [];
        if (details) {
            if (currentExecutionBlockStackRegisters.length > 0) {
                const postLines = [];
                currentExecutionBlockStackRegisters.forEach((reg) => {
                    const contextVal = getRegisterValue(context, reg.reg);
                    if (contextVal && contextVal != reg.value) {
                        const toStr = contextVal.toString();
                        let str = getSpacer(spaceAtOpStr);
                        if (colored) {
                            str += `${Color.colorify(reg.reg, 'blue bold')} = ${Color.colorify(toStr, 'red')}`;
                        }
                        else {
                            str += `${reg.reg} = ${toStr}`;
                        }
                        postLines.push({
                            data: str,
                            lineLength: spaceAtOpStr + reg.reg.length + toStr.length + 3,
                        });
                    }
                });
                currentExecutionBlockStackRegisters.length = 0;
                if (currentExecutionBlock.length > 0) {
                    currentExecutionBlock[currentExecutionBlock.length - 1].postDetails = postLines;
                }
            }
            detailsData = formatInstructionDetails(spaceAtOpStr, context, instruction, colored, isJump);
            detailsData.forEach((detail) => {
                if (detail.lineLength > currentBlockMaxWidth) {
                    currentBlockMaxWidth = detail.lineLength;
                }
            });
        }
        return {
            data: colored ? coloredLine : line,
            lineLength: lineLength,
            details: detailsData,
        };
    }
    function formatInstructionDetails(spaceAtOpStr, context, instruction, colored, isJump) {
        const anyContext = context;
        const data = [];
        const visited = new Set();
        let insn = null;
        if (Process.arch === 'arm64') {
            insn = instruction;
        }
        else if (Process.arch === 'ia32' || Process.arch === 'x64') {
            insn = instruction;
        }
        if (insn != null) {
            for (const op of insn.operands) {
                let reg;
                let value = null;
                let adds = 0;
                if (op.type === 'mem') {
                    adds = op.value.disp;
                    reg = op.value.base;
                }
                else if (op.type === 'reg') {
                    reg = op.value;
                }
                if (typeof reg !== 'undefined' && !visited.has(reg)) {
                    visited.add(reg);
                    try {
                        value = getRegisterValue(anyContext, reg);
                        if (typeof value !== 'undefined') {
                            currentExecutionBlockStackRegisters.push({
                                reg: reg.toString(),
                                value: value,
                            });
                            value = getRegisterValue(anyContext, reg);
                            const regLabel = reg.toString();
                            data.push([
                                regLabel,
                                value.toString() + (adds > 0 ? `#${adds.toString(16)}` : ''),
                                getTelescope(value.add(adds), colored, isJump),
                            ]);
                        }
                    }
                    catch (e) { }
                }
            }
        }
        const applyColor = (what, color) => {
            if (colored && color) {
                what = Color.colorify(what, color);
            }
            return what;
        };
        const lines = [];
        for (const row of data) {
            let line = Utils.getSpacer(spaceAtOpStr);
            let lineLength = spaceAtOpStr + row[0].length + row[1].toString().length + 3;
            line += `${applyColor(row[0], 'blue')} = ${applyColor(row[1], 'filter')}`;
            if (row.length > 2 && row[2] !== null) {
                const printInfo = row[2];
                if (printInfo.lineLength > 0) {
                    line += ` >> ${printInfo.data}`;
                    lineLength += printInfo.lineLength + 4;
                }
            }
            lines.push({ data: line, lineLength: lineLength });
        }
        return lines;
    }
    function getTelescope(address, colored, isJump) {
        if (isJump) {
            try {
                const instruction = Instruction.parse(address);
                let ret;
                if (colored) {
                    ret = Color.colorify(instruction.mnemonic, 'green');
                }
                else {
                    ret = instruction.mnemonic;
                }
                ret += ` ${instruction.opStr}`;
                return {
                    data: ret,
                    lineLength: instruction.mnemonic.length + instruction.opStr.length + 1,
                };
            }
            catch (e) { }
        }
        else {
            let count = 0;
            let current = address;
            let result = '';
            let resLen = 0;
            while (true) {
                try {
                    current = current.readPointer();
                    const asStr = current.toString();
                    if (result.length > 0) {
                        result += ' >> ';
                        resLen += 4;
                    }
                    resLen += asStr.length;
                    if (current.compare(0x10000) < 0) {
                        if (colored) {
                            result += Color.colorify(asStr, 'cyan bold');
                        }
                        else {
                            result += asStr;
                        }
                        break;
                    }
                    else {
                        if (colored) {
                            result += Color.colorify(asStr, 'red');
                        }
                        else {
                            result += asStr;
                        }
                        try {
                            const str = address.readUtf8String();
                            if (str && str.length > 0) {
                                const ret = str.replace('\n', ' ');
                                if (colored) {
                                    result += ` (${Color.colorify(ret, 'green')})`;
                                }
                                else {
                                    result += ` (${ret})`;
                                }
                                resLen += str.length + 3;
                            }
                        }
                        catch (e) { }
                    }
                    if (count === 5) {
                        break;
                    }
                    count += 1;
                }
                catch (e) {
                    break;
                }
            }
            return { data: result, lineLength: resLen };
        }
        return { data: '', lineLength: 0 };
    }
    function getJumpInstruction(instruction, context) {
        let insn = null;
        if (Process.arch === 'arm64') {
            insn = instruction;
        }
        else if (Process.arch === 'ia32' || Process.arch === 'x64') {
            insn = instruction;
        }
        if (insn) {
            if (Utils.isJumpInstruction(instruction)) {
                const lastOp = insn.operands[insn.operands.length - 1];
                switch (lastOp.type) {
                    case 'reg':
                        return Instruction.parse(context[lastOp.value]);
                    case 'imm':
                        return Instruction.parse(ptr(lastOp.value.toString()));
                }
            }
        }
        return null;
    }
    function getRegisterValue(context, reg) {
        if (Process.arch === 'arm64') {
            if (reg.startsWith('w')) {
                return context[reg.replace('w', 'x')].and(0x00000000ffffffff);
            }
        }
        return context[reg];
    }
})(HooahTrace || (HooahTrace = {}));
//# sourceMappingURL=hooah.js.map

/***/ }),

/***/ "./packages/native/dist/index.js":
/*!***************************************!*\
  !*** ./packages/native/dist/index.js ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Files: () => (/* reexport module object */ _files_js__WEBPACK_IMPORTED_MODULE_6__),
/* harmony export */   HooahTrace: () => (/* reexport safe */ _hooah_js__WEBPACK_IMPORTED_MODULE_2__.HooahTrace),
/* harmony export */   Inject: () => (/* reexport safe */ _inject_js__WEBPACK_IMPORTED_MODULE_3__.Inject),
/* harmony export */   Logcat: () => (/* reexport module object */ _logcat_js__WEBPACK_IMPORTED_MODULE_7__),
/* harmony export */   Pthread: () => (/* reexport module object */ _pthread_js__WEBPACK_IMPORTED_MODULE_8__),
/* harmony export */   Strings: () => (/* reexport module object */ _strings_js__WEBPACK_IMPORTED_MODULE_9__),
/* harmony export */   Syscall: () => (/* reexport module object */ _syscall_js__WEBPACK_IMPORTED_MODULE_10__),
/* harmony export */   System: () => (/* reexport module object */ _system_js__WEBPACK_IMPORTED_MODULE_11__),
/* harmony export */   TheEnd: () => (/* reexport module object */ _theEnd_js__WEBPACK_IMPORTED_MODULE_12__),
/* harmony export */   Time: () => (/* reexport module object */ _time_js__WEBPACK_IMPORTED_MODULE_13__),
/* harmony export */   attachRegisterNatives: () => (/* reexport safe */ _registerNatives_js__WEBPACK_IMPORTED_MODULE_4__.attachRegisterNatives),
/* harmony export */   attachSystemPropertyGet: () => (/* reexport safe */ _systemPropertyGet_js__WEBPACK_IMPORTED_MODULE_5__.attachSystemPropertyGet),
/* harmony export */   dumpFile: () => (/* reexport safe */ _utils_js__WEBPACK_IMPORTED_MODULE_14__.dumpFile),
/* harmony export */   gPtr: () => (/* binding */ gPtr),
/* harmony export */   getSelfFiles: () => (/* reexport safe */ _utils_js__WEBPACK_IMPORTED_MODULE_14__.getSelfFiles),
/* harmony export */   initLibart: () => (/* binding */ initLibart),
/* harmony export */   prettyMethod: () => (/* binding */ prettyMethod),
/* harmony export */   traceInModules: () => (/* reexport safe */ _utils_js__WEBPACK_IMPORTED_MODULE_14__.traceInModules),
/* harmony export */   tryResolveMapsSymbol: () => (/* reexport safe */ _utils_js__WEBPACK_IMPORTED_MODULE_14__.tryResolveMapsSymbol),
/* harmony export */   type: () => (/* binding */ type),
/* harmony export */   unbox: () => (/* binding */ unbox)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _hooah_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./hooah.js */ "./packages/native/dist/hooah.js");
/* harmony import */ var _inject_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./inject.js */ "./packages/native/dist/inject.js");
/* harmony import */ var _registerNatives_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./registerNatives.js */ "./packages/native/dist/registerNatives.js");
/* harmony import */ var _systemPropertyGet_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./systemPropertyGet.js */ "./packages/native/dist/systemPropertyGet.js");
/* harmony import */ var _files_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./files.js */ "./packages/native/dist/files.js");
/* harmony import */ var _logcat_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./logcat.js */ "./packages/native/dist/logcat.js");
/* harmony import */ var _pthread_js__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(/*! ./pthread.js */ "./packages/native/dist/pthread.js");
/* harmony import */ var _strings_js__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(/*! ./strings.js */ "./packages/native/dist/strings.js");
/* harmony import */ var _syscall_js__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(/*! ./syscall.js */ "./packages/native/dist/syscall.js");
/* harmony import */ var _system_js__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(/*! ./system.js */ "./packages/native/dist/system.js");
/* harmony import */ var _theEnd_js__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(/*! ./theEnd.js */ "./packages/native/dist/theEnd.js");
/* harmony import */ var _time_js__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(/*! ./time.js */ "./packages/native/dist/time.js");
/* harmony import */ var _utils_js__WEBPACK_IMPORTED_MODULE_14__ = __webpack_require__(/*! ./utils.js */ "./packages/native/dist/utils.js");















function gPtr(value) {
    return ptr(value).sub('0x100000');
}
function type(fn) {
    return function (...args) {
        return fn.call(this, ...args);
    };
}
function unbox(box) {
    let casted = null;
    if ((casted = box)) {
        return [casted.value, casted.errno];
    }
    if ((casted = box)) {
        return [casted.value, casted.lastError];
    }
    return [box.value, Number.NaN];
}
// * Currently unused
function initLibart() {
    const module = Process.getModuleByName('libart.so');
    const anyJava = Java;
    for (const { name, address } of module.enumerateSymbols()) {
        anyJava.api['art::ArtMethod::GetSignature'] ??= name.includes('_ZN3art9ArtMethod12GetSignatureEv')
            ? new NativeFunction(address, 'pointer', ['pointer'])
            : undefined;
        anyJava.api['art::ArtMethod::JniLongName'] ??= name.includes('_ZN3art9ArtMethod11JniLongNameEv')
            ? new NativeFunction(address, 'pointer', ['pointer'])
            : undefined;
        anyJava.api.NterpGetShortyFromMethodId ??= name.includes('NterpGetShortyFromMethodId')
            ? new NativeFunction(address, 'pointer', ['pointer'])
            : undefined;
        anyJava.api['art::ArtMethod::Invoke'] ??=
            name.includes('Invoke') &&
                name.includes('_ZN3art9ArtMethod') &&
                name.includes('Thread') &&
                name.includes('JValue')
                ? new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'int', 'pointer', 'pointer'])
                : undefined;
    }
    anyJava.api['art::DexFile::OpenMemory'] = module.findExportByName('_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_');
}
// * pointless ? no idea what could be the use case for this
function hookArtInvoke() {
    Interceptor.attach(Java.api['art::ArtMethod::Invoke'], {
        onEnter(args) {
            this.method = args[0];
            this.argRef = args[1];
            this.argSize = args[2];
            this.result = args[3];
            this.shorty = args[4];
            this.methodName = prettyMethod(this.method, true);
        },
        onLeave(retval) {
            const name = (this.methodName ?? '');
            if (name.includes('ClassNotFoundException'))
                return;
            const flags = this.method.add(0x4).readU16();
            const isStatic = (flags & 0x8) > 0;
            const argTypes = name.substring(name.indexOf('(') + 1, name.indexOf(')')).split(', ');
            const argLen = argTypes.length;
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'artmethod' }, `name: ${this.methodName} flags: ${flags} static: ${isStatic}`);
            let offset = 0;
            for (let i = 0; i < argLen; i += 1) {
                const argType = argTypes[i];
                const argAddress = this.argSize.add(4 * (i + (isStatic ? 0 : 1)) + offset);
                const argValue = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.tryNull)(() => (argType.includes('.') && Java.cast(argAddress, Classes.Object)) ||
                    argAddress.readU32());
                _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'arg' }, `${argType}: ${argAddress} ${argValue}`);
                if (argType === 'long') {
                    offset += 4;
                }
            }
        },
    });
}
function prettyMethod(methodID, withSignature) {
    const result = new _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Std.String();
    Java.api['art::ArtMethod::PrettyMethod'](result, methodID, withSignature ? 1 : 0);
    return result.disposeToString();
}

//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./packages/native/dist/inject.js":
/*!****************************************!*\
  !*** ./packages/native/dist/inject.js ***!
  \****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Inject: () => (/* binding */ Inject)
/* harmony export */ });
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");

const { blue, red, magentaBright: pink } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.Color.use();
// using namespace for singleton with all callbacks
var Inject;
(function (Inject) {
    Inject.modules = new ModuleMap();
    const initArrayCallbacks = [];
    let do_dlopen;
    let call_ctor;
    let prelink_image;
    const linker = Process.getModuleByName(Process.pointerSize === 4 ? 'linker' : 'linker64');
    for (const { name, address } of linker.enumerateSymbols()) {
        if (name.includes('do_dlopen')) {
            do_dlopen = address;
            continue;
        }
        if (name.includes('call_constructor')) {
            call_ctor = address;
            continue;
        }
        if (name.includes('phdr_table_get_dynamic_section')) {
            prelink_image = address;
            continue;
        }
    }
    // TODO add just hook dlopen_ext
    // const android_dlopen_ext = Module.getExportByName(null, 'android_dlopen_ext');
    Interceptor.attach(do_dlopen, {
        onEnter: function (args) {
            const libPath = (this.libPath = args[0].readCString());
            if (!libPath)
                return;
            const libName = (this.libName = libPath.split('/').pop());
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.logger.info(`[${pink('dlopen')}] ${libPath}`);
            Inject.modules.update();
            return;
            // TODO investigate
            let handle = null;
            const unhook = () => handle?.detach();
            handle = Interceptor.attach(call_ctor, ctorListenerCallback(libName, unhook));
        },
        onLeave: function (retval) {
            Inject.modules.update();
            if (!this.libPath)
                return;
            onAfterInitArray(this.libName, this);
        },
    });
    // call_constructor callback
    const ctorListenerCallback = (libName, detach) => ({
        onEnter(args) {
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.logger.info({ tag: 'ctor' }, `${libName} ${red('->')} ${args[0]}`);
        },
        onLeave(retval) {
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.logger.info({ tag: 'ctor' }, `${libName} ${blue('<-')} ${retval}`);
            detach();
        },
    });
    function onAfterInitArray(libName, ctx) {
        for (const cb of initArrayCallbacks) {
            cb.call(ctx, libName);
        }
    }
    function afterInitArray(fn) {
        initArrayCallbacks.push(fn);
    }
    Inject.afterInitArray = afterInitArray;
    function afterInitArrayModule(fn) {
        initArrayCallbacks.push(function (name) {
            const module = Process.findModuleByName(name);
            if (module)
                fn.call(this, module);
        });
    }
    Inject.afterInitArrayModule = afterInitArrayModule;
    function attachInModule(nameOrPredicate, address, callbacks) {
        const fn = typeof nameOrPredicate === 'function'
            ? nameOrPredicate
            : (ptr) => Inject.modules.findName(ptr) === nameOrPredicate;
        Interceptor.attach(address, {
            onEnter(args) {
                if (fn(this.returnAddress)) {
                    callbacks?.onEnter?.call?.(this, args);
                }
            },
            onLeave(retval) {
                if (fn(this.returnAddress)) {
                    callbacks?.onLeave?.call(this, retval);
                }
            },
        });
    }
    Inject.attachInModule = attachInModule;
    function attachRelativeTo(module, offset, callback) {
        afterInitArrayModule(({ name, base }) => {
            if (name === module) {
                const ptr = base.add(offset);
                console.log('attach to: ', ptr);
                Interceptor.attach(ptr, callback);
            }
        });
    }
    Inject.attachRelativeTo = attachRelativeTo;
    /** very useful for not hooking hardware, chrome, and other things you that cause crashes */
    function isWithinOwnRange(ptr) {
        const path = Inject.modules.findPath(ptr);
        return path?.includes('/data') === true && !path.includes('/com.google.android.trichromelibrary');
    }
    Inject.isWithinOwnRange = isWithinOwnRange;
})(Inject || (Inject = {}));

//# sourceMappingURL=inject.js.map

/***/ }),

/***/ "./packages/native/dist/logcat.js":
/*!****************************************!*\
  !*** ./packages/native/dist/logcat.js ***!
  \****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   hookLogcat: () => (/* binding */ hookLogcat)
/* harmony export */ });
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _inject_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./inject.js */ "./packages/native/dist/inject.js");


function hookLogcat() {
    const liblog = Process.getModuleByName('liblog.so');
    const _isLoggable = liblog.getExportByName('__android_log_is_loggable');
    Interceptor.replaceFast(_isLoggable, new NativeCallback(() => 1, 'bool', ['int', 'pointer', 'int']));
    const _logPrint = liblog.getExportByName('__android_log_print');
    Interceptor.attach(_logPrint, {
        onEnter: function (args) {
            this.resultPtr = this.context.sp.sub(1112);
            const tag = (this.tag = args[1].readCString()) ?? '';
            const msg = (this.msg = args[2].readCString()) ?? '';
            // logger.info(`${this.resultPtr} +- ${args[1]} = ${args[1].sub(this.resultPtr)}` )
        },
        onLeave(retval) {
            // ogger.info({ tag: 'logcat', id: this.tag }, `{${counter++}} ${this.resultPtr.readCString(200)}`);
        },
    });
    const vsnprintf = Module.getExportByName(null, 'vsnprintf');
    _inject_js__WEBPACK_IMPORTED_MODULE_1__.Inject.attachInModule('liblog.so', vsnprintf, {
        onEnter: function (args) {
            this.result = args[0];
        },
        onLeave: function (retval) {
            if (liblog.base <= this.returnAddress && liblog.base.add(liblog.size) >= this.returnAddress) {
                const result = this.result;
                _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.logger.info({ tag: 'logcat' }, `${result.readCString()}`.trimEnd());
                // MemoryAccessMonitor.enable(
                //     { base: result, size: 1024 },
                //     {
                //         onAccess(details) {
                //             logger.info({ tag: 'memwatch', id: `${result}` }, JSON.stringify(details));
                //         },
                //     },
                // );
            }
        },
    });
}

//# sourceMappingURL=logcat.js.map

/***/ }),

/***/ "./packages/native/dist/pthread.js":
/*!*****************************************!*\
  !*** ./packages/native/dist/pthread.js ***!
  \*****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   hookPthread_create: () => (/* binding */ hookPthread_create)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _utils_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./utils.js */ "./packages/native/dist/utils.js");



const { bold, dim, green, red, gray, black } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.use();
function hookPthread_create() {
    Interceptor.replace(Libc.pthread_create, new NativeCallback((thread, attr, start_routine, arg) => {
        const ret = Libc.pthread_create(thread, attr, start_routine, arg);
        // magic ?
        const tid = thread.readPointer().add(16).readUInt();
        const method = DebugSymbol.fromAddress(start_routine);
        const name = (0,_utils_js__WEBPACK_IMPORTED_MODULE_2__.tryDemangle)(method.name);
        const threadName = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.tryNull)(() => (0,_utils_js__WEBPACK_IMPORTED_MODULE_2__.readTidName)(tid));
        const fTid = dim(ret === 0 ? green(tid) : red(tid));
        const fThreadName = threadName ? `, ${bold(threadName)} ` : ' ';
        const fMethod = `[${gray(`${method.moduleName}`)} ${black(`${name}`)}] ${gray(`${method.address}`)}`;
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'pthread_create' }, `${gray('tid:')} ${fTid}, ${attr}${fThreadName}${fMethod}, ${!(0,_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.isNully)(arg) ? arg.readPointer() : arg}`);
        return ret;
    }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
}

//# sourceMappingURL=pthread.js.map

/***/ }),

/***/ "./packages/native/dist/registerNatives.js":
/*!*************************************************!*\
  !*** ./packages/native/dist/registerNatives.js ***!
  \*************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   attachRegisterNatives: () => (/* binding */ attachRegisterNatives)
/* harmony export */ });
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");

const { green, redBright, bold, dim, black } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.Color.use();
// biome-ignore lint/suspicious/noExplicitAny: <explanation>
let cachedVtable = null;
function vtable(instance) {
    if (cachedVtable === null) {
        cachedVtable = instance.handle.readPointer();
    }
    return cachedVtable;
}
function find(offset, returnType, args) {
    const env = Java.vm.tryGetEnv();
    if (!env)
        return null;
    const addr = vtable(env)
        .add(offset * Process.pointerSize)
        .readPointer();
    const func = new NativeFunction(addr, returnType, args);
    return func ?? null;
}
function attachRegisterNatives(fn) {
    const found = find(215, 'int32', ['pointer', 'pointer', 'pointer', 'int32']);
    if (found) {
        Interceptor.attach(found, {
            onEnter(args) {
                logOnEnterRegisterNatives.call(this, args);
            },
            onLeave(retval) {
                fn?.call(this, retval);
            },
        });
        return;
    }
    // fallback previous method
    const libart = Process.getModuleByName('libart.so');
    const symbols = libart.enumerateSymbols();
    for (const { name, address } of symbols) {
        if (name.includes('art') &&
            name.includes('JNI') &&
            name.includes('RegisterNatives') &&
            !name.includes('CheckJNI')) {
            console.log('RegisterNatives is at ', address, name);
            Interceptor.attach(address, {
                onEnter(args) {
                    logOnEnterRegisterNatives.call(this, args);
                    // TODO hook capabilities
                },
            });
        }
    }
}
/*
jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
struct JNINativeMethod< R (JNIEnv*, jclass*, Args...) > {
    const char* name;
    const char* signature;
    R (*fnPtr)(JNIEnv*, jclass*, Args...);
};
*/
function logOnEnterRegisterNatives(args) {
    const module = Process.findModuleByAddress(this.returnAddress) ?? Process.findModuleByAddress(args[2]);
    const clazz = args[1];
    const methodsPtr = args[2];
    const nMethods = args[3].toInt32();
    const className = Java.vm.tryGetEnv()?.getClassName(clazz) ?? '<unknown>';
    _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.logger.info({ tag: 'RegisterNatives' }, `${redBright(className)} methods: ${bold(nMethods)}`);
    addToExport({
        module: module?.name,
        name: className,
        methods_ptr: module ? methodsPtr.sub(module.base) : methodsPtr,
        nMethods: nMethods,
        backtrace: module
            ? Thread.backtrace()
                .filter((s) => s > module.base && s < module.base.add(module.size))
                .map((s) => s.sub(module.base))
            : undefined,
    });
    for (let i = 0; i < nMethods; i++) {
        const namePtr = methodsPtr.add(i * Process.pointerSize * 3).readPointer();
        const sigPtr = methodsPtr.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer();
        const fnPtrPtr = methodsPtr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
        const name = namePtr.readCString() ?? '';
        const sig = sigPtr.readCString() ?? '';
        const symbol = DebugSymbol.fromAddress(fnPtrPtr);
        console.log(`${black(dim('  >'))}${green(name)}${sig}`, `at:\n    ${symbol}\n    ${DebugSymbol.fromAddress(this.returnAddress)}`);
        // console.log(
        //     '[#]',
        //     JSON.stringify({
        //         class: className,
        //         name: name,
        //         sig: sig,
        //         module: symbol.moduleName,
        //         offset: badConvert(symbol),
        //     }),
        // );
    }
}
function getModuleBase(returnAddress) {
    const debug = DebugSymbol.fromAddress(returnAddress);
    if (!debug.name)
        return null;
    const module = Process.findModuleByName(debug.name);
    if (!module)
        return null;
    return module.base;
}
function badConvert(symbol) {
    const str = symbol.toString();
    const stripped = str.substring(str.lastIndexOf('0x'));
    return ptr(stripped);
}
function addToExport(item) {
    const native = (rpc.RegisterNatives ??= []);
    native.push(item);
}

//# sourceMappingURL=registerNatives.js.map

/***/ }),

/***/ "./packages/native/dist/strings.js":
/*!*****************************************!*\
  !*** ./packages/native/dist/strings.js ***!
  \*****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   hookStrcmp: () => (/* binding */ hookStrcmp),
/* harmony export */   hookStrcpy: () => (/* binding */ hookStrcpy),
/* harmony export */   hookStrlen: () => (/* binding */ hookStrlen),
/* harmony export */   hookStrstr: () => (/* binding */ hookStrstr),
/* harmony export */   hookStrtoLong: () => (/* binding */ hookStrtoLong)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");


const { dim, green, red, italic, gray } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.use();
function strOneLine(ptr) {
    return `${ptr.readCString()}`.replace(/\n/g, '\\n');
}
function hookStrstr(predicate) {
    const array = ['strstr', 'strcasestr'];
    for (const key of array) {
        const func = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc[key];
        Interceptor.replace(func, new NativeCallback(function (haystack, needle) {
            if (haystack.readCString()?.includes('TracerPid')) {
                haystack = Memory.allocUtf8String('nya');
            }
            const ret = func(haystack, needle);
            if (predicate(this.returnAddress)) {
                const isFound = ret && !ret.isNull();
                const strhay = gray(`"${strOneLine(haystack)}"`.slice(0, 100));
                const strned = isFound
                    ? `"${strOneLine(needle)}"`
                    : gray(`"${strOneLine(needle)}"`.slice(0, 100));
                const colorsign = isFound ? green : (x) => x;
                _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: key }, `${strhay} ${colorsign('?')} ${strned}`);
            }
            return ret;
        }, 'pointer', ['pointer', 'pointer']));
    }
}
function hookStrlen(predicate) {
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.strlen, new NativeCallback(function (s) {
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.strlen(s);
        if (predicate(this.returnAddress)) {
            const strs = gray(`"${strOneLine(s)}"`);
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'strlen' }, `${strs} # ${_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.number(ret)} ${DebugSymbol.fromAddress(this.returnAddress)}`);
        }
        return ret;
    }, 'int', ['pointer']));
}
function hookStrcpy(predicate) {
    const array = ['stpcpy', 'strcpy'];
    for (const key of array) {
        const func = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc[key];
        Interceptor.replace(func, new NativeCallback(function (dst, src) {
            if (predicate(this.returnAddress)) {
                const strdst = dim(`"${strOneLine(dst)}"`);
                const strsrc = dim(`"${strOneLine(src)}"`);
                _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: key }, `${strdst} | ${strsrc}`);
            }
            const ret = func(dst, src);
            return ret;
        }, 'pointer', ['pointer', 'pointer']));
    }
}
// hooking strcmp appears to kill the app regardless of what app it is ?
function hookStrcmp(predicate) {
    const array = ['strcmp', 'strncmp'];
    for (const key of array.slice(-1)) {
        const func = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc[key];
        Interceptor.attach(func, {
            onEnter({ 0: a, 1: b }) {
                if (predicate(this.returnAddress)) {
                    _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: key }, `${a.readCString()} ? ${b.readCString()}`);
                }
            },
            onLeave(retval) { },
        });
        // Interceptor.replace(
        // 	func,
        // 	new NativeCallback(
        // 		function (s1, s2) {
        // 			const ret = func(s1, s2);
        // 			if (predicate(this.returnAddress)) {
        // 				const strs1 =
        // 					ret === 0 ? `"${strOneLine(s1)}"` : gray(`"${strOneLine(s1)}"`);
        // 				const strs2 =
        // 					ret >= 0 ? `"${strOneLine(s2)}"` : gray(`"${strOneLine(s2)}"`);
        // 				logger.info({ tag: key }, `${strs1} = ${strs2}`);
        // 			}
        // 			return ret;
        // 		},
        // 		"int",
        // 		["pointer", "pointer"],
        // 	),
        // );
    }
}
function hookStrtoLong(predicate) {
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.strtoll, new NativeCallback(function (src, endptr, base) {
        if (predicate(this.returnAddress)) {
            const strsrc = dim(`"${strOneLine(src)}"`);
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'strtoll' }, `${strsrc}`);
        }
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.strtoll(src, endptr, base);
        return new Int64(ret);
    }, 'int64', ['pointer', 'pointer', 'int']));
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.strtoull, new NativeCallback(function (src, endptr, base) {
        if (predicate(this.returnAddress)) {
            const strsrc = dim(`"${strOneLine(src)}"`);
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'strtoull' }, `${strsrc}`);
        }
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.strtoull(src, endptr, base);
        return new UInt64(ret);
    }, 'uint64', ['pointer', 'pointer', 'int']));
}

//# sourceMappingURL=strings.js.map

/***/ }),

/***/ "./packages/native/dist/syscall.js":
/*!*****************************************!*\
  !*** ./packages/native/dist/syscall.js ***!
  \*****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   SyscallCallback: () => (/* binding */ SyscallCallback),
/* harmony export */   hookSyscall: () => (/* binding */ hookSyscall)
/* harmony export */ });
class SyscallCallback {
    frida;
    native;
    constructor(frida, native) {
        this.frida = frida;
        this.native = native;
    }
}
const callbacks = [];
function hookSyscall(syscallAddress, callback) {
    const address = syscallAddress.sub(12);
    const instructions = address.readByteArray(12);
    if (instructions == null) {
        throw new Error(`Unable to read instructions at address ${address}.`);
    }
    Memory.patchCode(address, 16, (code) => {
        const writer = new Arm64Writer(code, { pc: address });
        writer.putBranchAddress(createCallback(callback, instructions, address.add(16), syscallAddress));
        writer.flush();
    });
}
function createCallback(callback, instructions, retAddress, syscallAddress) {
    // Create custom instructions.
    const frida = Memory.alloc(Process.pageSize);
    Memory.patchCode(frida, Process.pageSize, (code) => {
        const writer = new Arm64Writer(code, { pc: frida });
        // Restore argument instructions.
        writer.putBytes(instructions);
        // Push all registers except x0.
        writer.putPushRegReg('x15', 'x1');
        writer.putPushRegReg('x2', 'x3');
        writer.putPushRegReg('x4', 'x5');
        writer.putPushRegReg('x6', 'x7');
        writer.putPushRegReg('x8', 'x9');
        writer.putPushRegReg('x10', 'x11');
        writer.putPushRegReg('x12', 'x13');
        writer.putPushRegReg('x14', 'x15');
        writer.putPushRegReg('x16', 'x17');
        writer.putPushRegReg('x18', 'x19');
        writer.putPushRegReg('x20', 'x21');
        writer.putPushRegReg('x22', 'x23');
        writer.putPushRegReg('x24', 'x25');
        writer.putPushRegReg('x26', 'x27');
        writer.putPushRegReg('x28', 'x29');
        writer.putInstruction(0xd53b420f);
        writer.putPushRegReg('x30', 'x15');
        // Call native.
        writer.putLdrRegAddress('x16', callback);
        writer.putBlrReg('x16');
        // Pop all registers, except x0, so x0 from native call gets used.
        writer.putPopRegReg('x30', 'x15');
        writer.putInstruction(0xd51b420f);
        writer.putPopRegReg('x28', 'x29');
        writer.putPopRegReg('x26', 'x27');
        writer.putPopRegReg('x24', 'x25');
        writer.putPopRegReg('x22', 'x23');
        writer.putPopRegReg('x20', 'x21');
        writer.putPopRegReg('x18', 'x19');
        writer.putPopRegReg('x16', 'x17');
        writer.putPopRegReg('x14', 'x15');
        writer.putPopRegReg('x12', 'x13');
        writer.putPopRegReg('x10', 'x11');
        writer.putPopRegReg('x8', 'x9');
        writer.putPopRegReg('x6', 'x7');
        writer.putPopRegReg('x4', 'x5');
        writer.putPopRegReg('x2', 'x3');
        writer.putPopRegReg('x15', 'x1');
        // Call syscall.
        // writer.putInstruction(0xd4000001);
        writer.putBranchAddress(retAddress);
        writer.flush();
    });
    // Store callback so it doesn't get garbage collected.
    callbacks.push(new SyscallCallback(frida, callback));
    // Return pointer to the instructions.
    return callbacks[callbacks.length - 1].frida;
}

//# sourceMappingURL=syscall.js.map

/***/ }),

/***/ "./packages/native/dist/system.js":
/*!****************************************!*\
  !*** ./packages/native/dist/system.js ***!
  \****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   hookGetauxval: () => (/* binding */ hookGetauxval),
/* harmony export */   hookSystem: () => (/* binding */ hookSystem)
/* harmony export */ });
/* harmony import */ var _clockwork_common_dist_define_enum_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common/dist/define/enum.js */ "./packages/common/dist/define/enum.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");


const { gray } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.use();
function hookGetauxval() {
    Interceptor.replace(Libc.getauxval, new NativeCallback(function (type) {
        const retval = Libc.getauxval(type);
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'getauxval' }, `${gray(_clockwork_common_dist_define_enum_js__WEBPACK_IMPORTED_MODULE_0__.a_type[type])}: ${ptr(retval)}`);
        return retval;
    }, 'uint32', ['uint32']));
}
function hookSystem() {
    Interceptor.replace(Libc.system, new NativeCallback(function (command) {
        const retval = Libc.system(command);
        return retval;
    }, 'int', ['pointer']));
}

//# sourceMappingURL=system.js.map

/***/ }),

/***/ "./packages/native/dist/systemPropertyGet.js":
/*!***************************************************!*\
  !*** ./packages/native/dist/systemPropertyGet.js ***!
  \***************************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   attachSystemPropertyGet: () => (/* binding */ attachSystemPropertyGet)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");


const { gray, green, red } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.use();
const logger = (0,_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.subLogger)('sysprop');
const spammyKeys = ['debug.stagefright.ccodec_timeout_mult'];
function attachSystemPropertyGet(fn) {
    fn &&
        Interceptor.attach(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.__system_property_read, {
            onEnter(args) { },
            onLeave(retval) {
                retval.replace(ptr(0x5b));
            },
        });
    Interceptor.attach(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.__system_property_get, {
        onEnter: function (args) {
            this.name = args[0].readCString();
            this.value = args[1];
        },
        onLeave: function (retval) {
            const key = this.name;
            const value = this.value.readCString();
            const fValue = value && value.length >= 0 ? value : null;
            const result = fn?.call(this, key, fValue);
            if (result !== undefined) {
                this.value.writeUtf8String(result);
                logger.info(`${gray(key)}: ${red(value ?? retval)} -> ${green(result)}`);
            }
            else {
                if (!spammyKeys.includes(key)) {
                    logger.info(`${gray(key)}: ${value ?? retval}`);
                }
            }
        },
    });
}

//# sourceMappingURL=systemPropertyGet.js.map

/***/ }),

/***/ "./packages/native/dist/theEnd.js":
/*!****************************************!*\
  !*** ./packages/native/dist/theEnd.js ***!
  \****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   hook: () => (/* binding */ hook),
/* harmony export */   hookExit: () => (/* binding */ hookExit),
/* harmony export */   hookKill: () => (/* binding */ hookKill)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");


function hookExit(predicate) {
    const array = ['exit', '_exit', 'abort'];
    for (const key of array) {
        //@ts-ignore
        const func = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc[key];
        Interceptor.replace(func, new NativeCallback(function (code) {
            const stacktrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress)
                .join('\n');
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: key }, `code: ${code} ${stacktrace}`);
            return 0;
        }, 'void', ['pointer']));
    }
    //@ts-ignore
    Interceptor.replace(
    //@ts-ignore
    _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.raise, new NativeCallback(function (err) {
        const stacktrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join('\n');
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'raise' }, `err: ${err} ${stacktrace}`);
        return 0;
    }, 'int', ['int']));
}
function hookKill(predicate) {
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.kill, new NativeCallback((pid, code) => {
        _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'kill' }, `kill(${pid}, ${code}) called !`);
        return 0;
    }, 'int', ['int', 'int']));
}
function hook(predicate) {
    hookKill(predicate);
    hookExit(predicate);
}

//# sourceMappingURL=theEnd.js.map

/***/ }),

/***/ "./packages/native/dist/time.js":
/*!**************************************!*\
  !*** ./packages/native/dist/time.js ***!
  \**************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   hookDifftime: () => (/* binding */ hookDifftime),
/* harmony export */   hookGettimeofday: () => (/* binding */ hookGettimeofday),
/* harmony export */   hookLocaltime: () => (/* binding */ hookLocaltime),
/* harmony export */   hookTime: () => (/* binding */ hookTime)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");


const { gray, bold, black } = _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.use();
function hookDifftime(predicate) {
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.difftime, new NativeCallback(function (time_0, time_1) {
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.difftime(time_0, time_1);
        if (predicate(this.returnAddress))
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'difftime' }, `${gray(`${time_0}`)} - ${gray(`${time_1}`)} = ${bold(`${ret}`)}`);
        return ret;
    }, 'double', ['pointer', 'pointer']));
}
function hookTime(predicate) {
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.time, new NativeCallback(function (time_t) {
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.time(time_t);
        if (predicate(this.returnAddress))
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'time' }, `${gray(`${time_t}`)}`);
        return ret;
    }, 'pointer', ['pointer']));
}
function hookLocaltime(predicate) {
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.localtime, new NativeCallback(function (time_t) {
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.time(time_t);
        if (predicate(this.returnAddress))
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'localtime' }, `${gray(`${time_t}`)}`);
        return ret;
    }, 'pointer', ['pointer']));
}
function hookGettimeofday(predicate) {
    Interceptor.replace(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.gettimeofday, new NativeCallback(function (tv, tz) {
        const ret = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.gettimeofday(tv, tz);
        if (predicate(this.returnAddress)) {
            const timeval = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Struct.Time.timeval(tv);
            const timezone = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Struct.Time.timezone(tz);
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'gettimeofday' }, `${gray(JSON.stringify(timeval))} ${gray(JSON.stringify(timezone))} ${black(ret)}`);
        }
        return ret;
    }, 'int', ['pointer', 'pointer']));
}

//# sourceMappingURL=time.js.map

/***/ }),

/***/ "./packages/native/dist/utils.js":
/*!***************************************!*\
  !*** ./packages/native/dist/utils.js ***!
  \***************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   dellocate: () => (/* binding */ dellocate),
/* harmony export */   dumpFile: () => (/* binding */ dumpFile),
/* harmony export */   getSelfFiles: () => (/* binding */ getSelfFiles),
/* harmony export */   getSelfProcessName: () => (/* binding */ getSelfProcessName),
/* harmony export */   mkdir: () => (/* binding */ mkdir),
/* harmony export */   readFdPath: () => (/* binding */ readFdPath),
/* harmony export */   readTidName: () => (/* binding */ readTidName),
/* harmony export */   traceInModules: () => (/* binding */ traceInModules),
/* harmony export */   tryDemangle: () => (/* binding */ tryDemangle),
/* harmony export */   tryResolveMapsSymbol: () => (/* binding */ tryResolveMapsSymbol)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");


function dellocate(ptr) {
    try {
        const env = Java.vm.tryGetEnv();
        env?.ReleaseStringUTFChars(ptr);
    }
    catch (_) { }
}
function mkdir(path) {
    const cPath = Memory.allocUtf8String(path);
    const dir = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.opendir(cPath);
    if (!dir.isNull()) {
        _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.closedir(dir);
        return false;
    }
    _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.mkdir(cPath, 755);
    _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.chmod(cPath, 755);
    dellocate(cPath);
    return true;
}
function getSelfProcessName() {
    const path = Memory.allocUtf8String('/proc/self/cmdline');
    const { value: fd } = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.open(path, 0);
    dellocate(path);
    if (fd !== -1) {
        const buffer = Memory.alloc(0x1000);
        _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.read(fd, buffer, 0x1000);
        _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.close(fd);
        return buffer.readCString();
    }
    return null;
}
function getSelfFiles() {
    const process_name = getSelfProcessName();
    const files_dir = `/data/data/${process_name}/files`;
    mkdir(files_dir);
    return files_dir;
}
function traceInModules(ptr) {
    for (const { base, name, size } of Process.enumerateModules()) {
        if (ptr > base && ptr < base.add(size)) {
            return `${ptr.toString(16)} at ${name}!0x${ptr.sub(base).toString(16)}`;
        }
    }
    return `${ptr.toString(16)} at ${ptr}}`;
}
function chmod(path) {
    const cPath = Memory.allocUtf8String(path);
    _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.chmod(cPath, 755);
    dellocate(cPath);
}
function mkdirs(base_path, file_path) {
    const dir_array = file_path.split('/');
    let path = base_path;
    for (const segment of dir_array) {
        mkdir(path);
        path += `/${segment}`;
    }
}
function dumpFile(stringPtr, size, relativePath, tag) {
    const process_name = getSelfProcessName();
    const filesDir = `/data/data/${process_name}/files`;
    mkdir(filesDir);
    const dexDir = `${filesDir}/dump_${tag}_${process_name}`;
    mkdir(dexDir);
    const fullpath = `${dexDir}/${relativePath}`;
    // Memory.protect(stringPtr, size, 'rw');
    const buffer = stringPtr.readCString(size);
    if (!buffer) {
        return false;
    }
    mkdirs(dexDir, relativePath);
    //@ts-ignore issue with File from esnext 5.4
    const file = new File(fullpath, 'w');
    file.write(buffer);
    file.close();
    return true;
}
function readFdPath(fd, bufsize = Process.pageSize) {
    const buf = Memory.alloc(bufsize);
    const path = Memory.allocUtf8String(`/proc/self/fd/${fd}`);
    const _ = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.readlink(path, buf, bufsize);
    const str = buf.readCString();
    dellocate(buf);
    dellocate(path);
    return str;
}
function readTidName(tid) {
    //@ts-ignore issue with File from esnext 5.4
    const file = new File(`/proc/self/task/${tid}/comm`, 'r');
    const str = file.readLine().slice(0, -1);
    file.close();
    return str;
}
function tryDemangle(name) {
    if (!name)
        return name;
    try {
        if (!_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.__cxa_demangle) {
            throw Error('__cxa_demangle not found');
        }
        const str = Memory.allocUtf8String(name);
        const len = Memory.alloc(4).writeUInt(name.length);
        const buf = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.__cxa_demangle(str, NULL, len, NULL);
        dellocate(str);
        const demangled = buf.readCString();
        dellocate(buf);
        if (demangled && demangled.length > 0)
            return demangled;
    }
    catch (e) { }
    return name;
}
const sscanf = new NativeFunction(Module.getExportByName('libc.so', 'sscanf'), 'int', [
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
    'pointer',
]);
function tryResolveMapsSymbol(loc, pid = Process.id) {
    try {
        const path = Memory.allocUtf8String(`/proc/${pid}/maps`);
        const mode = Memory.allocUtf8String('r');
        const fd = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fopen(path, mode);
        dellocate(path);
        dellocate(mode);
        if (!fd.value.isNull()) {
            let nread;
            const size = 0x1000;
            const linePtr = Memory.alloc(size);
            const [begin, end] = [Memory.alloc(12), Memory.alloc(12)];
            const [perm, foo, dev, inode, mapname] = [
                Memory.alloc(12),
                Memory.alloc(12),
                Memory.alloc(Process.pointerSize),
                Memory.alloc(Process.pointerSize),
                Memory.alloc(size),
            ];
            const template = Memory.allocUtf8String('%lx-%lx %s %lx %s %ld %s');
            while ((nread = _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fgets(linePtr, size, fd.value))) {
                const read = sscanf(linePtr, template, begin, end, perm, foo, dev, inode, mapname);
                _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'mapres' }, `${linePtr.readCString()} ${read}`);
            }
            dellocate(template);
            _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.fclose(fd.value);
        }
    }
    catch (e) {
        console.error(`${e}`);
    }
    return null;
}

//# sourceMappingURL=utils.js.map

/***/ }),

/***/ "./packages/network/dist/hostaddr.js":
/*!*******************************************!*\
  !*** ./packages/network/dist/hostaddr.js ***!
  \*******************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   attachGetAddrInfo: () => (/* binding */ attachGetAddrInfo),
/* harmony export */   attachGetHostByName: () => (/* binding */ attachGetHostByName),
/* harmony export */   attachInteAton: () => (/* binding */ attachInteAton)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");


function attachGetHostByName() {
    Interceptor.attach(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.gethostbyname, {
        onEnter(args) {
            this.name = args[0].readCString();
        },
        onLeave(retval) {
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'gethostbyname' }, `${_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.url(this.name)} -> result: ${retval}`);
        },
    });
}
function attachGetAddrInfo(detailed = false) {
    Interceptor.attach(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.getaddrinfo, {
        onEnter(args) {
            this.host = args[0].readCString();
            this.port = args[1].readCString();
            this.result = args[2];
        },
        onLeave(retval) {
            const resInt = retval.toUInt32();
            const text = !this.port || this.port === 'null' ? `${this.host}` : `${this.host}:${this.port}`;
            const result = resInt === 0x0 ? 'success' : 'failure';
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'getaddrinfo' }, `${_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.Color.url(text)} -> ${result}`);
            if (resInt === 0x0) {
                let ptr = this.result;
                if (!detailed)
                    return;
                const aiFlags = (ptr = ptr.add(0)).readInt();
                const aiFamilty = (ptr = ptr.add(4)).readInt();
                const aiSockType = (ptr = ptr.add(4)).readInt();
                const aiProtocol = (ptr = ptr.add(4)).readInt();
                const aiAddrLen = (ptr = ptr.add(4)).readUInt();
                const aiAddr = (ptr = ptr.add(4)).readPointer();
                const aiCannonName = (ptr = ptr.add(8)).readCString();
                const aiNext = (ptr = ptr.add(8)).readPointer();
                _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'getaddrinfo' }, JSON.stringify({
                    aiFlags: aiFlags,
                    aiFamilty: aiFamilty,
                    aiSockType: aiSockType,
                    aiProtocol: aiProtocol,
                    aiAddrLen: aiAddrLen,
                    aiAddr: aiAddr,
                    aiCannonName: aiCannonName,
                    aiNext: aiNext,
                }, null, 2));
            }
        },
    });
}
function attachInteAton() {
    Interceptor.attach(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.inet_aton, {
        onEnter(args) {
            this.addr = args[0].readCString();
        },
        onLeave(retval) {
            _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.logger.info({ tag: 'inet_aton' }, `${this.addr} -> ${retval}`);
        },
    });
}

//# sourceMappingURL=hostaddr.js.map

/***/ }),

/***/ "./packages/network/dist/index.js":
/*!****************************************!*\
  !*** ./packages/network/dist/index.js ***!
  \****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   attachGetAddrInfo: () => (/* reexport safe */ _hostaddr_js__WEBPACK_IMPORTED_MODULE_0__.attachGetAddrInfo),
/* harmony export */   attachGetHostByName: () => (/* reexport safe */ _hostaddr_js__WEBPACK_IMPORTED_MODULE_0__.attachGetHostByName),
/* harmony export */   attachInteAton: () => (/* reexport safe */ _hostaddr_js__WEBPACK_IMPORTED_MODULE_0__.attachInteAton),
/* harmony export */   attachNativeSocket: () => (/* reexport safe */ _socket_js__WEBPACK_IMPORTED_MODULE_1__.attachNativeSocket),
/* harmony export */   injectSsl: () => (/* reexport safe */ _trustmanager_js__WEBPACK_IMPORTED_MODULE_2__.injectSsl),
/* harmony export */   useTrustManager: () => (/* reexport safe */ _trustmanager_js__WEBPACK_IMPORTED_MODULE_2__.useTrustManager)
/* harmony export */ });
/* harmony import */ var _hostaddr_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./hostaddr.js */ "./packages/network/dist/hostaddr.js");
/* harmony import */ var _socket_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./socket.js */ "./packages/network/dist/socket.js");
/* harmony import */ var _trustmanager_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./trustmanager.js */ "./packages/network/dist/trustmanager.js");



//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./packages/network/dist/socket.js":
/*!*****************************************!*\
  !*** ./packages/network/dist/socket.js ***!
  \*****************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   attachNativeSocket: () => (/* binding */ attachNativeSocket)
/* harmony export */ });
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");


const logger = (0,_clockwork_logging__WEBPACK_IMPORTED_MODULE_1__.subLogger)('socket');
function attachNativeSocket() {
    const stacktrace = false;
    const backtrace = false;
    const tcpSocketFDs = new Map();
    Interceptor.attach(_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.connect, {
        onEnter(args) {
            this.sockFd = args[0].toInt32();
        },
        onLeave(res) {
            const sockFd = this.sockFd;
            const sockType = Socket.type(sockFd);
            if (!(sockType === 'tcp' || sockType === 'tcp6'))
                return;
            const sockLocal = Socket.localAddress(sockFd);
            const tcpEpLocal = sockLocal ?? undefined;
            const sockRemote = Socket.peerAddress(sockFd);
            const tcpEpRemote = sockRemote ?? undefined;
            if (!tcpEpLocal)
                return;
            // ToDo: if socket FD already exists in the set, a faked 'close' message shall be sent first (currently handled by receiving logic)
            tcpSocketFDs.set(sockFd, tcpEpLocal);
            const msg = {
                socketFd: sockFd,
                pid: Process.id,
                threadId: this.threadId,
                type: 'connect',
                hostIp: tcpEpLocal?.ip,
                port: tcpEpLocal?.port,
                dstIp: tcpEpRemote?.ip,
                dstPort: tcpEpRemote?.port,
                result: res,
            };
            if (stacktrace && Java.available && Java.vm !== null && Java.vm.tryGetEnv()) {
                // checks if Thread is JVM attached (JNI env available)
                const exception = Java.use('java.lang.Exception').$new();
                const trace = exception.getStackTrace();
                // msg.stacktrace = trace.map((traceEl) => {
                //     return {
                //         class: traceEl.getClassName(),
                //         file: traceEl.getFileName(),
                //         line: traceEl.getLineNumber(),
                //         method: traceEl.getMethodName(),
                //         isNative: traceEl.isNativeMethod(),
                //         str: traceEl.toString(),
                //     };
                // });
            }
            if (backtrace) {
                // msg.backtrace = xzxz
            }
            //send(msg)
            logOpen(msg);
        },
    });
    [_clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.close, _clockwork_common__WEBPACK_IMPORTED_MODULE_0__.Libc.shutdown].forEach((fn, i) => {
        Interceptor.attach(fn, {
            onEnter(args) {
                const sockFd = args[0].toInt32();
                if (!tcpSocketFDs.has(sockFd))
                    return;
                const sockType = Socket.type(sockFd);
                if (tcpSocketFDs.has(sockFd)) {
                    const tcpEP = tcpSocketFDs.get(sockFd);
                    const msg = {
                        socketFd: sockFd,
                        pid: Process.id,
                        threadId: this.threadIds,
                        type: ['close', 'shutdown'][i],
                        hostIp: tcpEP?.ip,
                        port: tcpEP?.port,
                    };
                    tcpSocketFDs.delete(sockFd);
                    //send(msg)
                    logClose(msg);
                }
            },
        });
    });
}
function logOpen(msg) {
    const host = `${msg.hostIp?.replace('::ffff:', '')}${String(msg.port ? `:${msg.port}` : '')}`;
    const dest = msg.dstIp
        ? `, dst@${msg.dstIp.replace('::ffff:', '')}${String(msg.dstPort ? `:${msg.dstPort}` : '')}`
        : '';
    logger.info(`(pid: ${msg.pid}, thread: ${msg.threadId}, fd: ${msg.socketFd}) ${msg.type} -> [host@${host}${dest}]`);
}
function logClose(msg) {
    const host = `${msg.hostIp?.replace('::ffff:', '')}${String(msg.port ? `:${msg.port}` : '')}`;
    const thread = msg.threadId ? `, thread: ${msg.threadId}` : '';
    logger.info(`(pid: ${msg.pid}${thread}, fd: ${msg.socketFd}) ${msg.type} -> ${host}`);
}

//# sourceMappingURL=socket.js.map

/***/ }),

/***/ "./packages/network/dist/trustmanager.js":
/*!***********************************************!*\
  !*** ./packages/network/dist/trustmanager.js ***!
  \***********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   injectSsl: () => (/* binding */ injectSsl),
/* harmony export */   useTrustManager: () => (/* binding */ useTrustManager)
/* harmony export */ });
/* harmony import */ var _clockwork_hooks__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/hooks */ "./packages/hooks/dist/index.js");
/* harmony import */ var _clockwork_common__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/common */ "./packages/common/dist/index.js");
/* harmony import */ var _clockwork_hooks_dist_addons_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @clockwork/hooks/dist/addons.js */ "./packages/hooks/dist/addons.js");



const className = 'com.google.in.MemoryTrustManager';
const dexBytes = [
    0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00, 0x65, 0x9e, 0xb0, 0x9f, 0x2f, 0x88, 0x93, 0x44, 0xd4,
    0x22, 0x01, 0xd7, 0xfe, 0xed, 0x81, 0x5e, 0x55, 0x48, 0x42, 0xf7, 0x39, 0x66, 0x45, 0x10, 0x08, 0x04,
    0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x50, 0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0xb0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0xf4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1c, 0x01,
    0x00, 0x00, 0xcc, 0x02, 0x00, 0x00, 0x3c, 0x01, 0x00, 0x00, 0xcc, 0x01, 0x00, 0x00, 0xd4, 0x01, 0x00,
    0x00, 0xd7, 0x01, 0x00, 0x00, 0xfb, 0x01, 0x00, 0x00, 0x17, 0x02, 0x00, 0x00, 0x2b, 0x02, 0x00, 0x00,
    0x3f, 0x02, 0x00, 0x00, 0x6a, 0x02, 0x00, 0x00, 0x8c, 0x02, 0x00, 0x00, 0xa5, 0x02, 0x00, 0x00, 0xa8,
    0x02, 0x00, 0x00, 0xad, 0x02, 0x00, 0x00, 0xd4, 0x02, 0x00, 0x00, 0xe8, 0x02, 0x00, 0x00, 0xfc, 0x02,
    0x00, 0x00, 0x10, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
    0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xc4, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x0e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xbc, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x9c, 0x01,
    0x00, 0x00, 0x37, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2f, 0x03, 0x00,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x17, 0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x70, 0x10, 0x04, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c,
    0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x23, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x12, 0x00, 0x23, 0x00,
    0x07, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3c, 0x01,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x03,
    0x00, 0x06, 0x3c, 0x69, 0x6e, 0x69, 0x74, 0x3e, 0x00, 0x01, 0x4c, 0x00, 0x22, 0x4c, 0x63, 0x6f, 0x6d,
    0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x69, 0x6e, 0x2f, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79,
    0x54, 0x72, 0x75, 0x73, 0x74, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x3b, 0x00, 0x1a, 0x4c, 0x64,
    0x61, 0x6c, 0x76, 0x69, 0x6b, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f,
    0x54, 0x68, 0x72, 0x6f, 0x77, 0x73, 0x3b, 0x00, 0x12, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61,
    0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3b, 0x00, 0x12, 0x4c, 0x6a, 0x61, 0x76, 0x61,
    0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3b, 0x00, 0x29, 0x4c, 0x6a,
    0x61, 0x76, 0x61, 0x2f, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x63, 0x65, 0x72, 0x74,
    0x2f, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x45, 0x78, 0x63, 0x65, 0x70,
    0x74, 0x69, 0x6f, 0x6e, 0x3b, 0x00, 0x20, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x78, 0x2f, 0x6e, 0x65, 0x74,
    0x2f, 0x73, 0x73, 0x6c, 0x2f, 0x58, 0x35, 0x30, 0x39, 0x54, 0x72, 0x75, 0x73, 0x74, 0x4d, 0x61, 0x6e,
    0x61, 0x67, 0x65, 0x72, 0x3b, 0x00, 0x17, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x54, 0x72, 0x75, 0x73,
    0x74, 0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x6a, 0x61, 0x76, 0x61, 0x00, 0x01, 0x56, 0x00,
    0x03, 0x56, 0x4c, 0x4c, 0x00, 0x25, 0x5b, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x73, 0x65, 0x63, 0x75,
    0x72, 0x69, 0x74, 0x79, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x2f, 0x58, 0x35, 0x30, 0x39, 0x43, 0x65, 0x72,
    0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x3b, 0x00, 0x12, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x43,
    0x6c, 0x69, 0x65, 0x6e, 0x74, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x00, 0x12, 0x63, 0x68, 0x65,
    0x63, 0x6b, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x54, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x00, 0x12,
    0x67, 0x65, 0x74, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x65, 0x64, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72,
    0x73, 0x00, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x00, 0x05, 0x00, 0x07, 0x0e, 0x00, 0x07, 0x02, 0x00,
    0x00, 0x07, 0x0e, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x07, 0x0e, 0x00, 0x0e, 0x00, 0x07, 0x0e, 0x00, 0x02,
    0x01, 0x01, 0x0f, 0x1c, 0x01, 0x18, 0x04, 0x00, 0x00, 0x01, 0x03, 0x00, 0x81, 0x80, 0x04, 0xc4, 0x02,
    0x01, 0x01, 0xdc, 0x02, 0x01, 0x01, 0xf0, 0x02, 0x01, 0x01, 0x84, 0x03, 0x00, 0x00, 0x00, 0x0f, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0xb0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0xf4, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x1c, 0x01, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x01, 0x00,
    0x00, 0x01, 0x20, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x44, 0x01, 0x00, 0x00, 0x06, 0x20, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x9c, 0x01, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xbc,
    0x01, 0x00, 0x00, 0x02, 0x20, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0xcc, 0x01, 0x00, 0x00, 0x03, 0x20,
    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x17, 0x03, 0x00, 0x00, 0x04, 0x20, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x2f, 0x03, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x37, 0x03, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x50, 0x03, 0x00, 0x00,
];
function useTrustManager(loader) {
    loader ??= Java.classFactory.loader ?? undefined;
    if (!loader) {
        throw Error('ClassLoader not found !');
    }
    const InMemoryDexClassLoader = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_1__.findClass)(_clockwork_common__WEBPACK_IMPORTED_MODULE_1__.ClassesString.InMemoryDexClassLoader, loader);
    const ByteBuffer = (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_1__.findClass)(_clockwork_common__WEBPACK_IMPORTED_MODULE_1__.ClassesString.ByteBuffer, loader);
    if (!InMemoryDexClassLoader || !ByteBuffer) {
        throw Error(`InMemoryDexClassLoader: ${InMemoryDexClassLoader}, ByteBuffer: ${ByteBuffer}`);
    }
    const inMemory = InMemoryDexClassLoader.$new(ByteBuffer.wrap(Java.array('B', dexBytes)), loader);
    return (0,_clockwork_common__WEBPACK_IMPORTED_MODULE_1__.findClass)(className, inMemory);
}
function injectSsl() {
    const uniqHook = (0,_clockwork_hooks__WEBPACK_IMPORTED_MODULE_0__.getHookUnique)(false);
    const mTrustManagers = [];
    uniqHook('javax.net.ssl.SSLContext', 'init', {
        replace(method, ...args) {
            if (mTrustManagers.length === 0) {
                const clsLoader = this.getClass().getClassLoader();
                const mgr = useTrustManager(clsLoader)?.$new();
                if (mgr)
                    mTrustManagers.push(Java.retain(mgr));
            }
            if (mTrustManagers.length > 0) {
                args[1] = mTrustManagers;
            }
            return method.call(this, ...args);
        },
        logging: { return: false, arguments: false, short: true },
    });
    uniqHook('okhttp3.CertificatePinner', 'check', {
        replace: () => { },
        logging: { return: false, arguments: false, short: true },
    });
    uniqHook('com.android.org.conscrypt.TrustManagerImpl', 'verifyChain', {
        replace: (_, ...params) => params[0],
        logging: { return: false, arguments: false, short: true },
    });
    uniqHook('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier', 'verify', {
        replace: (0,_clockwork_hooks_dist_addons_js__WEBPACK_IMPORTED_MODULE_2__.always)(true),
        logging: { return: false, arguments: false, short: true },
    });
    uniqHook('appcelerator.https.PinningTrustManager', 'checkServerTrusted', {
        replace: (0,_clockwork_hooks_dist_addons_js__WEBPACK_IMPORTED_MODULE_2__.always)(null),
        logging: { return: false, arguments: false, short: true },
    });
}

//# sourceMappingURL=trustmanager.js.map

/***/ }),

/***/ "./packages/unity/dist/index.js":
/*!**************************************!*\
  !*** ./packages/unity/dist/index.js ***!
  \**************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   attachScenes: () => (/* binding */ attachScenes),
/* harmony export */   attachStrings: () => (/* binding */ attachStrings),
/* harmony export */   listGameObjects: () => (/* binding */ listGameObjects),
/* harmony export */   mempatchSsl: () => (/* binding */ mempatchSsl),
/* harmony export */   patchSsl: () => (/* binding */ patchSsl),
/* harmony export */   setVersion: () => (/* binding */ setVersion),
/* harmony export */   unitypatchSsl: () => (/* binding */ unitypatchSsl)
/* harmony export */ });
/* harmony import */ var _clockwork_logging__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @clockwork/logging */ "./packages/logging/dist/index.js");
/* harmony import */ var _clockwork_native__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @clockwork/native */ "./packages/native/dist/index.js");
/* harmony import */ var frida_il2cpp_bridge__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! frida-il2cpp-bridge */ "./node_modules/frida-il2cpp-bridge/dist/index.js");



const logger = (0,_clockwork_logging__WEBPACK_IMPORTED_MODULE_0__.subLogger)('unity');
function setVersion(version) {
    globalThis.IL2CPP_UNITY_VERSION = version;
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
            .filterMethods((m) => !m.name.includes('get_Chars') &&
            !m.name.includes('FastAllocateString') &&
            // !m.name.includes('FillStringChecked') &&
            !m.name.includes('CtorCharArrayStartLength') &&
            m.name !== 'Ctor' &&
            m.name !== 'CreateString' &&
            m.name !== 'wstrcpy')
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
        const WebRequest = Il2Cpp.domain.assembly('UnityEngine.UnityWebRequestModule').image;
        const CertificateHandler = WebRequest.class('UnityEngine.Networking.CertificateHandler');
        const ValidateCertificateNative = CertificateHandler.method('ValidateCertificateNative');
        ValidateCertificateNative.implementation = (...args) => true;
        const TlsProvider = Il2Cpp.domain.assembly('System').image.class('Mono.Unity.UnityTlsProvider');
        const ValidateCertificate = TlsProvider.method('ValidateCertificate');
        ValidateCertificate.implementation = (...args) => true;
    });
}
function mempatchSsl() {
    _clockwork_native__WEBPACK_IMPORTED_MODULE_1__.Inject.afterInitArrayModule((m) => {
        const pattern = 'f? ?? ?c ?? f7 5b 01 a9 f5 53 02 a9 f3 7b 03 a9 ?? ?? 40 f9 f3 03 02 aa f4 03 01 aa ?? ?? 40 f9';
        Memory.scan(m.base, m.size, pattern, {
            onMatch(address, size) {
                logger.info(`Memory.scan() found match at ${address.sub(m.base)} with size ${size}\nGhidra addr ${address.sub(m.base).add(0x100000)}`);
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
        const fmt = (gmObj) => {
            return `${gmObj}`;
        };
        const snap = Il2Cpp.MemorySnapshot.capture();
        if (!snap)
            return;
        for (const obj of snap.objects) {
            logger.info({ tag: 'il2cpp' }, fmt(obj));
        }
    });
}

//# sourceMappingURL=index.js.map

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/global */
/******/ 	(() => {
/******/ 		__webpack_require__.g = (function() {
/******/ 			if (typeof globalThis === 'object') return globalThis;
/******/ 			try {
/******/ 				return this || new Function('return this')();
/******/ 			} catch (e) {
/******/ 				if (typeof window === 'object') return window;
/******/ 			}
/******/ 		})();
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __webpack_require__("./agent/index.ts");
/******/ 	
/******/ })()
;