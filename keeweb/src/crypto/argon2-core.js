import { argon2d as wasmArgon2d, argon2id as wasmArgon2id } from 'hash-wasm'
import { argon2dAsync as nobleArgon2dAsync, argon2idAsync as nobleArgon2idAsync } from '@noble/hashes/argon2'

export const ARGON2_TYPE_D = 0
export const ARGON2_TYPE_ID = 2

function toExactArrayBuffer(bytes) {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
}

/**
 * Computes Argon2d or Argon2id hash compatible with kdbxweb CryptoEngine.setArgon2Impl.
 * Uses WebAssembly (hash-wasm) for Argon2 v1.3 (0x13) when available under CSP wasm-unsafe-eval,
 * and falls back transparently to pure-JS (@noble/hashes) if WASM is restricted or version is 0x10.
 */
export async function computeArgon2Hash({
    password,
    salt,
    memory,
    iterations,
    length,
    parallelism,
    type,
    version,
}) {
    const passwordBytes = password instanceof Uint8Array ? password : new Uint8Array(password)
    const saltBytes = salt instanceof Uint8Array ? salt : new Uint8Array(salt)
    const normalizedVersion = version === 0x10 ? 0x10 : 0x13
    const isArgon2id = type === ARGON2_TYPE_ID

    if (normalizedVersion === 0x13) {
        try {
            const fn = isArgon2id ? wasmArgon2id : wasmArgon2d
            const derived = await fn({
                password: passwordBytes,
                salt: saltBytes,
                memorySize: memory,
                iterations,
                hashLength: length,
                parallelism,
                outputType: 'binary',
            })
            return toExactArrayBuffer(derived)
        } catch {
            // Fall through to pure-JS @noble/hashes implementation if WebAssembly is unavailable
        }
    }

    const nobleFn = isArgon2id ? nobleArgon2idAsync : nobleArgon2dAsync
    const maxmem = Math.max((memory + 1024) * 1024, 1024 * 1024 * 1024)
    const derived = await nobleFn(passwordBytes, saltBytes, {
        t: iterations,
        m: memory,
        p: parallelism,
        dkLen: length,
        version: normalizedVersion,
        maxmem,
        asyncTick: 10,
    })
    return toExactArrayBuffer(derived)
}
