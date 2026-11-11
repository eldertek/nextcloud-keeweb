const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/**
 * Decodes RFC 4648 Base32 secrets tolerantly (case-insensitive, ignores spaces, hyphens, and missing '=' padding).
 */
export function decodeBase32Secret(input) {
    if (typeof input !== 'string') {
        throw new Error('OTP secret must be a string')
    }
    const cleaned = input.toUpperCase().replace(/[\s\-=]+/g, '')
    if (cleaned.length === 0) {
        throw new Error('OTP secret is empty')
    }

    let bits = 0
    let value = 0
    const bytes = []

    for (let i = 0; i < cleaned.length; i += 1) {
        const idx = BASE32_ALPHABET.indexOf(cleaned[i])
        if (idx === -1) {
            throw new Error(`Invalid Base32 character: ${cleaned[i]}`)
        }
        value = (value << 5) | idx
        bits += 5
        if (bits >= 8) {
            bits -= 8
            bytes.push((value >>> bits) & 0xff)
        }
    }

    return new Uint8Array(bytes)
}

function decodeHexSecret(input) {
    const cleaned = String(input).trim().replace(/\s+/g, '')
    if (cleaned.length === 0 || cleaned.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(cleaned)) {
        throw new Error('Invalid hexadecimal OTP secret')
    }
    const out = new Uint8Array(cleaned.length / 2)
    for (let i = 0; i < cleaned.length; i += 2) {
        out[i / 2] = parseInt(cleaned.slice(i, i + 2), 16)
    }
    return out
}

function normalizeAlgorithm(raw) {
    const upper = String(raw || 'SHA1').toUpperCase().replace(/[^A-Z0-9]/g, '')
    if (upper === 'SHA256' || upper === 'HMACSHA256') {
        return 'SHA-256'
    }
    if (upper === 'SHA512' || upper === 'HMACSHA512') {
        return 'SHA-512'
    }
    return 'SHA-1'
}

/**
 * Extracts normalized TOTP configuration from an entry's plain fields map.
 * Supports otpauth://totp URIs (KeePassXC / Strongbox), KeePass 2 TimeOtp-* fields,
 * Keepass2Android TOTP Seed / TOTP Settings, or a bare Base32 secret in `otp` / `TOTP`.
 */
export function extractTotpConfigFromFields(plainFields) {
    if (!plainFields || typeof plainFields !== 'object') {
        return null
    }

    const otpRaw = plainFields.otp || plainFields.OTP || plainFields.TOTP || plainFields.totp || ''
    if (typeof otpRaw === 'string' && otpRaw.trim() !== '') {
        const trimmed = otpRaw.trim()
        if (trimmed.toLowerCase().startsWith('otpauth://')) {
            try {
                const parsed = new URL(trimmed)
                if (parsed.host.toLowerCase() !== 'totp' && !parsed.pathname.toLowerCase().includes('totp')) {
                    return null
                }
                const secretParam = parsed.searchParams.get('secret')
                if (!secretParam) {
                    return null
                }
                const secretBytes = decodeBase32Secret(secretParam)
                const digits = Math.min(10, Math.max(6, parseInt(parsed.searchParams.get('digits') || '6', 10) || 6))
                const period = Math.max(5, parseInt(parsed.searchParams.get('period') || '30', 10) || 30)
                const algorithm = normalizeAlgorithm(parsed.searchParams.get('algorithm') || 'SHA1')
                return { secretBytes, digits, period, algorithm, raw: trimmed }
            } catch {
                return null
            }
        }

        try {
            const secretBytes = decodeBase32Secret(trimmed)
            return { secretBytes, digits: 6, period: 30, algorithm: 'SHA-1', raw: trimmed }
        } catch {
            return null
        }
    }

    const kpBase32 = plainFields['TimeOtp-Secret-Base32'] || plainFields['TOTP Seed'] || ''
    const kpHex = plainFields['TimeOtp-Secret-Hex'] || ''
    if (!kpBase32 && !kpHex) {
        return null
    }

    try {
        const secretBytes = kpBase32 ? decodeBase32Secret(kpBase32) : decodeHexSecret(kpHex)
        let period = parseInt(plainFields['TimeOtp-Period'] || '30', 10) || 30
        let digits = parseInt(plainFields['TimeOtp-Length'] || '6', 10) || 6
        if (typeof plainFields['TOTP Settings'] === 'string') {
            const parts = plainFields['TOTP Settings'].split(';')
            if (parts.length >= 2) {
                period = parseInt(parts[0], 10) || period
                digits = parseInt(parts[1], 10) || digits
            }
        }
        const algorithm = normalizeAlgorithm(plainFields['TimeOtp-Algorithm'] || 'SHA1')
        return {
            secretBytes,
            digits: Math.min(10, Math.max(6, digits)),
            period: Math.max(5, period),
            algorithm,
            raw: kpBase32 || kpHex,
        }
    } catch {
        return null
    }
}

/**
 * Generates an RFC 6238 TOTP code at the specified timestamp (milliseconds).
 */
export async function generateTotpCode(totpConfig, nowMs = Date.now()) {
    if (!totpConfig || !(totpConfig.secretBytes instanceof Uint8Array) || totpConfig.secretBytes.length === 0) {
        throw new Error('Invalid TOTP configuration')
    }
    const subtle = globalThis.crypto && globalThis.crypto.subtle
    if (!subtle) {
        throw new Error('WebCrypto subtle API is unavailable')
    }

    const { secretBytes, digits = 6, period = 30, algorithm = 'SHA-1' } = totpConfig
    const epochSeconds = Math.floor(nowMs / 1000)
    const counter = Math.floor(epochSeconds / period)
    const remainingSeconds = period - (epochSeconds % period)

    const counterBytes = new Uint8Array(8)
    let temp = counter
    for (let i = 7; i >= 0; i -= 1) {
        counterBytes[i] = temp & 0xff
        temp = Math.floor(temp / 256)
    }

    const cryptoKey = await subtle.importKey(
        'raw',
        secretBytes,
        { name: 'HMAC', hash: { name: algorithm } },
        false,
        ['sign'],
    )

    const macBuffer = await subtle.sign('HMAC', cryptoKey, counterBytes)
    const mac = new Uint8Array(macBuffer)
    const offset = mac[mac.length - 1] & 0x0f
    const binary =
        ((mac[offset] & 0x7f) << 24) |
        ((mac[offset + 1] & 0xff) << 16) |
        ((mac[offset + 2] & 0xff) << 8) |
        (mac[offset + 3] & 0xff)

    const mod = 10 ** digits
    const code = String(binary % mod).padStart(digits, '0')

    return {
        code,
        digits,
        period,
        remainingSeconds,
    }
}
