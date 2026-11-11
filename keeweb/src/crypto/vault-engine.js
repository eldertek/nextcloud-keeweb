import * as kdbxwebModule from 'kdbxweb'
import { computeArgon2Hash } from './argon2-core.js'
import { extractTotpConfigFromFields } from './totp.js'

const kdbxweb = kdbxwebModule.default || kdbxwebModule

const STANDARD_FIELDS = new Set(['Title', 'UserName', 'Password', 'URL', 'Notes'])
const OTP_AUX_FIELDS = new Set([
    'otp',
    'OTP',
    'TOTP',
    'totp',
    'TimeOtp-Secret-Base32',
    'TimeOtp-Secret-Hex',
    'TimeOtp-Period',
    'TimeOtp-Length',
    'TimeOtp-Algorithm',
    'TOTP Seed',
    'TOTP Settings',
])

let configuredWorkerUrl = ''
let activeWorker = null
let workerRequestSeq = 0
const pendingWorkerCalls = new Map()

function getOrCreateWorker() {
    if (!configuredWorkerUrl || typeof Worker !== 'function') {
        return null
    }
    if (activeWorker) {
        return activeWorker
    }
    try {
        const worker = new Worker(configuredWorkerUrl)
        worker.addEventListener('message', (event) => {
            const { id, ok, hash, error } = event.data || {}
            const pending = pendingWorkerCalls.get(id)
            if (!pending) {
                return
            }
            pendingWorkerCalls.delete(id)
            if (ok) {
                pending.resolve(hash)
            } else {
                pending.reject(new Error(error || 'Argon2 worker calculation failed'))
            }
        })
        worker.addEventListener('error', () => {
            for (const [, pending] of pendingWorkerCalls) {
                pending.reject(new Error('Argon2 worker crashed'))
            }
            pendingWorkerCalls.clear()
            activeWorker = null
        })
        activeWorker = worker
        return activeWorker
    } catch {
        return null
    }
}

async function runArgon2(password, salt, memory, iterations, length, parallelism, type, version) {
    const worker = getOrCreateWorker()
    if (worker) {
        try {
            const pwCopy = password.slice(0)
            const saltCopy = salt.slice(0)
            return await new Promise((resolve, reject) => {
                workerRequestSeq += 1
                const id = workerRequestSeq
                pendingWorkerCalls.set(id, { resolve, reject })
                worker.postMessage(
                    {
                        id,
                        password: pwCopy,
                        salt: saltCopy,
                        memory,
                        iterations,
                        length,
                        parallelism,
                        type,
                        version,
                    },
                    [pwCopy, saltCopy],
                )
            })
        } catch {
            // Fall back to main-thread Argon2 if worker dispatch fails
        }
    }

    return computeArgon2Hash({
        password,
        salt,
        memory,
        iterations,
        length,
        parallelism,
        type,
        version,
    })
}

kdbxweb.CryptoEngine.setArgon2Impl((password, salt, memory, iterations, length, parallelism, type, version) =>
    runArgon2(password, salt, memory, iterations, length, parallelism, type, version),
)

export function configureArgon2Runtime({ workerUrl = '' } = {}) {
    configuredWorkerUrl = typeof workerUrl === 'string' ? workerUrl.trim() : ''
}

function toArrayBuffer(input) {
    if (!input) {
        return null
    }
    if (input instanceof ArrayBuffer) {
        return input
    }
    if (ArrayBuffer.isView(input)) {
        return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength)
    }
    throw new Error('Expected ArrayBuffer or TypedArray')
}

function uuidToString(uuid) {
    if (!uuid) {
        return ''
    }
    return typeof uuid === 'string' ? uuid : String(uuid.id || uuid.toString())
}

function readFieldString(val) {
    if (val === undefined || val === null) {
        return ''
    }
    if (val instanceof kdbxweb.ProtectedValue) {
        return val.getText()
    }
    return String(val)
}

export function describeVaultHeader(db) {
    const major = db.header?.versionMajor ?? 4
    const minor = db.header?.versionMinor ?? 0
    let kdfName = major === 3 ? 'AES-KDF' : 'Argon2'

    const kdfParams = db.header?.kdfParameters
    if (kdfParams) {
        const rawUuid = kdfParams.get('$UUID')
        if (rawUuid) {
            const b64 = kdbxweb.ByteUtils.bytesToBase64(rawUuid)
            if (b64 === kdbxweb.Consts.KdfId.Argon2id) {
                kdfName = 'Argon2id'
            } else if (b64 === kdbxweb.Consts.KdfId.Argon2d) {
                kdfName = 'Argon2d'
            } else if (b64 === kdbxweb.Consts.KdfId.Aes) {
                kdfName = 'AES-KDF'
            }
        }
    }

    const cipherId = uuidToString(db.header?.dataCipherUuid)
    let cipherName = 'AES-256'
    if (cipherId === kdbxweb.Consts.CipherId.ChaCha20) {
        cipherName = 'ChaCha20'
    }

    return {
        name: db.meta?.name || 'Vault',
        description: db.meta?.desc || '',
        versionMajor: major,
        versionMinor: minor,
        versionLabel: `KDBX ${major}.${minor}`,
        kdfName,
        cipherName,
        recycleBinEnabled: Boolean(db.meta?.recycleBinEnabled),
        recycleBinUuid: uuidToString(db.meta?.recycleBinUuid),
    }
}

/**
 * Unlocks an encrypted KDBX 3.x or KDBX 4.x database client-side.
 */
export async function unlockVault(rawData, { password = '', keyFileBytes = null } = {}) {
    const buffer = toArrayBuffer(rawData)
    if (!buffer || buffer.byteLength < 64) {
        throw new Error('The selected file is empty or too small to be a KDBX database.')
    }

    const keyBuf = keyFileBytes ? toArrayBuffer(keyFileBytes) : null
    const hasPassword = typeof password === 'string' && password.length > 0

    const attemptFactories = []
    if (hasPassword) {
        attemptFactories.push(() =>
            new kdbxweb.Credentials(
                kdbxweb.ProtectedValue.fromString(password),
                keyBuf ? keyBuf.slice(0) : null,
            ),
        )
    } else if (keyBuf) {
        attemptFactories.push(() => new kdbxweb.Credentials(null, keyBuf.slice(0)))
        attemptFactories.push(() =>
            new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(''), keyBuf.slice(0)),
        )
    } else {
        attemptFactories.push(() => new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(''), null))
    }

    let lastError = null
    for (const makeCredentials of attemptFactories) {
        try {
            const credentials = makeCredentials()
            await credentials.ready
            const db = await kdbxweb.Kdbx.load(buffer.slice(0), credentials)
            return {
                db,
                meta: describeVaultHeader(db),
            }
        } catch (err) {
            lastError = err
            if (!(err instanceof kdbxweb.KdbxError) || err.code !== kdbxweb.Consts.ErrorCodes.InvalidKey) {
                break
            }
        }
    }

    if (lastError instanceof kdbxweb.KdbxError) {
        if (lastError.code === kdbxweb.Consts.ErrorCodes.InvalidKey) {
            throw new Error('Invalid master password or key file.')
        }
        if (lastError.code === kdbxweb.Consts.ErrorCodes.BadSignature) {
            throw new Error('File is not a valid KeePass KDBX database.')
        }
        if (lastError.code === kdbxweb.Consts.ErrorCodes.InvalidVersion) {
            throw new Error('Unsupported KDBX format version.')
        }
    }

    throw lastError instanceof Error ? lastError : new Error('Failed to decrypt KDBX database.')
}

/**
 * Creates a brand-new KDBX 4.1 (Argon2id + ChaCha20/AES) or KDBX 3.1 (AES-KDF) database in memory.
 */
export async function createNewVault({
    name = 'Passwords',
    password = '',
    keyFileBytes = null,
    formatVersion = 4,
    argon2MemoryKiB = 32768,
    argon2Iterations = 3,
    argon2Parallelism = 2,
} = {}) {
    const keyBuf = keyFileBytes ? toArrayBuffer(keyFileBytes) : null
    const hasPassword = typeof password === 'string' && password.length > 0
    if (!hasPassword && !keyBuf) {
        throw new Error('A master password or key file is required to create a vault.')
    }

    const pwVal = hasPassword ? kdbxweb.ProtectedValue.fromString(password) : (keyBuf ? null : kdbxweb.ProtectedValue.fromString(''))
    const credentials = new kdbxweb.Credentials(pwVal, keyBuf ? keyBuf.slice(0) : null)
    await credentials.ready

    const db = kdbxweb.Kdbx.create(credentials, name.trim() || 'Passwords')

    if (formatVersion === 3) {
        db.setVersion(3)
    } else {
        db.setVersion(4)
        db.setKdf(kdbxweb.Consts.KdfId.Argon2id)
        db.header.versionMinor = 1
        if (db.header.kdfParameters) {
            const VT = kdbxweb.VarDictionary.ValueType
            db.header.kdfParameters.set('M', VT.UInt64, kdbxweb.Int64.from(argon2MemoryKiB * 1024))
            db.header.kdfParameters.set('I', VT.UInt64, kdbxweb.Int64.from(argon2Iterations))
            db.header.kdfParameters.set('P', VT.UInt32, argon2Parallelism)
        }
    }

    return {
        db,
        meta: describeVaultHeader(db),
    }
}

/**
 * Serializes a Kdbx database back into encrypted binary bytes without downgrading format version.
 */
export async function saveVaultToBytes(db) {
    const arrayBuffer = await db.save()
    return new Uint8Array(arrayBuffer)
}

function countEntriesDeep(group) {
    let total = Array.isArray(group.entries) ? group.entries.length : 0
    if (Array.isArray(group.groups)) {
        for (const child of group.groups) {
            total += countEntriesDeep(child)
        }
    }
    return total
}

export function serializeGroupTree(db) {
    const recycleUuid = db.meta?.recycleBinEnabled ? uuidToString(db.meta?.recycleBinUuid) : ''

    function mapGroup(group, depth = 0) {
        const uuid = uuidToString(group.uuid)
        const isRecycleBin = Boolean(recycleUuid && uuid === recycleUuid)
        const children = (group.groups || []).map((child) => mapGroup(child, depth + 1))
        return {
            uuid,
            name: group.name || 'Unnamed group',
            depth,
            isRecycleBin,
            directEntryCount: (group.entries || []).length,
            totalEntryCount: countEntriesDeep(group),
            children,
        }
    }

    return (db.groups || []).map((rootGroup) => mapGroup(rootGroup, 0))
}

export function findGroupByUuid(db, groupUuid) {
    if (!groupUuid) {
        return db.getDefaultGroup()
    }
    function walk(groups) {
        for (const g of groups || []) {
            if (uuidToString(g.uuid) === groupUuid) {
                return g
            }
            const nested = walk(g.groups)
            if (nested) {
                return nested
            }
        }
        return null
    }
    return walk(db.groups)
}

export function findEntryByUuid(db, entryUuid) {
    if (!entryUuid) {
        return null
    }
    function walk(groups) {
        for (const g of groups || []) {
            for (const entry of g.entries || []) {
                if (uuidToString(entry.uuid) === entryUuid) {
                    return { entry, group: g }
                }
            }
            const nested = walk(g.groups)
            if (nested) {
                return nested
            }
        }
        return null
    }
    return walk(db.groups)
}

function extractEntryPlainFields(entry) {
    const out = {}
    if (entry.fields && typeof entry.fields.forEach === 'function') {
        entry.fields.forEach((val, key) => {
            out[key] = readFieldString(val)
        })
    }
    return out
}

export function serializeEntryDetail(db, entryUuid) {
    const found = findEntryByUuid(db, entryUuid)
    if (!found) {
        return null
    }
    const { entry, group } = found
    const plainFields = extractEntryPlainFields(entry)
    const totpConfig = extractTotpConfigFromFields(plainFields)

    const customFields = []
    if (entry.fields && typeof entry.fields.forEach === 'function') {
        entry.fields.forEach((val, key) => {
            if (STANDARD_FIELDS.has(key) || OTP_AUX_FIELDS.has(key)) {
                return
            }
            customFields.push({
                key,
                value: readFieldString(val),
                protected: val instanceof kdbxweb.ProtectedValue,
            })
        })
    }

    const attachments = []
    if (entry.binaries && typeof entry.binaries.forEach === 'function') {
        entry.binaries.forEach((bin, name) => {
            const rawVal = bin && bin.value ? bin.value : bin
            let size = 0
            if (rawVal instanceof kdbxweb.ProtectedValue) {
                size = rawVal.byteLength
            } else if (rawVal instanceof ArrayBuffer) {
                size = rawVal.byteLength
            } else if (ArrayBuffer.isView(rawVal)) {
                size = rawVal.byteLength
            }
            attachments.push({ name, size })
        })
    }

    return {
        uuid: uuidToString(entry.uuid),
        groupUuid: uuidToString(group.uuid),
        groupName: group.name || '',
        title: plainFields.Title || '',
        username: plainFields.UserName || '',
        password: plainFields.Password || '',
        url: plainFields.URL || '',
        notes: plainFields.Notes || '',
        otpRaw: plainFields.otp || plainFields.OTP || plainFields.TOTP || plainFields['TimeOtp-Secret-Base32'] || '',
        totpConfig,
        hasTotp: Boolean(totpConfig),
        tags: Array.isArray(entry.tags) ? [...entry.tags] : [],
        customFields,
        attachments,
        creationTime: entry.times?.creationTime ? entry.times.creationTime.toISOString() : null,
        lastModTime: entry.times?.lastModTime ? entry.times.lastModTime.toISOString() : null,
    }
}

export function getEntryAttachmentBytes(db, entryUuid, attachmentName) {
    const found = findEntryByUuid(db, entryUuid)
    if (!found || !found.entry.binaries) {
        return null
    }
    const bin = found.entry.binaries.get(attachmentName)
    if (!bin) {
        return null
    }
    const rawVal = bin.value ? bin.value : bin
    if (rawVal instanceof kdbxweb.ProtectedValue) {
        return new Uint8Array(rawVal.getBinary())
    }
    if (rawVal instanceof ArrayBuffer) {
        return new Uint8Array(rawVal)
    }
    if (ArrayBuffer.isView(rawVal)) {
        return new Uint8Array(rawVal.buffer, rawVal.byteOffset, rawVal.byteLength)
    }
    return null
}

/**
 * Lists and filters entries across the vault or inside a specific group.
 */
export function queryEntries(db, { groupUuid = null, searchQuery = '', includeRecycleBin = false } = {}) {
    const recycleUuid = db.meta?.recycleBinEnabled ? uuidToString(db.meta?.recycleBinUuid) : ''
    const needle = String(searchQuery || '').trim().toLowerCase()
    const results = []

    function collectFromGroup(group, insideRecycleBin = false) {
        const currentUuid = uuidToString(group.uuid)
        const isRecycle = insideRecycleBin || Boolean(recycleUuid && currentUuid === recycleUuid)

        const viewingRecycleDirectly = Boolean(groupUuid && groupUuid === recycleUuid)
        if (isRecycle && !includeRecycleBin && !viewingRecycleDirectly) {
            return
        }

        const includeThisGroup = !groupUuid || currentUuid === groupUuid
        if (includeThisGroup) {
            for (const entry of group.entries || []) {
                const plain = extractEntryPlainFields(entry)
                const tags = Array.isArray(entry.tags) ? entry.tags : []
                if (needle) {
                    const haystackParts = [
                        plain.Title || '',
                        plain.UserName || '',
                        plain.URL || '',
                        plain.Notes || '',
                        tags.join(' '),
                    ]
                    for (const [k, v] of Object.entries(plain)) {
                        if (!STANDARD_FIELDS.has(k) && k !== 'Password') {
                            haystackParts.push(k, v)
                        }
                    }
                    const matches = haystackParts.some((part) => part.toLowerCase().includes(needle))
                    if (!matches) {
                        continue
                    }
                }
                const totpConfig = extractTotpConfigFromFields(plain)
                results.push({
                    uuid: uuidToString(entry.uuid),
                    groupUuid: currentUuid,
                    groupName: group.name || '',
                    isRecycleBin: isRecycle,
                    title: plain.Title || 'Untitled entry',
                    username: plain.UserName || '',
                    url: plain.URL || '',
                    tags,
                    hasPassword: Boolean(plain.Password),
                    hasTotp: Boolean(totpConfig),
                    lastModTime: entry.times?.lastModTime ? entry.times.lastModTime.getTime() : 0,
                })
            }
        }

        for (const child of group.groups || []) {
            if (!groupUuid) {
                collectFromGroup(child, isRecycle)
            } else if (currentUuid === groupUuid) {
                collectSubtree(child, isRecycle)
            } else {
                collectFromGroup(child, isRecycle)
            }
        }
    }

    function collectSubtree(group, isRecycle) {
        const currentUuid = uuidToString(group.uuid)
        for (const entry of group.entries || []) {
            const plain = extractEntryPlainFields(entry)
            const tags = Array.isArray(entry.tags) ? entry.tags : []
            if (needle) {
                const matches = [plain.Title || '', plain.UserName || '', plain.URL || '', plain.Notes || '', tags.join(' ')]
                    .some((part) => part.toLowerCase().includes(needle))
                if (!matches) {
                    continue
                }
            }
            const totpConfig = extractTotpConfigFromFields(plain)
            results.push({
                uuid: uuidToString(entry.uuid),
                groupUuid: currentUuid,
                groupName: group.name || '',
                isRecycleBin: isRecycle,
                title: plain.Title || 'Untitled entry',
                username: plain.UserName || '',
                url: plain.URL || '',
                tags,
                hasPassword: Boolean(plain.Password),
                hasTotp: Boolean(totpConfig),
                lastModTime: entry.times?.lastModTime ? entry.times.lastModTime.getTime() : 0,
            })
        }
        for (const child of group.groups || []) {
            collectSubtree(child, isRecycle)
        }
    }

    for (const root of db.groups || []) {
        collectFromGroup(root, false)
    }

    results.sort((a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: 'base' }))
    return results
}

function applyFieldsToEntry(entry, payload) {
    entry.fields.set('Title', String(payload.title ?? '').trim())
    entry.fields.set('UserName', String(payload.username ?? ''))
    entry.fields.set('Password', kdbxweb.ProtectedValue.fromString(String(payload.password ?? '')))
    entry.fields.set('URL', String(payload.url ?? '').trim())
    entry.fields.set('Notes', String(payload.notes ?? ''))

    if (payload.otpRaw !== undefined) {
        const otpTrimmed = String(payload.otpRaw || '').trim()
        if (otpTrimmed) {
            const formattedOtp = otpTrimmed.toLowerCase().startsWith('otpauth://')
                ? otpTrimmed
                : `otpauth://totp/${encodeURIComponent(String(payload.title || 'Account').trim())}?secret=${encodeURIComponent(otpTrimmed.replace(/\s+/g, ''))}&digits=6&period=30`
            entry.fields.set('otp', kdbxweb.ProtectedValue.fromString(formattedOtp))
        } else {
            entry.fields.delete('otp')
            entry.fields.delete('OTP')
            entry.fields.delete('TOTP')
            entry.fields.delete('TimeOtp-Secret-Base32')
            entry.fields.delete('TimeOtp-Secret-Hex')
        }
    }

    if (Array.isArray(payload.tags)) {
        entry.tags = payload.tags.map((t) => String(t).trim()).filter(Boolean)
    } else if (typeof payload.tags === 'string') {
        entry.tags = payload.tags.split(',').map((t) => t.trim()).filter(Boolean)
    }

    if (Array.isArray(payload.customFields)) {
        const existingKeys = []
        entry.fields.forEach((_, key) => {
            if (!STANDARD_FIELDS.has(key) && !OTP_AUX_FIELDS.has(key)) {
                existingKeys.push(key)
            }
        })
        for (const key of existingKeys) {
            entry.fields.delete(key)
        }
        for (const item of payload.customFields) {
            const fieldKey = String(item.key || '').trim()
            if (!fieldKey || STANDARD_FIELDS.has(fieldKey)) {
                continue
            }
            const strVal = String(item.value ?? '')
            entry.fields.set(
                fieldKey,
                item.protected ? kdbxweb.ProtectedValue.fromString(strVal) : strVal,
            )
        }
    }

    if (entry.times && typeof entry.times.update === 'function') {
        entry.times.update()
    }
}

export function createVaultEntry(db, groupUuid, payload = {}) {
    const targetGroup = findGroupByUuid(db, groupUuid) || db.getDefaultGroup()
    const entry = db.createEntry(targetGroup)
    applyFieldsToEntry(entry, payload)
    return serializeEntryDetail(db, uuidToString(entry.uuid))
}

export function updateVaultEntry(db, entryUuid, payload = {}) {
    const found = findEntryByUuid(db, entryUuid)
    if (!found) {
        throw new Error('Entry not found in vault')
    }
    const { entry, group } = found
    entry.pushHistory()
    applyFieldsToEntry(entry, payload)

    if (payload.groupUuid && payload.groupUuid !== uuidToString(group.uuid)) {
        const newGroup = findGroupByUuid(db, payload.groupUuid)
        if (newGroup) {
            db.move(entry, newGroup)
        }
    }

    return serializeEntryDetail(db, uuidToString(entry.uuid))
}

export function deleteVaultEntry(db, entryUuid) {
    const found = findEntryByUuid(db, entryUuid)
    if (!found) {
        throw new Error('Entry not found in vault')
    }
    const recycleUuid = db.meta?.recycleBinEnabled ? uuidToString(db.meta?.recycleBinUuid) : ''
    const inRecycleBin = Boolean(recycleUuid && uuidToString(found.group.uuid) === recycleUuid)
    if (inRecycleBin) {
        db.move(found.entry, null)
    } else {
        db.remove(found.entry)
    }
}

export function createVaultGroup(db, parentGroupUuid, name) {
    const cleanName = String(name || '').trim()
    if (!cleanName) {
        throw new Error('Group name cannot be empty')
    }
    const parent = findGroupByUuid(db, parentGroupUuid) || db.getDefaultGroup()
    const created = db.createGroup(parent, cleanName)
    return {
        uuid: uuidToString(created.uuid),
        name: created.name,
    }
}

/**
 * Generates a cryptographically strong random password without modulo bias.
 */
export function generateRandomPassword({
    length = 20,
    upper = true,
    lower = true,
    digits = true,
    symbols = true,
} = {}) {
    const pools = []
    if (lower) pools.push('abcdefghijkmnopqrstuvwxyz')
    if (upper) pools.push('ABCDEFGHJKLMNPQRSTUVWXYZ')
    if (digits) pools.push('23456789')
    if (symbols) pools.push('!@#$%^&*()-_=+[]{};:,.?')

    if (pools.length === 0) {
        pools.push('abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789')
    }

    const safeLen = Math.min(128, Math.max(6, Number(length) || 20))
    const combined = pools.join('')

    function randomInt(maxExclusive) {
        const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive
        const buf = new Uint32Array(1)
        let candidate = 0
        do {
            globalThis.crypto.getRandomValues(buf)
            candidate = buf[0]
        } while (candidate >= limit)
        return candidate % maxExclusive
    }

    const chars = []
    for (const pool of pools) {
        if (chars.length < safeLen) {
            chars.push(pool[randomInt(pool.length)])
        }
    }
    while (chars.length < safeLen) {
        chars.push(combined[randomInt(combined.length)])
    }

    for (let i = chars.length - 1; i > 0; i -= 1) {
        const j = randomInt(i + 1)
        const tmp = chars[i]
        chars[i] = chars[j]
        chars[j] = tmp
    }

    return chars.join('')
}
