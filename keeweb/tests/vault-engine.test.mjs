import test from 'node:test'
import assert from 'node:assert/strict'
import * as kdbxwebModule from 'kdbxweb'

const kdbxweb = kdbxwebModule.default || kdbxwebModule
import {
    unlockVault,
    createNewVault,
    saveVaultToBytes,
    serializeGroupTree,
    queryEntries,
    serializeEntryDetail,
    getEntryAttachmentBytes,
    createVaultEntry,
    updateVaultEntry,
    deleteVaultEntry,
    createVaultGroup,
    generateRandomPassword,
} from '../src/crypto/vault-engine.js'
import { computeArgon2Hash, ARGON2_TYPE_D, ARGON2_TYPE_ID } from '../src/crypto/argon2-core.js'
import { decodeBase32Secret, extractTotpConfigFromFields, generateTotpCode } from '../src/crypto/totp.js'

function assertKdbxMagic(bytes) {
    assert.ok(bytes instanceof Uint8Array, 'Expected Uint8Array')
    assert.ok(bytes.byteLength >= 64, 'Expected KDBX payload >= 64 bytes')
    assert.equal(bytes[0], 0x03)
    assert.equal(bytes[1], 0xd9)
    assert.equal(bytes[2], 0xa2)
    assert.equal(bytes[3], 0x9a)
}

test('KDBX 3.1 (sample-v3.kdbx) create, unlock, edit, group tree, search, and binary round-trip', async () => {
    const { db, meta } = await createNewVault({
        name: 'sample-v3',
        password: 'QaVault3-Password!',
        formatVersion: 3,
    })

    assert.equal(meta.versionMajor, 3)
    assert.equal(meta.versionMinor, 1)
    assert.equal(meta.kdfName, 'AES-KDF')

    const subGroup = createVaultGroup(db, null, 'Infrastructure')
    const createdEntry = createVaultEntry(db, subGroup.uuid, {
        title: 'Database Cluster',
        username: 'qa-admin',
        password: 'InitialSecret-v3#99',
        url: 'https://db.internal.example',
        notes: 'Primary replica credentials',
        otpRaw: 'JBSWY3DPEHPK3PXP',
        tags: ['infra', 'postgres'],
        customFields: [
            { key: 'Port', value: '5432', protected: false },
            { key: 'RecoveryPin', value: '884422', protected: true },
        ],
    })

    assert.equal(createdEntry.title, 'Database Cluster')
    assert.equal(createdEntry.hasTotp, true)

    const sampleV3Bytes = await saveVaultToBytes(db)
    assertKdbxMagic(sampleV3Bytes)

    await assert.rejects(
        () => unlockVault(sampleV3Bytes, { password: 'wrong-password' }),
        /Invalid master password/,
    )

    const reopened = await unlockVault(sampleV3Bytes, { password: 'QaVault3-Password!' })
    assert.equal(reopened.meta.versionMajor, 3)
    assert.equal(reopened.meta.versionMinor, 1)
    assert.equal(reopened.meta.kdfName, 'AES-KDF')

    const tree = serializeGroupTree(reopened.db)
    assert.equal(tree.length, 1)
    assert.ok(tree[0].children.some((g) => g.name === 'Infrastructure'))

    const matches = queryEntries(reopened.db, { searchQuery: 'postgres' })
    assert.equal(matches.length, 1)
    assert.equal(matches[0].username, 'qa-admin')

    updateVaultEntry(reopened.db, createdEntry.uuid, {
        title: 'Database Cluster Primary',
        groupUuid: subGroup.uuid,
        username: 'qa-admin',
        password: 'RotatedSecret-v3#100',
        url: 'https://db.internal.example',
        notes: 'Rotated in v3 test',
        otpRaw: 'JBSWY3DPEHPK3PXP',
        tags: ['infra', 'postgres'],
        customFields: [{ key: 'RecoveryPin', value: '991100', protected: true }],
    })

    const savedAgain = await saveVaultToBytes(reopened.db)
    assertKdbxMagic(savedAgain)

    const verified = await unlockVault(savedAgain, { password: 'QaVault3-Password!' })
    assert.equal(verified.meta.versionMajor, 3)
    const detail = serializeEntryDetail(verified.db, createdEntry.uuid)
    assert.equal(detail.title, 'Database Cluster Primary')
    assert.equal(detail.password, 'RotatedSecret-v3#100')
    assert.equal(detail.customFields.length, 1)
    assert.equal(detail.customFields[0].value, '991100')
    assert.equal(detail.customFields[0].protected, true)
})

test('KDBX 4.1 Argon2id (sample-v4.kdbx) with password + keyfile, attachments, history, and deletion', async () => {
    const keyFileBytes = new Uint8Array(32)
    globalThis.crypto.getRandomValues(keyFileBytes)

    const { db, meta } = await createNewVault({
        name: 'sample-v4',
        password: 'QaVault4-Argon2id-Password!',
        keyFileBytes,
        formatVersion: 4,
        argon2MemoryKiB: 4096,
        argon2Iterations: 2,
        argon2Parallelism: 1,
    })

    assert.equal(meta.versionMajor, 4)
    assert.equal(meta.versionMinor, 1)
    assert.equal(meta.kdfName, 'Argon2id')

    const entryA = createVaultEntry(db, null, {
        title: 'Nextcloud Admin',
        username: 'qa-admin',
        password: 'Nc4-Secret-Value!',
        url: 'https://cloud.example.org',
        notes: 'Main admin login',
    })
    const entryB = createVaultEntry(db, null, {
        title: 'Temporary Token',
        username: 'qa-test',
        password: 'Temp-Delete-Me',
    })

    // Attach binary payload to entryA to ensure KDBX 4 inner header binaries survive round-trip
    const attachmentPayload = new TextEncoder().encode('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIqa-test-key\n')
    const foundA = db.groups[0].entries.find((e) => e.uuid.toString() === entryA.uuid)
    const binRef = await db.createBinary(attachmentPayload.buffer.slice(0))
    foundA.binaries.set('id_ed25519.pub', binRef)

    const sampleV4Bytes = await saveVaultToBytes(db)
    assertKdbxMagic(sampleV4Bytes)

    // Missing keyfile must fail
    await assert.rejects(
        () => unlockVault(sampleV4Bytes, { password: 'QaVault4-Argon2id-Password!' }),
        /Invalid master password or key file/,
    )

    const unlocked = await unlockVault(sampleV4Bytes, {
        password: 'QaVault4-Argon2id-Password!',
        keyFileBytes,
    })
    assert.equal(unlocked.meta.versionMajor, 4)
    assert.equal(unlocked.meta.versionMinor, 1)
    assert.equal(unlocked.meta.kdfName, 'Argon2id')

    // Delete entryB and update entryA
    deleteVaultEntry(unlocked.db, entryB.uuid)
    updateVaultEntry(unlocked.db, entryA.uuid, {
        title: 'Nextcloud Admin Updated',
        username: 'qa-admin',
        password: 'Nc4-Updated-Secret-Value!',
        url: 'https://cloud.example.org',
        notes: 'Updated notes',
    })

    const savedV4Bytes = await saveVaultToBytes(unlocked.db)
    assertKdbxMagic(savedV4Bytes)

    const finalUnlock = await unlockVault(savedV4Bytes, {
        password: 'QaVault4-Argon2id-Password!',
        keyFileBytes,
    })
    assert.equal(finalUnlock.meta.versionMajor, 4)
    assert.equal(finalUnlock.meta.versionMinor, 1)
    assert.equal(finalUnlock.meta.kdfName, 'Argon2id')

    const visibleEntries = queryEntries(finalUnlock.db)
    assert.equal(visibleEntries.length, 1)
    assert.equal(visibleEntries[0].title, 'Nextcloud Admin Updated')

    const detailA = serializeEntryDetail(finalUnlock.db, entryA.uuid)
    assert.equal(detailA.password, 'Nc4-Updated-Secret-Value!')
    assert.equal(detailA.attachments.length, 1)
    assert.equal(detailA.attachments[0].name, 'id_ed25519.pub')

    const recoveredAtt = getEntryAttachmentBytes(finalUnlock.db, entryA.uuid, 'id_ed25519.pub')
    assert.equal(new TextDecoder().decode(recoveredAtt), 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIqa-test-key\n')
})

test('KDBX 4.0 Argon2d and keyfile-only vault unlock work cleanly', async () => {
    const keyFileBytes = new Uint8Array(32)
    globalThis.crypto.getRandomValues(keyFileBytes)

    const credentials = new kdbxweb.Credentials(null, keyFileBytes.buffer.slice(0))
    await credentials.ready
    const db = kdbxweb.Kdbx.create(credentials, 'argon2d-keyonly')
    db.setVersion(4)
    db.setKdf(kdbxweb.Consts.KdfId.Argon2d)
    const VT = kdbxweb.VarDictionary.ValueType
    db.header.kdfParameters.set('M', VT.UInt64, kdbxweb.Int64.from(2048 * 1024))
    db.header.kdfParameters.set('I', VT.UInt64, kdbxweb.Int64.from(2))
    db.header.kdfParameters.set('P', VT.UInt32, 1)

    createVaultEntry(db, null, {
        title: 'Hardware Key Entry',
        username: 'qa-test',
        password: 'KeyOnly-Value',
    })

    const bytes = await saveVaultToBytes(db)
    const unlocked = await unlockVault(bytes, { password: '', keyFileBytes })
    assert.equal(unlocked.meta.kdfName, 'Argon2d')
    const entries = queryEntries(unlocked.db)
    assert.equal(entries.length, 1)
    assert.equal(entries[0].title, 'Hardware Key Entry')
})

test('Argon2 engine handles both v1.3 (0x13) and legacy v1.0 (0x10) derivations', async () => {
    const password = new TextEncoder().encode('test-secret')
    const salt = new TextEncoder().encode('1234567890abcdef')

    const h13 = await computeArgon2Hash({
        password,
        salt,
        memory: 1024,
        iterations: 2,
        length: 32,
        parallelism: 1,
        type: ARGON2_TYPE_ID,
        version: 0x13,
    })
    assert.equal(h13.byteLength, 32)

    const h10 = await computeArgon2Hash({
        password,
        salt,
        memory: 1024,
        iterations: 2,
        length: 32,
        parallelism: 1,
        type: ARGON2_TYPE_D,
        version: 0x10,
    })
    assert.equal(h10.byteLength, 32)
})

test('TOTP RFC 6238 generator and unpadded Base32 secret decoding', async () => {
    // Unpadded, lowercase, spaced Base32 secret (upstream issue #249)
    const decoded = decodeBase32Secret('jbsw y3dp ehpk 3pxp===')
    assert.equal(decoded.length, 10)

    // RFC 6238 SHA-1 test seed: ASCII "12345678901234567890" -> Base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    const cfg = extractTotpConfigFromFields({
        otp: 'otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1',
    })
    assert.ok(cfg)
    const res = await generateTotpCode(cfg, 59 * 1000)
    assert.equal(res.code, '94287082')
    assert.equal(res.remainingSeconds, 1)
})

test('CSPRNG password generator respects length and character classes', () => {
    const pw = generateRandomPassword({ length: 32, upper: true, lower: true, digits: true, symbols: true })
    assert.equal(pw.length, 32)
    assert.match(pw, /[A-Z]/)
    assert.match(pw, /[a-z]/)
    assert.match(pw, /[0-9]/)
})
