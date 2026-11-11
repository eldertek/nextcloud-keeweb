import assert from 'node:assert/strict'
import {
    unlockVault,
    createNewVault,
    saveVaultToBytes,
    createVaultEntry,
    updateVaultEntry,
    queryEntries,
    serializeEntryDetail,
} from '../src/crypto/vault-engine.js'

const BASE_URL = (process.env.NC_BASE_URL || 'http://127.0.0.1:8035').replace(/\/+$/, '')
const ADMIN_USER = process.env.NC_USER || 'qa-admin'
const ADMIN_PASS = process.env.NC_PASS || 'QaAdmin-2026-nc'
const RO_USER = process.env.NC_RO_USER || ''
const RO_PASS = process.env.NC_RO_PASS || ''

function basicAuthHeader(user, pass) {
    return 'Basic ' + Buffer.from(`${user}:${pass}`, 'utf8').toString('base64')
}

class CookieSessionClient {
    constructor(baseUrl) {
        this.baseUrl = baseUrl
        this.cookies = new Map()
    }

    storeSetCookies(headers) {
        const rawList = typeof headers.getSetCookie === 'function'
            ? headers.getSetCookie()
            : (headers.get('set-cookie') ? [headers.get('set-cookie')] : [])
        for (const item of rawList) {
            const firstPart = item.split(';')[0]
            const eqIdx = firstPart.indexOf('=')
            if (eqIdx > 0) {
                const name = firstPart.slice(0, eqIdx).trim()
                const val = firstPart.slice(eqIdx + 1).trim()
                this.cookies.set(name, val)
            }
        }
    }

    cookieHeader() {
        return Array.from(this.cookies.entries())
            .map(([k, v]) => `${k}=${v}`)
            .join('; ')
    }

    async request(path, options = {}) {
        const url = path.startsWith('http') ? path : `${this.baseUrl}${path}`
        const headers = new Headers(options.headers || {})
        const cookieStr = this.cookieHeader()
        if (cookieStr && !headers.has('Cookie')) {
            headers.set('Cookie', cookieStr)
        }
        const response = await fetch(url, {
            ...options,
            headers,
            redirect: options.redirect || 'manual',
        })
        this.storeSetCookies(response.headers)
        return response
    }

    async login(user, password) {
        const getLogin = await this.request('/index.php/login')
        const html = await getLogin.text()
        const tokenMatch = html.match(/data-requesttoken="([^"]+)"/)
        assert.ok(tokenMatch, `Expected data-requesttoken on /index.php/login (HTTP ${getLogin.status})`)
        const loginToken = tokenMatch[1]

        const form = new URLSearchParams({
            user,
            password,
            timezone: 'UTC',
            timezone_offset: '0',
            requesttoken: loginToken,
        })

        const postLogin = await this.request('/index.php/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Origin: this.baseUrl,
                requesttoken: loginToken,
            },
            body: form.toString(),
        })

        assert.ok(
            postLogin.status === 303 || postLogin.status === 302 || postLogin.status === 200,
            `Unexpected login status ${postLogin.status}`,
        )
    }
}

async function run() {
    console.log(`[E2E] Running real Nextcloud HTTP + WebDAV + KDBX 3/4 suite against ${BASE_URL}`)

    // 1. Build genuine KDBX 3.1 and KDBX 4.1 Argon2id sample vaults
    const v3Created = await createNewVault({
        name: 'Sample Vault v3',
        password: 'SampleV3-Password!',
        formatVersion: 3,
    })
    createVaultEntry(v3Created.db, null, {
        title: 'Legacy Portal',
        username: 'qa-admin',
        password: 'Legacy-V3-Secret',
        url: 'https://legacy.example.test',
    })
    const v3Bytes = await saveVaultToBytes(v3Created.db)

    const v4Created = await createNewVault({
        name: 'Sample Vault v4',
        password: 'SampleV4-Argon2id!',
        formatVersion: 4,
        argon2MemoryKiB: 4096,
        argon2Iterations: 2,
        argon2Parallelism: 1,
    })
    const initialV4Entry = createVaultEntry(v4Created.db, null, {
        title: 'Production Cluster',
        username: 'qa-admin',
        password: 'Initial-V4-Password',
        url: 'https://prod.example.test',
        otpRaw: 'JBSWY3DPEHPK3PXP',
        notes: 'Seeded before WebDAV upload',
    })
    const v4Bytes = await saveVaultToBytes(v4Created.db)

    // 2. Upload both vaults via Nextcloud WebDAV
    const auth = basicAuthHeader(ADMIN_USER, ADMIN_PASS)
    for (const [filename, payload] of [
        ['sample-v3.kdbx', v3Bytes],
        ['sample-v4.kdbx', v4Bytes],
    ]) {
        const putRes = await fetch(`${BASE_URL}/remote.php/dav/files/${encodeURIComponent(ADMIN_USER)}/${filename}`, {
            method: 'PUT',
            headers: {
                Authorization: auth,
                'Content-Type': 'application/x-kdbx',
            },
            body: payload,
        })
        assert.ok(
            putRes.status === 201 || putRes.status === 204,
            `WebDAV PUT ${filename} failed with HTTP ${putRes.status}`,
        )
    }
    console.log('[E2E] Uploaded sample-v3.kdbx and sample-v4.kdbx via WebDAV')

    // 3. Authenticate browser session and verify /apps/files viewer.js injection + /apps/keeweb page + strict CSP headers
    const session = new CookieSessionClient(BASE_URL)
    await session.login(ADMIN_USER, ADMIN_PASS)

    const filesAppRes = await session.request('/index.php/apps/files/')
    assert.equal(filesAppRes.status, 200, 'Expected HTTP 200 on /apps/files/')
    const filesAppHtml = await filesAppRes.text()
    assert.ok(
        filesAppHtml.includes('keeweb/js/viewer'),
        'Expected LoadAdditionalScriptsListener to inject keeweb/js/viewer into Nextcloud Files',
    )
    console.log('[E2E] Verified keeweb/js/viewer.js injection in Nextcloud Files app')

    const pageRes = await session.request('/index.php/apps/keeweb/?open=%2Fsample-v4.kdbx')
    assert.equal(pageRes.status, 200, 'Expected HTTP 200 on /apps/keeweb/')
    const pageHtml = await pageRes.text()
    const csp = pageRes.headers.get('content-security-policy') || ''

    assert.ok(pageHtml.includes('id="keeweb-root"'), 'Expected #keeweb-root mount element in HTML')
    assert.ok(pageHtml.includes('data-initial-open="/sample-v4.kdbx"'), 'Expected data-initial-open attribute')
    assert.ok(csp.includes("'wasm-unsafe-eval'"), `Expected 'wasm-unsafe-eval' in CSP: ${csp}`)
    assert.ok(csp.includes("worker-src 'self'"), `Expected worker-src 'self' in CSP: ${csp}`)

    const scriptSrcMatch = csp.match(/script-src\s+([^;]+)/)
    assert.ok(scriptSrcMatch, 'Expected script-src directive in CSP')
    assert.ok(!scriptSrcMatch[1].includes("'unsafe-inline'"), `script-src must not contain unsafe-inline: ${scriptSrcMatch[1]}`)
    assert.ok(!scriptSrcMatch[1].includes("'unsafe-eval'"), `script-src must not contain unsafe-eval: ${scriptSrcMatch[1]}`)
    console.log('[E2E] Verified page HTML and strict CSP header (no unsafe-inline / unsafe-eval in script-src)')

    const csrfMatch = pageHtml.match(/data-requesttoken="([^"]+)"/)
    assert.ok(csrfMatch, 'Expected Nextcloud CSRF requesttoken in page head')
    const csrfToken = csrfMatch[1]

    // Verify worker script URL from DOM attribute is reachable
    const workerMatch = pageHtml.match(/data-worker-url="([^"]+)"/)
    assert.ok(workerMatch && workerMatch[1], 'Expected non-empty data-worker-url')
    const workerRes = await session.request(workerMatch[1].replace(/&amp;/g, '&'))
    assert.equal(workerRes.status, 200, 'Expected HTTP 200 on argon2-worker.js')
    const workerJs = await workerRes.text()
    assert.ok(workerJs.length > 500, 'Expected non-empty compiled argon2-worker.js bundle')

    // 4. Verify /api/files lists both uploaded vaults
    const listRes = await session.request('/index.php/apps/keeweb/api/files', {
        headers: { requesttoken: csrfToken },
    })
    assert.equal(listRes.status, 200)
    const listJson = await listRes.json()
    const listedPaths = (listJson.files || []).map((f) => f.path)
    assert.ok(listedPaths.includes('/sample-v3.kdbx'), `Expected /sample-v3.kdbx in ${JSON.stringify(listedPaths)}`)
    assert.ok(listedPaths.includes('/sample-v4.kdbx'), `Expected /sample-v4.kdbx in ${JSON.stringify(listedPaths)}`)
    console.log('[E2E] Verified /api/files lists both KDBX 3.1 and KDBX 4.1 vaults')

    // 5. Load sample-v4.kdbx via /api/vault, decrypt, modify, and save atomically with ETag
    const loadV4Res = await session.request('/index.php/apps/keeweb/api/vault?path=%2Fsample-v4.kdbx', {
        headers: { requesttoken: csrfToken },
    })
    assert.equal(loadV4Res.status, 200)
    const initialEtag = loadV4Res.headers.get('x-keeweb-etag') || ''
    assert.ok(initialEtag.length > 0, 'Expected X-Keeweb-Etag header')
    assert.equal(loadV4Res.headers.get('x-keeweb-writable'), '1')

    const loadedV4Buf = await loadV4Res.arrayBuffer()
    const unlockedV4 = await unlockVault(loadedV4Buf, { password: 'SampleV4-Argon2id!' })
    assert.equal(unlockedV4.meta.versionMajor, 4)
    assert.equal(unlockedV4.meta.versionMinor, 1)
    assert.equal(unlockedV4.meta.kdfName, 'Argon2id')

    updateVaultEntry(unlockedV4.db, initialV4Entry.uuid, {
        title: 'Production Cluster',
        username: 'qa-admin',
        password: 'Updated-Via-Keeweb-E2E-V4!',
        url: 'https://prod.example.test',
        otpRaw: 'JBSWY3DPEHPK3PXP',
        notes: 'Modified client-side and saved with ETag check',
    })
    createVaultEntry(unlockedV4.db, null, {
        title: 'Secondary Bastion',
        username: 'qa-test',
        password: 'Bastion-SSH-Password!',
    })
    const updatedV4Bytes = await saveVaultToBytes(unlockedV4.db)

    const saveV4Res = await session.request('/index.php/apps/keeweb/api/vault?path=%2Fsample-v4.kdbx', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/octet-stream',
            'If-Match': `"${initialEtag}"`,
            requesttoken: csrfToken,
        },
        body: updatedV4Bytes,
    })
    assert.equal(saveV4Res.status, 200, `Expected HTTP 200 on atomic vault save, got ${saveV4Res.status}`)
    const saveV4Body = await saveV4Res.json()
    assert.equal(saveV4Body.status, 'ok')
    assert.ok(saveV4Body.etag && saveV4Body.etag !== initialEtag, 'Expected updated ETag after save')

    // 6. Verify ETag concurrency guard rejects stale ETag with 409 Conflict
    const staleSaveRes = await session.request('/index.php/apps/keeweb/api/vault?path=%2Fsample-v4.kdbx', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/octet-stream',
            'If-Match': `"${initialEtag}"`,
            requesttoken: csrfToken,
        },
        body: updatedV4Bytes,
    })
    assert.equal(staleSaveRes.status, 409, 'Expected HTTP 409 Conflict when saving with stale ETag')
    const staleBody = await staleSaveRes.json()
    assert.equal(staleBody.code, 'ETAG_CONFLICT')
    console.log('[E2E] Verified atomic ETag save (200) and concurrent stale-ETag rejection (409 Conflict)')

    // 7. Download sample-v4.kdbx back via raw WebDAV and verify KDBX 4.1 integrity
    const webdavGetV4 = await fetch(`${BASE_URL}/remote.php/dav/files/${encodeURIComponent(ADMIN_USER)}/sample-v4.kdbx`, {
        headers: { Authorization: auth },
    })
    assert.equal(webdavGetV4.status, 200)
    const roundtripV4Buf = await webdavGetV4.arrayBuffer()
    const verifiedV4 = await unlockVault(roundtripV4Buf, { password: 'SampleV4-Argon2id!' })
    assert.equal(verifiedV4.meta.versionMajor, 4)
    assert.equal(verifiedV4.meta.versionMinor, 1)
    assert.equal(verifiedV4.meta.kdfName, 'Argon2id')
    const v4Entries = queryEntries(verifiedV4.db)
    assert.equal(v4Entries.length, 2)
    const prodDetail = serializeEntryDetail(verifiedV4.db, initialV4Entry.uuid)
    assert.equal(prodDetail.password, 'Updated-Via-Keeweb-E2E-V4!')
    console.log('[E2E] Verified WebDAV round-trip of edited KDBX 4.1 Argon2id vault (zero corruption)')

    // 8. Also test KDBX 3.1 load + edit + save + WebDAV verification
    const loadV3Res = await session.request('/index.php/apps/keeweb/api/vault?path=%2Fsample-v3.kdbx', {
        headers: { requesttoken: csrfToken },
    })
    assert.equal(loadV3Res.status, 200)
    const v3Etag = loadV3Res.headers.get('x-keeweb-etag') || ''
    const unlockedV3 = await unlockVault(await loadV3Res.arrayBuffer(), { password: 'SampleV3-Password!' })
    createVaultEntry(unlockedV3.db, null, {
        title: 'Added In V3',
        username: 'qa-test',
        password: 'Added-V3-Secret',
    })
    const updatedV3Bytes = await saveVaultToBytes(unlockedV3.db)
    const saveV3Res = await session.request('/index.php/apps/keeweb/api/vault?path=%2Fsample-v3.kdbx', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/octet-stream',
            'If-Match': `"${v3Etag}"`,
            requesttoken: csrfToken,
        },
        body: updatedV3Bytes,
    })
    assert.equal(saveV3Res.status, 200)
    const webdavGetV3 = await fetch(`${BASE_URL}/remote.php/dav/files/${encodeURIComponent(ADMIN_USER)}/sample-v3.kdbx`, {
        headers: { Authorization: auth },
    })
    const verifiedV3 = await unlockVault(await webdavGetV3.arrayBuffer(), { password: 'SampleV3-Password!' })
    assert.equal(verifiedV3.meta.versionMajor, 3)
    assert.equal(verifiedV3.meta.versionMinor, 1)
    assert.equal(queryEntries(verifiedV3.db).length, 2)
    console.log('[E2E] Verified WebDAV round-trip of edited KDBX 3.1 AES-KDF vault')

    // 8b. Test POST /api/vault/create and duplicate path rejection (409)
    const createRes = await session.request('/index.php/apps/keeweb/api/vault/create', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            requesttoken: csrfToken,
        },
        body: JSON.stringify({
            path: '/qa-created-v4.kdbx',
            dataBase64: Buffer.from(updatedV4Bytes).toString('base64'),
        }),
    })
    assert.equal(createRes.status, 201, `Expected HTTP 201 Created on /api/vault/create, got ${createRes.status}`)
    const dupCreateRes = await session.request('/index.php/apps/keeweb/api/vault/create', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            requesttoken: csrfToken,
        },
        body: JSON.stringify({
            path: '/qa-created-v4.kdbx',
            dataBase64: Buffer.from(updatedV4Bytes).toString('base64'),
        }),
    })
    assert.equal(dupCreateRes.status, 409, 'Expected HTTP 409 on duplicate vault creation')
    await fetch(`${BASE_URL}/remote.php/dav/files/${encodeURIComponent(ADMIN_USER)}/qa-created-v4.kdbx`, {
        method: 'DELETE',
        headers: { Authorization: auth },
    })
    console.log('[E2E] Verified POST /api/vault/create (201) and duplicate guard (409)')

    // 9. Optional Read-Only share test if RO_USER is provided
    if (RO_USER && RO_PASS) {
        const shareForm = new URLSearchParams({
            path: '/sample-v4.kdbx',
            shareType: '0',
            shareWith: RO_USER,
            permissions: '1', // Permission.READ only
        })
        const shareRes = await fetch(`${BASE_URL}/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json`, {
            method: 'POST',
            headers: {
                Authorization: auth,
                'OCS-APIRequest': 'true',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: shareForm.toString(),
        })
        assert.equal(shareRes.status, 200, `Expected OCS share HTTP 200, got ${shareRes.status}`)

        const roSession = new CookieSessionClient(BASE_URL)
        await roSession.login(RO_USER, RO_PASS)
        const roPage = await roSession.request('/index.php/apps/keeweb/')
        const roHtml = await roPage.text()
        const roCsrf = roHtml.match(/data-requesttoken="([^"]+)"/)[1]

        const roFilesRes = await roSession.request('/index.php/apps/keeweb/api/files', {
            headers: { requesttoken: roCsrf },
        })
        assert.equal(roFilesRes.status, 200)
        const roFilesBody = await roFilesRes.json()
        const sharedEntry = (roFilesBody.files || []).find((f) => f.name.includes('sample-v4'))
        assert.ok(sharedEntry, `Expected shared sample-v4.kdbx in RO user /api/files: ${JSON.stringify(roFilesBody.files)}`)
        assert.equal(sharedEntry.writable, false, 'Expected shared vault in /api/files to have writable=false')

        const roLoad = await roSession.request(
            `/index.php/apps/keeweb/api/vault?path=${encodeURIComponent(sharedEntry.path)}`,
            { headers: { requesttoken: roCsrf } },
        )
        assert.equal(roLoad.status, 200)
        assert.equal(roLoad.headers.get('x-keeweb-writable'), '0', 'Expected read-only share to report writable=0')
        const roEtag = roLoad.headers.get('x-keeweb-etag') || ''

        const roSaveAttempt = await roSession.request(
            `/index.php/apps/keeweb/api/vault?path=${encodeURIComponent(sharedEntry.path)}`,
            {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/octet-stream',
                    'If-Match': `"${roEtag}"`,
                    requesttoken: roCsrf,
                },
                body: updatedV4Bytes,
            },
        )
        assert.equal(roSaveAttempt.status, 403, 'Expected HTTP 403 Forbidden when writing to read-only shared vault')
        console.log('[E2E] Verified read-only shared vault enforcement (writable=false in /api/files, writable=0 on GET, HTTP 403 on PUT)')
    }

    // Cleanup uploaded test files
    for (const filename of ['sample-v3.kdbx', 'sample-v4.kdbx']) {
        await fetch(`${BASE_URL}/remote.php/dav/files/${encodeURIComponent(ADMIN_USER)}/${filename}`, {
            method: 'DELETE',
            headers: { Authorization: auth },
        })
    }
    console.log(`[E2E] ALL CHECKS PASSED ON ${BASE_URL}`)
}

run().catch((err) => {
    console.error('[E2E] FAILURE:', err)
    process.exit(1)
})
