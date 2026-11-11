import { generateUrl } from '@nextcloud/router'

function getCsrfToken() {
    if (typeof window !== 'undefined' && window.OC && typeof window.OC.requestToken === 'string' && window.OC.requestToken) {
        return window.OC.requestToken
    }
    if (typeof document !== 'undefined' && document.head) {
        const attr = document.head.getAttribute('data-requesttoken')
        if (attr) {
            return attr
        }
    }
    return ''
}

function buildApiUrl(endpoint, params = {}) {
    const base = generateUrl(`/apps/keeweb${endpoint}`)
    const queryEntries = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
    if (queryEntries.length === 0) {
        return base
    }
    const qs = queryEntries.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&')
    const separator = base.includes('?') ? '&' : '?'
    return `${base}${separator}${qs}`
}

function uint8ToBase64(bytes) {
    let binary = ''
    const chunkSize = 0x8000
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const slice = bytes.subarray(i, i + chunkSize)
        binary += String.fromCharCode.apply(null, slice)
    }
    return btoa(binary)
}

async function parseJsonSafe(response) {
    const text = await response.text()
    if (!text) {
        return {}
    }
    try {
        return JSON.parse(text)
    } catch {
        return { error: text }
    }
}

export async function fetchVaultList(kind = 'kdbx') {
    const url = buildApiUrl('/api/files', { kind })
    const response = await fetch(url, {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            Accept: 'application/json',
            requesttoken: getCsrfToken(),
        },
    })
    const body = await parseJsonSafe(response)
    if (!response.ok) {
        throw new Error(body.error || `Failed to list files (HTTP ${response.status})`)
    }
    return Array.isArray(body.files) ? body.files : []
}

export async function downloadVaultBinary(path) {
    const url = buildApiUrl('/api/vault', { path })
    const response = await fetch(url, {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
            requesttoken: getCsrfToken(),
        },
    })

    if (!response.ok) {
        const errBody = await parseJsonSafe(response)
        const err = new Error(errBody.error || `Unable to load vault file (HTTP ${response.status})`)
        err.status = response.status
        err.code = errBody.code || ''
        throw err
    }

    const arrayBuffer = await response.arrayBuffer()
    const rawEtag = response.headers.get('X-Keeweb-Etag') || response.headers.get('ETag') || ''
    const etag = rawEtag.replace(/^W\//, '').replace(/^"+|"+$/g, '').trim()
    const writableHeader = response.headers.get('X-Keeweb-Writable')
    const writable = writableHeader !== '0'
    const mtime = parseInt(response.headers.get('X-Keeweb-Mtime') || '0', 10) || 0
    const rawName = response.headers.get('X-Keeweb-Filename') || ''
    const name = rawName ? decodeURIComponent(rawName) : (path.split('/').pop() || 'vault.kdbx')

    return {
        arrayBuffer,
        etag,
        writable,
        mtime,
        name,
        path,
    }
}

export async function saveVaultBinary(path, bytes, expectedEtag) {
    const uint8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
    const putUrl = buildApiUrl('/api/vault', { path })

    let response = await fetch(putUrl, {
        method: 'PUT',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/octet-stream',
            'If-Match': `"${expectedEtag}"`,
            'X-Keeweb-If-Match': expectedEtag,
            requesttoken: getCsrfToken(),
        },
        body: uint8,
    })

    if (response.status === 405 || response.status === 501) {
        const postUrl = buildApiUrl('/api/vault/save')
        response = await fetch(postUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'If-Match': `"${expectedEtag}"`,
                requesttoken: getCsrfToken(),
            },
            body: JSON.stringify({
                path,
                etag: expectedEtag,
                dataBase64: uint8ToBase64(uint8),
            }),
        })
    }

    const body = await parseJsonSafe(response)
    if (!response.ok) {
        const err = new Error(body.error || `Failed to save vault (HTTP ${response.status})`)
        err.status = response.status
        err.code = body.code || (response.status === 409 ? 'ETAG_CONFLICT' : '')
        err.currentEtag = body.currentEtag || ''
        throw err
    }

    return body
}

export async function createRemoteVault(path, bytes) {
    const uint8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
    const url = buildApiUrl('/api/vault/create')
    const response = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            requesttoken: getCsrfToken(),
        },
        body: JSON.stringify({
            path,
            dataBase64: uint8ToBase64(uint8),
        }),
    })

    const body = await parseJsonSafe(response)
    if (!response.ok) {
        const err = new Error(body.error || `Failed to create vault (HTTP ${response.status})`)
        err.status = response.status
        err.code = body.code || ''
        throw err
    }

    return body
}
