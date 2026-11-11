import { computeArgon2Hash } from './crypto/argon2-core.js'

self.addEventListener('message', async (event) => {
    const payload = event.data || {}
    const { id } = payload
    try {
        const hashBuffer = await computeArgon2Hash(payload)
        self.postMessage({ id, ok: true, hash: hashBuffer }, [hashBuffer])
    } catch (err) {
        self.postMessage({
            id,
            ok: false,
            error: err instanceof Error ? err.message : String(err),
        })
    }
})
