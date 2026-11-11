import { createApp } from 'vue'
import { VaultApp } from './ui/VaultApp.js'

function bootstrapKeewebApp() {
    const mountEl = document.getElementById('keeweb-root')
    if (!mountEl) {
        return
    }

    const urlOpen = new URLSearchParams(window.location.search).get('open') || ''
    const initialOpen = mountEl.dataset.initialOpen || urlOpen || ''
    const workerUrl = mountEl.dataset.workerUrl || ''

    const app = createApp(VaultApp, {
        initialOpen,
        workerUrl,
    })

    app.mount(mountEl)
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrapKeewebApp)
} else {
    bootstrapKeewebApp()
}
