import { registerFileAction, Permission, DefaultType } from '@nextcloud/files'
import { generateUrl } from '@nextcloud/router'

const KEY_SVG =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M12.65 10A5.99 5.99 0 0 0 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6a5.99 5.99 0 0 0 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>'

function translateLabel(text) {
    if (typeof window !== 'undefined' && typeof window.t === 'function') {
        return window.t('keeweb', text)
    }
    return text
}

function isKdbxNode(node) {
    if (!node) {
        return false
    }
    if (node.mime === 'application/x-kdbx') {
        return true
    }
    const name = String(node.basename || node.name || '')
    return /\.kdbx$/i.test(name)
}

registerFileAction({
    id: 'keeweb',
    order: 1,
    default: DefaultType.DEFAULT,
    iconSvgInline: () => KEY_SVG,
    displayName: () => translateLabel('Open in Keeweb'),
    enabled: ({ nodes }) =>
        Array.isArray(nodes) &&
        nodes.length === 1 &&
        nodes.every(
            (node) =>
                node.type !== 'folder' &&
                (node.permissions & Permission.READ) !== 0 &&
                isKdbxNode(node),
        ),
    async exec({ nodes }) {
        const node = nodes[0]
        if (!node || !node.path) {
            return null
        }
        const baseUrl = generateUrl('/apps/keeweb/')
        const separator = baseUrl.includes('?') ? '&' : '?'
        window.location.href = `${baseUrl}${separator}open=${encodeURIComponent(node.path)}`
        return null
    },
})
