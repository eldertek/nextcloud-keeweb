import { defineComponent, h, markRaw } from 'vue'
import {
    configureArgon2Runtime,
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
} from '../crypto/vault-engine.js'
import { generateTotpCode } from '../crypto/totp.js'
import {
    fetchVaultList,
    downloadVaultBinary,
    saveVaultBinary,
    createRemoteVault,
} from '../services/vault-api.js'

const STORAGE_KEYFILE_MAP = 'nc_keeweb_keyfile_paths_v1'
const AUTO_LOCK_MS = 15 * 60 * 1000

function loadSavedKeyfileMap() {
    try {
        const raw = window.localStorage.getItem(STORAGE_KEYFILE_MAP)
        if (!raw) return {}
        const parsed = JSON.parse(raw)
        return parsed && typeof parsed === 'object' ? parsed : {}
    } catch {
        return {}
    }
}

function saveKeyfilePathForVault(vaultPath, keyfilePath) {
    try {
        const map = loadSavedKeyfileMap()
        if (keyfilePath) {
            map[vaultPath] = keyfilePath
        } else {
            delete map[vaultPath]
        }
        window.localStorage.setItem(STORAGE_KEYFILE_MAP, JSON.stringify(map))
    } catch {
        // Ignore storage quota / private mode restrictions
    }
}

function formatBytes(bytes) {
    const n = Number(bytes) || 0
    if (n < 1024) return `${n} B`
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
    return `${(n / (1024 * 1024)).toFixed(2)} MB`
}

function formatDateShort(epochSecondsOrIso) {
    if (!epochSecondsOrIso) return ''
    const d = typeof epochSecondsOrIso === 'number'
        ? new Date(epochSecondsOrIso * 1000)
        : new Date(epochSecondsOrIso)
    if (Number.isNaN(d.getTime())) return ''
    return d.toLocaleString()
}

function safeExternalHref(rawUrl) {
    const trimmed = String(rawUrl || '').trim()
    if (!trimmed) return null
    if (/^https?:\/\//i.test(trimmed)) {
        return trimmed
    }
    if (/^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(trimmed)) {
        return `https://${trimmed}`
    }
    return null
}

function flattenGroups(nodes, list = []) {
    for (const node of nodes || []) {
        if (!node.isRecycleBin) {
            list.push(node)
            flattenGroups(node.children, list)
        }
    }
    return list
}

export const VaultApp = defineComponent({
    name: 'VaultApp',
    props: {
        initialOpen: { type: String, default: '' },
        workerUrl: { type: String, default: '' },
    },
    data() {
        return {
            screen: 'picker', // 'picker' | 'unlock' | 'workspace'
            loadingFiles: false,
            vaultFiles: [],
            keyFiles: [],
            pickerError: '',

            showCreateModal: false,
            createForm: {
                path: '/Passwords.kdbx',
                name: 'Passwords',
                formatVersion: 4,
                password: '',
                confirmPassword: '',
                keyFileBytes: null,
                keyFileName: '',
            },
            creatingVault: false,
            createError: '',

            targetVault: {
                path: '',
                name: '',
                etag: '',
                writable: true,
                mtime: 0,
                size: 0,
                localOnly: false,
                encryptedBuffer: null,
            },
            unlockPassword: '',
            showUnlockPassword: false,
            keyfileMode: 'none', // 'none' | 'local' | 'nextcloud'
            localKeyFileBytes: null,
            localKeyFileName: '',
            selectedNcKeyfilePath: '',
            rememberKeyfilePath: true,
            unlocking: false,
            unlockError: '',

            dbRef: null,
            vaultMeta: null,
            groupTree: [],
            selectedGroupUuid: null, // null = All entries
            searchQuery: '',
            entries: [],
            selectedEntryUuid: null,
            activeEntry: null,
            revealPassword: false,
            revealedCustomIndices: {},

            totpState: null,
            totpTimerId: null,
            inactivityTimerId: null,
            clipboardTimerId: null,
            copiedFieldKey: '',

            isDirty: false,
            savingVault: false,
            saveStatusText: '',
            saveError: '',
            etagConflict: false,

            newGroupName: '',
            showNewGroupInput: false,

            editorMode: null, // null | 'create' | 'edit'
            editorForm: {
                title: '',
                groupUuid: '',
                username: '',
                password: '',
                url: '',
                otpRaw: '',
                tagsText: '',
                notes: '',
                customFields: [],
            },
            showEditorPassword: false,
            showPasswordGen: false,
            pwGenOptions: {
                length: 24,
                upper: true,
                lower: true,
                digits: true,
                symbols: true,
            },
        }
    },
    mounted() {
        configureArgon2Runtime({ workerUrl: this.workerUrl })
        window.addEventListener('keydown', this.handleGlobalKeydown)
        window.addEventListener('mousemove', this.resetInactivityTimer, { passive: true })
        window.addEventListener('keydown', this.resetInactivityTimer, { passive: true })

        if (this.initialOpen) {
            this.prepareRemoteVaultUnlock(this.initialOpen)
        } else {
            this.loadVaultPicker()
        }
    },
    beforeUnmount() {
        window.removeEventListener('keydown', this.handleGlobalKeydown)
        window.removeEventListener('mousemove', this.resetInactivityTimer)
        window.removeEventListener('keydown', this.resetInactivityTimer)
        this.stopTotpTimer()
        this.clearInactivityTimer()
        if (this.clipboardTimerId) {
            clearTimeout(this.clipboardTimerId)
        }
    },
    methods: {
        resetInactivityTimer() {
            if (this.screen !== 'workspace') return
            this.clearInactivityTimer()
            this.inactivityTimerId = setTimeout(() => {
                if (this.screen === 'workspace' && !this.isDirty) {
                    this.lockVault('Vault locked automatically after inactivity.')
                }
            }, AUTO_LOCK_MS)
        },
        clearInactivityTimer() {
            if (this.inactivityTimerId) {
                clearTimeout(this.inactivityTimerId)
                this.inactivityTimerId = null
            }
        },
        handleGlobalKeydown(event) {
            if (this.screen !== 'workspace') return
            if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
                if (this.targetVault.writable && !this.targetVault.localOnly) {
                    event.preventDefault()
                    this.persistVaultToServer()
                }
            }
        },
        async loadVaultPicker() {
            this.screen = 'picker'
            this.loadingFiles = true
            this.pickerError = ''
            try {
                this.vaultFiles = await fetchVaultList('kdbx')
            } catch (err) {
                this.pickerError = err instanceof Error ? err.message : 'Unable to load vault list.'
            } finally {
                this.loadingFiles = false
            }
        },
        async loadKeyfileOptions(vaultPath) {
            try {
                this.keyFiles = await fetchVaultList('keyfile')
                const savedMap = loadSavedKeyfileMap()
                const savedPath = vaultPath ? savedMap[vaultPath] : ''
                if (savedPath && this.keyFiles.some((f) => f.path === savedPath)) {
                    this.keyfileMode = 'nextcloud'
                    this.selectedNcKeyfilePath = savedPath
                    this.rememberKeyfilePath = true
                }
            } catch {
                this.keyFiles = []
            }
        },
        async prepareRemoteVaultUnlock(path) {
            this.screen = 'unlock'
            this.unlockError = ''
            this.unlockPassword = ''
            this.showUnlockPassword = false
            this.keyfileMode = 'none'
            this.localKeyFileBytes = null
            this.localKeyFileName = ''
            this.selectedNcKeyfilePath = ''
            this.unlocking = true
            this.targetVault = {
                path,
                name: path.split('/').pop() || 'vault.kdbx',
                etag: '',
                writable: true,
                mtime: 0,
                size: 0,
                localOnly: false,
                encryptedBuffer: null,
            }

            try {
                const [downloaded] = await Promise.all([
                    downloadVaultBinary(path),
                    this.loadKeyfileOptions(path),
                ])
                this.targetVault = {
                    path: downloaded.path,
                    name: downloaded.name,
                    etag: downloaded.etag,
                    writable: downloaded.writable,
                    mtime: downloaded.mtime,
                    size: downloaded.arrayBuffer.byteLength,
                    localOnly: false,
                    encryptedBuffer: downloaded.arrayBuffer,
                }
            } catch (err) {
                this.unlockError = err instanceof Error ? err.message : 'Unable to fetch vault from Nextcloud.'
            } finally {
                this.unlocking = false
            }
        },
        async handleOpenLocalVaultFile(event) {
            const file = event.target?.files?.[0]
            if (!file) return
            const buffer = await file.arrayBuffer()
            this.targetVault = {
                path: file.name,
                name: file.name,
                etag: '',
                writable: false,
                mtime: Math.floor(file.lastModified / 1000),
                size: buffer.byteLength,
                localOnly: true,
                encryptedBuffer: buffer,
            }
            this.unlockPassword = ''
            this.unlockError = ''
            this.keyfileMode = 'none'
            this.localKeyFileBytes = null
            this.localKeyFileName = ''
            this.screen = 'unlock'
            event.target.value = ''
        },
        async handleLocalKeyfilePicked(event) {
            const file = event.target?.files?.[0]
            if (!file) return
            this.localKeyFileBytes = await file.arrayBuffer()
            this.localKeyFileName = file.name
            this.keyfileMode = 'local'
        },
        async handleCreateKeyfilePicked(event) {
            const file = event.target?.files?.[0]
            if (!file) {
                this.createForm.keyFileBytes = null
                this.createForm.keyFileName = ''
                return
            }
            this.createForm.keyFileBytes = await file.arrayBuffer()
            this.createForm.keyFileName = file.name
        },
        async submitUnlock(event) {
            if (event) event.preventDefault()
            if (this.unlocking) return
            this.unlockError = ''

            if (!this.targetVault.encryptedBuffer) {
                try {
                    this.unlocking = true
                    const downloaded = await downloadVaultBinary(this.targetVault.path)
                    this.targetVault.encryptedBuffer = downloaded.arrayBuffer
                    this.targetVault.etag = downloaded.etag
                    this.targetVault.writable = downloaded.writable
                    this.targetVault.size = downloaded.arrayBuffer.byteLength
                } catch (err) {
                    this.unlocking = false
                    this.unlockError = err instanceof Error ? err.message : 'Failed to load vault file.'
                    return
                }
            }

            this.unlocking = true
            try {
                let keyBytes = null
                if (this.keyfileMode === 'local' && this.localKeyFileBytes) {
                    keyBytes = this.localKeyFileBytes
                } else if (this.keyfileMode === 'nextcloud' && this.selectedNcKeyfilePath) {
                    const kf = await downloadVaultBinary(this.selectedNcKeyfilePath)
                    keyBytes = kf.arrayBuffer
                    if (!this.targetVault.localOnly) {
                        saveKeyfilePathForVault(
                            this.targetVault.path,
                            this.rememberKeyfilePath ? this.selectedNcKeyfilePath : '',
                        )
                    }
                } else if (!this.targetVault.localOnly && !this.rememberKeyfilePath) {
                    saveKeyfilePathForVault(this.targetVault.path, '')
                }

                const { db, meta } = await unlockVault(this.targetVault.encryptedBuffer, {
                    password: this.unlockPassword,
                    keyFileBytes: keyBytes,
                })

                this.unlockPassword = ''
                this.enterWorkspace(db, meta)
            } catch (err) {
                this.unlockError = err instanceof Error ? err.message : 'Decryption failed.'
            } finally {
                this.unlocking = false
            }
        },
        async submitCreateVault(event) {
            if (event) event.preventDefault()
            if (this.creatingVault) return
            this.createError = ''

            const path = String(this.createForm.path || '').trim()
            if (!path) {
                this.createError = 'Please enter a file path (for example /Passwords.kdbx).'
                return
            }
            if (!this.createForm.password && !this.createForm.keyFileBytes) {
                this.createError = 'Enter a master password or attach a key file.'
                return
            }
            if (this.createForm.password !== this.createForm.confirmPassword) {
                this.createError = 'Master password confirmation does not match.'
                return
            }

            this.creatingVault = true
            try {
                const { db, meta } = await createNewVault({
                    name: this.createForm.name || 'Passwords',
                    password: this.createForm.password,
                    keyFileBytes: this.createForm.keyFileBytes,
                    formatVersion: Number(this.createForm.formatVersion) === 3 ? 3 : 4,
                })
                const bytes = await saveVaultToBytes(db)
                const created = await createRemoteVault(path, bytes)

                this.targetVault = {
                    path: created.path,
                    name: created.name,
                    etag: created.etag,
                    writable: Boolean(created.writable),
                    mtime: created.mtime,
                    size: created.size,
                    localOnly: false,
                    encryptedBuffer: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
                }
                this.showCreateModal = false
                this.createForm.password = ''
                this.createForm.confirmPassword = ''
                this.createForm.keyFileBytes = null
                this.createForm.keyFileName = ''
                this.enterWorkspace(db, meta)
            } catch (err) {
                this.createError = err instanceof Error ? err.message : 'Unable to create vault.'
            } finally {
                this.creatingVault = false
            }
        },
        enterWorkspace(db, meta) {
            this.dbRef = markRaw(db)
            this.vaultMeta = meta
            this.selectedGroupUuid = null
            this.searchQuery = ''
            this.isDirty = false
            this.etagConflict = false
            this.saveError = ''
            this.saveStatusText = this.targetVault.writable ? 'All changes saved' : 'Read-only mode'
            this.editorMode = null
            this.refreshVaultViews()
            if (this.entries.length > 0) {
                this.selectEntry(this.entries[0].uuid)
            } else {
                this.selectedEntryUuid = null
                this.activeEntry = null
            }
            this.screen = 'workspace'
            this.resetInactivityTimer()
        },
        refreshVaultViews() {
            if (!this.dbRef) return
            this.groupTree = serializeGroupTree(this.dbRef)
            this.entries = queryEntries(this.dbRef, {
                groupUuid: this.selectedGroupUuid,
                searchQuery: this.searchQuery,
            })
            if (this.selectedEntryUuid) {
                const detail = serializeEntryDetail(this.dbRef, this.selectedEntryUuid)
                this.activeEntry = detail
                if (!detail) {
                    this.selectedEntryUuid = null
                    this.stopTotpTimer()
                } else {
                    this.syncTotpTimer()
                }
            }
        },
        selectGroup(groupUuid) {
            this.selectedGroupUuid = groupUuid
            this.editorMode = null
            this.entries = queryEntries(this.dbRef, {
                groupUuid: this.selectedGroupUuid,
                searchQuery: this.searchQuery,
            })
            if (!this.entries.some((e) => e.uuid === this.selectedEntryUuid)) {
                if (this.entries.length > 0) {
                    this.selectEntry(this.entries[0].uuid)
                } else {
                    this.selectedEntryUuid = null
                    this.activeEntry = null
                    this.stopTotpTimer()
                }
            }
        },
        updateSearch(val) {
            this.searchQuery = val
            this.entries = queryEntries(this.dbRef, {
                groupUuid: this.selectedGroupUuid,
                searchQuery: this.searchQuery,
            })
        },
        selectEntry(entryUuid) {
            this.selectedEntryUuid = entryUuid
            this.revealPassword = false
            this.revealedCustomIndices = {}
            this.editorMode = null
            this.activeEntry = this.dbRef ? serializeEntryDetail(this.dbRef, entryUuid) : null
            this.syncTotpTimer()
        },
        stopTotpTimer() {
            if (this.totpTimerId) {
                clearInterval(this.totpTimerId)
                this.totpTimerId = null
            }
            this.totpState = null
        },
        async refreshTotpOnce() {
            if (!this.activeEntry || !this.activeEntry.totpConfig) {
                this.totpState = null
                return
            }
            try {
                this.totpState = await generateTotpCode(this.activeEntry.totpConfig, Date.now())
            } catch {
                this.totpState = null
            }
        },
        syncTotpTimer() {
            this.stopTotpTimer()
            if (this.activeEntry && this.activeEntry.totpConfig) {
                this.refreshTotpOnce()
                this.totpTimerId = setInterval(() => {
                    this.refreshTotpOnce()
                }, 1000)
            }
        },
        async copySecret(value, fieldKey) {
            if (!value) return
            try {
                await navigator.clipboard.writeText(String(value))
                this.copiedFieldKey = fieldKey
                if (this.clipboardTimerId) {
                    clearTimeout(this.clipboardTimerId)
                }
                this.clipboardTimerId = setTimeout(async () => {
                    if (this.copiedFieldKey === fieldKey) {
                        this.copiedFieldKey = ''
                    }
                    try {
                        const current = await navigator.clipboard.readText()
                        if (current === String(value)) {
                            await navigator.clipboard.writeText('')
                        }
                    } catch {
                        // Ignore clipboard read restrictions
                    }
                }, 25000)
            } catch {
                // Fallback textarea copy
                const area = document.createElement('textarea')
                area.value = String(value)
                area.style.position = 'fixed'
                area.style.opacity = '0'
                document.body.appendChild(area)
                area.select()
                document.execCommand('copy')
                document.body.removeChild(area)
                this.copiedFieldKey = fieldKey
            }
        },
        openCreateEntryEditor() {
            if (!this.targetVault.writable) return
            const flat = flattenGroups(this.groupTree)
            const defaultGroup =
                (this.selectedGroupUuid && flat.some((g) => g.uuid === this.selectedGroupUuid)
                    ? this.selectedGroupUuid
                    : flat[0]?.uuid) || ''
            this.editorForm = {
                title: '',
                groupUuid: defaultGroup,
                username: '',
                password: generateRandomPassword(this.pwGenOptions),
                url: '',
                otpRaw: '',
                tagsText: '',
                notes: '',
                customFields: [],
            }
            this.showEditorPassword = false
            this.showPasswordGen = false
            this.editorMode = 'create'
        },
        openEditEntryEditor() {
            if (!this.targetVault.writable || !this.activeEntry) return
            const e = this.activeEntry
            this.editorForm = {
                title: e.title,
                groupUuid: e.groupUuid,
                username: e.username,
                password: e.password,
                url: e.url,
                otpRaw: e.otpRaw || '',
                tagsText: (e.tags || []).join(', '),
                notes: e.notes,
                customFields: (e.customFields || []).map((cf) => ({
                    key: cf.key,
                    value: cf.value,
                    protected: Boolean(cf.protected),
                })),
            }
            this.showEditorPassword = false
            this.showPasswordGen = false
            this.editorMode = 'edit'
        },
        regenerateEditorPassword() {
            this.editorForm.password = generateRandomPassword(this.pwGenOptions)
        },
        async submitEntryEditor(event) {
            if (event) event.preventDefault()
            if (!this.dbRef || !this.targetVault.writable) return

            const payload = {
                title: this.editorForm.title || 'Untitled entry',
                groupUuid: this.editorForm.groupUuid,
                username: this.editorForm.username,
                password: this.editorForm.password,
                url: this.editorForm.url,
                otpRaw: this.editorForm.otpRaw,
                tags: this.editorForm.tagsText,
                notes: this.editorForm.notes,
                customFields: this.editorForm.customFields,
            }

            let savedDetail = null
            if (this.editorMode === 'create') {
                savedDetail = createVaultEntry(this.dbRef, payload.groupUuid, payload)
            } else if (this.editorMode === 'edit' && this.selectedEntryUuid) {
                savedDetail = updateVaultEntry(this.dbRef, this.selectedEntryUuid, payload)
            }

            this.editorMode = null
            this.isDirty = true
            this.refreshVaultViews()
            if (savedDetail) {
                this.selectEntry(savedDetail.uuid)
            }

            if (!this.targetVault.localOnly) {
                await this.persistVaultToServer()
            }
        },
        async handleDeleteActiveEntry() {
            if (!this.dbRef || !this.targetVault.writable || !this.activeEntry) return
            const title = this.activeEntry.title || 'this entry'
            if (!window.confirm(`Delete "${title}"?`)) {
                return
            }
            deleteVaultEntry(this.dbRef, this.activeEntry.uuid)
            this.isDirty = true
            this.selectedEntryUuid = null
            this.activeEntry = null
            this.stopTotpTimer()
            this.refreshVaultViews()
            if (this.entries.length > 0) {
                this.selectEntry(this.entries[0].uuid)
            }
            if (!this.targetVault.localOnly) {
                await this.persistVaultToServer()
            }
        },
        async submitNewGroup(event) {
            if (event) event.preventDefault()
            if (!this.dbRef || !this.targetVault.writable) return
            const name = this.newGroupName.trim()
            if (!name) return
            const flat = flattenGroups(this.groupTree)
            const parentUuid =
                (this.selectedGroupUuid && flat.some((g) => g.uuid === this.selectedGroupUuid)
                    ? this.selectedGroupUuid
                    : flat[0]?.uuid) || null
            const created = createVaultGroup(this.dbRef, parentUuid, name)
            this.newGroupName = ''
            this.showNewGroupInput = false
            this.isDirty = true
            this.refreshVaultViews()
            this.selectGroup(created.uuid)
            if (!this.targetVault.localOnly) {
                await this.persistVaultToServer()
            }
        },
        async persistVaultToServer() {
            if (!this.dbRef || !this.targetVault.writable || this.targetVault.localOnly || this.savingVault) {
                return
            }
            this.savingVault = true
            this.saveError = ''
            this.etagConflict = false
            this.saveStatusText = 'Saving...'
            try {
                const bytes = await saveVaultToBytes(this.dbRef)
                const result = await saveVaultBinary(this.targetVault.path, bytes, this.targetVault.etag)
                this.targetVault.etag = result.etag
                this.targetVault.mtime = result.mtime
                this.targetVault.size = result.size
                this.targetVault.encryptedBuffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
                this.isDirty = false
                this.saveStatusText = 'Saved'
            } catch (err) {
                if (err && (err.status === 409 || err.code === 'ETAG_CONFLICT')) {
                    this.etagConflict = true
                    this.saveStatusText = 'Conflict detected'
                    this.saveError = err.message || 'Remote vault changed on server.'
                } else if (err && (err.status === 403 || err.code === 'READ_ONLY')) {
                    this.targetVault.writable = false
                    this.saveStatusText = 'Read-only'
                    this.saveError = err.message || 'Vault is read-only.'
                } else {
                    this.saveStatusText = 'Save failed'
                    this.saveError = err instanceof Error ? err.message : 'Unable to save vault.'
                }
            } finally {
                this.savingVault = false
            }
        },
        async exportEncryptedVault() {
            if (!this.dbRef) return
            const bytes = await saveVaultToBytes(this.dbRef)
            const blob = new Blob([bytes], { type: 'application/x-kdbx' })
            const url = URL.createObjectURL(blob)
            const link = document.createElement('a')
            link.href = url
            link.download = this.targetVault.name || 'vault.kdbx'
            document.body.appendChild(link)
            link.click()
            document.body.removeChild(link)
            setTimeout(() => URL.revokeObjectURL(url), 1000)
        },
        downloadAttachment(name) {
            if (!this.dbRef || !this.activeEntry) return
            const bytes = getEntryAttachmentBytes(this.dbRef, this.activeEntry.uuid, name)
            if (!bytes) return
            const blob = new Blob([bytes], { type: 'application/octet-stream' })
            const url = URL.createObjectURL(blob)
            const link = document.createElement('a')
            link.href = url
            link.download = name
            document.body.appendChild(link)
            link.click()
            document.body.removeChild(link)
            setTimeout(() => URL.revokeObjectURL(url), 1000)
        },
        lockVault(reason = '') {
            this.stopTotpTimer()
            this.clearInactivityTimer()
            this.dbRef = null
            this.vaultMeta = null
            this.groupTree = []
            this.entries = []
            this.activeEntry = null
            this.selectedEntryUuid = null
            this.editorMode = null
            this.isDirty = false
            this.unlockPassword = ''
            this.unlockError = reason
            this.screen = 'unlock'
        },

        // --- Render helpers ---
        renderPickerScreen() {
            return h('div', { class: 'kw-centered-stage' }, [
                h('div', { class: 'kw-card kw-picker-card' }, [
                    h('div', { class: 'kw-picker-header' }, [
                        h('div', [
                            h('h1', { class: 'kw-title' }, 'KeePass Vaults'),
                            h('p', { class: 'kw-subtitle' }, 'Select an encrypted .kdbx database from Nextcloud Files or create a new KDBX 4.1 vault.'),
                        ]),
                        h('div', { class: 'kw-header-actions' }, [
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: 'kw-btn kw-btn-secondary',
                                    disabled: this.loadingFiles,
                                    onClick: () => this.loadVaultPicker(),
                                },
                                this.loadingFiles ? 'Refreshing...' : 'Refresh',
                            ),
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: 'kw-btn kw-btn-primary',
                                    onClick: () => {
                                        this.createError = ''
                                        this.showCreateModal = true
                                    },
                                },
                                '+ New vault',
                            ),
                        ]),
                    ]),

                    this.pickerError
                        ? h('div', { class: 'kw-alert kw-alert-error', role: 'alert' }, this.pickerError)
                        : null,

                    this.loadingFiles
                        ? h('div', { class: 'kw-empty-box' }, 'Scanning your Nextcloud files for .kdbx vaults...')
                        : this.vaultFiles.length === 0
                            ? h('div', { class: 'kw-empty-box' }, [
                                h('p', 'No .kdbx vaults were found in your Nextcloud account yet.'),
                                h('p', { class: 'kw-muted' }, 'Create a new vault above or upload an existing KeePass database in Nextcloud Files.'),
                            ])
                            : h(
                                'ul',
                                { class: 'kw-vault-list', 'data-testid': 'vault-list' },
                                this.vaultFiles.map((file) =>
                                    h(
                                        'li',
                                        {
                                            key: `${file.id}-${file.path}`,
                                            class: 'kw-vault-item',
                                            onClick: () => this.prepareRemoteVaultUnlock(file.path),
                                        },
                                        [
                                            h('div', { class: 'kw-vault-item-main' }, [
                                                h('span', { class: 'kw-vault-name' }, file.name),
                                                h('span', { class: 'kw-vault-path' }, file.path),
                                            ]),
                                            h('div', { class: 'kw-vault-item-meta' }, [
                                                !file.writable
                                                    ? h('span', { class: 'kw-badge kw-badge-readonly' }, 'Read-only')
                                                    : null,
                                                h('span', { class: 'kw-muted' }, formatBytes(file.size)),
                                                h('span', { class: 'kw-muted' }, formatDateShort(file.mtime)),
                                            ]),
                                        ],
                                    ),
                                ),
                            ),

                    h('div', { class: 'kw-picker-footer' }, [
                        h('label', { class: 'kw-local-open-label' }, [
                            h('span', { class: 'kw-btn kw-btn-ghost' }, 'Open local .kdbx file (browser only)'),
                            h('input', {
                                type: 'file',
                                accept: '.kdbx,application/x-kdbx',
                                class: 'kw-sr-only',
                                onChange: (e) => this.handleOpenLocalVaultFile(e),
                            }),
                        ]),
                    ]),
                ]),
                this.showCreateModal ? this.renderCreateVaultModal() : null,
            ])
        },

        renderCreateVaultModal() {
            return h('div', { class: 'kw-modal-backdrop', role: 'dialog', 'aria-modal': 'true' }, [
                h('form', { class: 'kw-card kw-modal-card', onSubmit: (e) => this.submitCreateVault(e) }, [
                    h('h2', { class: 'kw-title' }, 'Create new KeePass vault'),
                    h('p', { class: 'kw-subtitle' }, 'Encrypted client-side in your browser before saving to Nextcloud.'),
                    this.createError
                        ? h('div', { class: 'kw-alert kw-alert-error', role: 'alert' }, this.createError)
                        : null,
                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Path in Nextcloud'),
                        h('input', {
                            type: 'text',
                            class: 'kw-input',
                            required: true,
                            value: this.createForm.path,
                            onInput: (e) => {
                                this.createForm.path = e.target.value
                            },
                        }),
                    ]),
                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Vault display name'),
                        h('input', {
                            type: 'text',
                            class: 'kw-input',
                            required: true,
                            value: this.createForm.name,
                            onInput: (e) => {
                                this.createForm.name = e.target.value
                            },
                        }),
                    ]),
                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Format & KDF'),
                        h(
                            'select',
                            {
                                class: 'kw-input',
                                value: String(this.createForm.formatVersion),
                                onChange: (e) => {
                                    this.createForm.formatVersion = Number(e.target.value)
                                },
                            },
                            [
                                h('option', { value: '4' }, 'KDBX 4.1 - Argon2id (Recommended)'),
                                h('option', { value: '3' }, 'KDBX 3.1 - AES-KDF (Legacy compatibility)'),
                            ],
                        ),
                    ]),
                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Master password'),
                        h('input', {
                            type: 'password',
                            class: 'kw-input',
                            autocomplete: 'new-password',
                            value: this.createForm.password,
                            onInput: (e) => {
                                this.createForm.password = e.target.value
                            },
                        }),
                    ]),
                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Confirm master password'),
                        h('input', {
                            type: 'password',
                            class: 'kw-input',
                            autocomplete: 'new-password',
                            value: this.createForm.confirmPassword,
                            onInput: (e) => {
                                this.createForm.confirmPassword = e.target.value
                            },
                        }),
                    ]),
                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Optional key file'),
                        h('input', {
                            type: 'file',
                            class: 'kw-input',
                            onChange: (e) => this.handleCreateKeyfilePicked(e),
                        }),
                    ]),
                    h('div', { class: 'kw-modal-actions' }, [
                        h(
                            'button',
                            {
                                type: 'button',
                                class: 'kw-btn kw-btn-secondary',
                                disabled: this.creatingVault,
                                onClick: () => {
                                    this.showCreateModal = false
                                },
                            },
                            'Cancel',
                        ),
                        h(
                            'button',
                            {
                                type: 'submit',
                                class: 'kw-btn kw-btn-primary',
                                disabled: this.creatingVault,
                            },
                            this.creatingVault ? 'Encrypting & saving...' : 'Create vault',
                        ),
                    ]),
                ]),
            ])
        },

        renderUnlockScreen() {
            return h('div', { class: 'kw-centered-stage' }, [
                h('form', { class: 'kw-card kw-unlock-card', onSubmit: (e) => this.submitUnlock(e), 'data-testid': 'unlock-form' }, [
                    h('div', { class: 'kw-unlock-top' }, [
                        h('div', { class: 'kw-vault-badge-row' }, [
                            h('span', { class: 'kw-badge kw-badge-accent' }, 'Encrypted KDBX'),
                            !this.targetVault.writable
                                ? h('span', { class: 'kw-badge kw-badge-readonly' }, this.targetVault.localOnly ? 'Local preview' : 'Read-only share')
                                : null,
                        ]),
                        h('h1', { class: 'kw-title' }, this.targetVault.name || 'Unlock vault'),
                        h('p', { class: 'kw-subtitle kw-mono' }, [
                            this.targetVault.path,
                            this.targetVault.size ? ` (${formatBytes(this.targetVault.size)})` : '',
                        ]),
                    ]),

                    !this.targetVault.writable && !this.targetVault.localOnly
                        ? h(
                            'div',
                            { class: 'kw-alert kw-alert-info' },
                            'You have read-only access to this vault. You can unlock, search, view, and copy entries safely without modifying the file.',
                        )
                        : null,

                    this.unlockError
                        ? h('div', { class: 'kw-alert kw-alert-error', role: 'alert' }, this.unlockError)
                        : null,

                    h('div', { class: 'kw-field' }, [
                        h('label', { class: 'kw-label', for: 'kw-master-password' }, 'Master password'),
                        h('div', { class: 'kw-input-row' }, [
                            h('input', {
                                id: 'kw-master-password',
                                type: this.showUnlockPassword ? 'text' : 'password',
                                class: 'kw-input',
                                placeholder: 'Enter master password (leave blank if key-file only)',
                                autocomplete: 'current-password',
                                autofocus: true,
                                disabled: this.unlocking,
                                value: this.unlockPassword,
                                onInput: (e) => {
                                    this.unlockPassword = e.target.value
                                },
                            }),
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: 'kw-btn kw-btn-secondary',
                                    onClick: () => {
                                        this.showUnlockPassword = !this.showUnlockPassword
                                    },
                                },
                                this.showUnlockPassword ? 'Hide' : 'Show',
                            ),
                        ]),
                    ]),

                    h('div', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Key file (optional)'),
                        h('div', { class: 'kw-segmented' }, [
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: ['kw-seg-btn', this.keyfileMode === 'none' ? 'is-active' : ''],
                                    onClick: () => {
                                        this.keyfileMode = 'none'
                                    },
                                },
                                'None',
                            ),
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: ['kw-seg-btn', this.keyfileMode === 'local' ? 'is-active' : ''],
                                    onClick: () => {
                                        this.keyfileMode = 'local'
                                    },
                                },
                                'Upload from device',
                            ),
                            !this.targetVault.localOnly
                                ? h(
                                    'button',
                                    {
                                        type: 'button',
                                        class: ['kw-seg-btn', this.keyfileMode === 'nextcloud' ? 'is-active' : ''],
                                        onClick: () => {
                                            this.keyfileMode = 'nextcloud'
                                        },
                                    },
                                    'From Nextcloud Files',
                                )
                                : null,
                        ]),

                        this.keyfileMode === 'local'
                            ? h('div', { class: 'kw-keyfile-box' }, [
                                h('input', {
                                    type: 'file',
                                    class: 'kw-input',
                                    onChange: (e) => this.handleLocalKeyfilePicked(e),
                                }),
                                this.localKeyFileName
                                    ? h('p', { class: 'kw-muted' }, `Selected: ${this.localKeyFileName}`)
                                    : null,
                            ])
                            : null,

                        this.keyfileMode === 'nextcloud'
                            ? h('div', { class: 'kw-keyfile-box' }, [
                                this.keyFiles.length === 0
                                    ? h('p', { class: 'kw-muted' }, 'No .key or .keyx files found in your Nextcloud account.')
                                    : h(
                                        'select',
                                        {
                                            class: 'kw-input',
                                            value: this.selectedNcKeyfilePath,
                                            onChange: (e) => {
                                                this.selectedNcKeyfilePath = e.target.value
                                            },
                                        },
                                        [
                                            h('option', { value: '' }, 'Select a key file...'),
                                            ...this.keyFiles.map((kf) =>
                                                h('option', { key: kf.path, value: kf.path }, `${kf.name} (${kf.path})`),
                                            ),
                                        ],
                                    ),
                                h('label', { class: 'kw-checkbox-row' }, [
                                    h('input', {
                                        type: 'checkbox',
                                        checked: this.rememberKeyfilePath,
                                        onChange: (e) => {
                                            this.rememberKeyfilePath = e.target.checked
                                        },
                                    }),
                                    h('span', 'Remember this Nextcloud key file path on this browser'),
                                ]),
                            ])
                            : null,
                    ]),

                    h('div', { class: 'kw-unlock-actions' }, [
                        h(
                            'button',
                            {
                                type: 'button',
                                class: 'kw-btn kw-btn-secondary',
                                disabled: this.unlocking,
                                onClick: () => this.loadVaultPicker(),
                            },
                            'Switch vault',
                        ),
                        h(
                            'button',
                            {
                                type: 'submit',
                                class: 'kw-btn kw-btn-primary',
                                disabled: this.unlocking,
                                'data-testid': 'unlock-submit',
                            },
                            this.unlocking ? 'Decrypting vault...' : 'Unlock vault',
                        ),
                    ]),
                ]),
            ])
        },

        renderGroupNodes(nodes) {
            return (nodes || []).map((group) =>
                h('div', { key: group.uuid, class: 'kw-group-branch' }, [
                    h(
                        'button',
                        {
                            type: 'button',
                            class: [
                                'kw-group-item',
                                this.selectedGroupUuid === group.uuid ? 'is-selected' : '',
                                group.isRecycleBin ? 'is-recycle' : '',
                            ],
                            style: { paddingLeft: `${12 + group.depth * 14}px` },
                            onClick: () => this.selectGroup(group.uuid),
                        },
                        [
                            h('span', { class: 'kw-group-label' }, group.isRecycleBin ? `${group.name} (Trash)` : group.name),
                            h('span', { class: 'kw-count-pill' }, String(group.totalEntryCount)),
                        ],
                    ),
                    group.children && group.children.length > 0 ? this.renderGroupNodes(group.children) : null,
                ]),
            )
        },

        renderEntryDetailPane() {
            if (this.editorMode) {
                return this.renderEntryEditorPane()
            }

            if (!this.activeEntry) {
                return h('div', { class: 'kw-detail-empty' }, [
                    h('p', 'Select an entry to view its credentials.'),
                    this.targetVault.writable
                        ? h(
                            'button',
                            {
                                type: 'button',
                                class: 'kw-btn kw-btn-primary',
                                onClick: () => this.openCreateEntryEditor(),
                            },
                            '+ Create entry',
                        )
                        : null,
                ])
            }

            const e = this.activeEntry
            const externalHref = safeExternalHref(e.url)

            return h('div', { class: 'kw-detail-content', 'data-testid': 'entry-detail' }, [
                h('div', { class: 'kw-detail-header' }, [
                    h('div', [
                        h('h2', { class: 'kw-entry-heading' }, e.title || 'Untitled entry'),
                        h('div', { class: 'kw-entry-submeta' }, [
                            e.groupName ? h('span', { class: 'kw-badge' }, e.groupName) : null,
                            ...(e.tags || []).map((tag) => h('span', { key: tag, class: 'kw-badge kw-badge-tag' }, `#${tag}`)),
                        ]),
                    ]),
                    this.targetVault.writable
                        ? h('div', { class: 'kw-header-actions' }, [
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: 'kw-btn kw-btn-secondary',
                                    onClick: () => this.openEditEntryEditor(),
                                },
                                'Edit',
                            ),
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: 'kw-btn kw-btn-danger',
                                    onClick: () => this.handleDeleteActiveEntry(),
                                },
                                'Delete',
                            ),
                        ])
                        : null,
                ]),

                h('div', { class: 'kw-cred-grid' }, [
                    h('div', { class: 'kw-cred-row' }, [
                        h('span', { class: 'kw-cred-label' }, 'Username'),
                        h('div', { class: 'kw-cred-value-wrap' }, [
                            h('span', { class: 'kw-cred-value kw-mono' }, e.username || '-'),
                            e.username
                                ? h(
                                    'button',
                                    {
                                        type: 'button',
                                        class: 'kw-btn kw-btn-small',
                                        onClick: () => this.copySecret(e.username, 'username'),
                                    },
                                    this.copiedFieldKey === 'username' ? 'Copied' : 'Copy',
                                )
                                : null,
                        ]),
                    ]),

                    h('div', { class: 'kw-cred-row' }, [
                        h('span', { class: 'kw-cred-label' }, 'Password'),
                        h('div', { class: 'kw-cred-value-wrap' }, [
                            h(
                                'span',
                                { class: 'kw-cred-value kw-mono', 'data-testid': 'entry-password-display' },
                                e.password ? (this.revealPassword ? e.password : '••••••••••••') : '-',
                            ),
                            e.password
                                ? h('div', { class: 'kw-inline-btns' }, [
                                    h(
                                        'button',
                                        {
                                            type: 'button',
                                            class: 'kw-btn kw-btn-small',
                                            onClick: () => {
                                                this.revealPassword = !this.revealPassword
                                            },
                                        },
                                        this.revealPassword ? 'Hide' : 'Show',
                                    ),
                                    h(
                                        'button',
                                        {
                                            type: 'button',
                                            class: 'kw-btn kw-btn-small kw-btn-primary',
                                            onClick: () => this.copySecret(e.password, 'password'),
                                        },
                                        this.copiedFieldKey === 'password' ? 'Copied' : 'Copy',
                                    ),
                                ])
                                : null,
                        ]),
                    ]),

                    this.totpState
                        ? h('div', { class: 'kw-cred-row kw-totp-row' }, [
                            h('span', { class: 'kw-cred-label' }, 'Verification code (TOTP)'),
                            h('div', { class: 'kw-cred-value-wrap' }, [
                                h('div', { class: 'kw-totp-box' }, [
                                    h(
                                        'span',
                                        { class: 'kw-totp-code kw-mono', 'data-testid': 'entry-totp-code' },
                                        this.totpState.code.replace(/^(\d{3})(\d+)$/, '$1 $2'),
                                    ),
                                    h('span', { class: 'kw-totp-timer' }, `${this.totpState.remainingSeconds}s`),
                                ]),
                                h(
                                    'button',
                                    {
                                        type: 'button',
                                        class: 'kw-btn kw-btn-small kw-btn-primary',
                                        onClick: () => this.copySecret(this.totpState.code, 'totp'),
                                    },
                                    this.copiedFieldKey === 'totp' ? 'Copied' : 'Copy code',
                                ),
                            ]),
                        ])
                        : null,

                    e.url
                        ? h('div', { class: 'kw-cred-row' }, [
                            h('span', { class: 'kw-cred-label' }, 'URL'),
                            h('div', { class: 'kw-cred-value-wrap' }, [
                                externalHref
                                    ? h(
                                        'a',
                                        {
                                            href: externalHref,
                                            target: '_blank',
                                            rel: 'noopener noreferrer',
                                            class: 'kw-link',
                                        },
                                        e.url,
                                    )
                                    : h('span', { class: 'kw-cred-value' }, e.url),
                                h(
                                    'button',
                                    {
                                        type: 'button',
                                        class: 'kw-btn kw-btn-small',
                                        onClick: () => this.copySecret(e.url, 'url'),
                                    },
                                    this.copiedFieldKey === 'url' ? 'Copied' : 'Copy',
                                ),
                            ]),
                        ])
                        : null,

                    ...(e.customFields || []).map((cf, idx) => {
                        const isShown = !cf.protected || Boolean(this.revealedCustomIndices[idx])
                        const copyKey = `cf-${idx}`
                        return h('div', { key: `${cf.key}-${idx}`, class: 'kw-cred-row' }, [
                            h('span', { class: 'kw-cred-label' }, cf.key),
                            h('div', { class: 'kw-cred-value-wrap' }, [
                                h('span', { class: 'kw-cred-value kw-mono' }, isShown ? cf.value : '••••••••••••'),
                                h('div', { class: 'kw-inline-btns' }, [
                                    cf.protected
                                        ? h(
                                            'button',
                                            {
                                                type: 'button',
                                                class: 'kw-btn kw-btn-small',
                                                onClick: () => {
                                                    this.revealedCustomIndices = {
                                                        ...this.revealedCustomIndices,
                                                        [idx]: !this.revealedCustomIndices[idx],
                                                    }
                                                },
                                            },
                                            isShown ? 'Hide' : 'Show',
                                        )
                                        : null,
                                    h(
                                        'button',
                                        {
                                            type: 'button',
                                            class: 'kw-btn kw-btn-small',
                                            onClick: () => this.copySecret(cf.value, copyKey),
                                        },
                                        this.copiedFieldKey === copyKey ? 'Copied' : 'Copy',
                                    ),
                                ]),
                            ]),
                        ])
                    }),
                ]),

                e.notes
                    ? h('div', { class: 'kw-notes-section' }, [
                        h('h3', { class: 'kw-section-title' }, 'Notes'),
                        h('pre', { class: 'kw-notes-body' }, e.notes),
                    ])
                    : null,

                e.attachments && e.attachments.length > 0
                    ? h('div', { class: 'kw-notes-section' }, [
                        h('h3', { class: 'kw-section-title' }, 'Attachments'),
                        h(
                            'div',
                            { class: 'kw-attachments-list' },
                            e.attachments.map((att) =>
                                h(
                                    'button',
                                    {
                                        key: att.name,
                                        type: 'button',
                                        class: 'kw-btn kw-btn-secondary kw-btn-small',
                                        onClick: () => this.downloadAttachment(att.name),
                                    },
                                    `${att.name} (${formatBytes(att.size)})`,
                                ),
                            ),
                        ),
                    ])
                    : null,

                h('div', { class: 'kw-detail-footer kw-muted' }, [
                    e.lastModTime ? h('span', `Updated: ${formatDateShort(e.lastModTime)}`) : null,
                    e.creationTime ? h('span', `Created: ${formatDateShort(e.creationTime)}`) : null,
                ]),
            ])
        },

        renderEntryEditorPane() {
            const flatGroups = flattenGroups(this.groupTree)
            return h('form', { class: 'kw-detail-content kw-editor-form', onSubmit: (e) => this.submitEntryEditor(e) }, [
                h('div', { class: 'kw-detail-header' }, [
                    h('h2', { class: 'kw-entry-heading' }, this.editorMode === 'create' ? 'New entry' : 'Edit entry'),
                    h('div', { class: 'kw-header-actions' }, [
                        h(
                            'button',
                            {
                                type: 'button',
                                class: 'kw-btn kw-btn-secondary',
                                onClick: () => {
                                    this.editorMode = null
                                },
                            },
                            'Cancel',
                        ),
                        h('button', { type: 'submit', class: 'kw-btn kw-btn-primary' }, 'Save entry'),
                    ]),
                ]),

                h('div', { class: 'kw-form-grid' }, [
                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Title'),
                        h('input', {
                            type: 'text',
                            class: 'kw-input',
                            required: true,
                            value: this.editorForm.title,
                            onInput: (e) => {
                                this.editorForm.title = e.target.value
                            },
                        }),
                    ]),

                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Group'),
                        h(
                            'select',
                            {
                                class: 'kw-input',
                                value: this.editorForm.groupUuid,
                                onChange: (e) => {
                                    this.editorForm.groupUuid = e.target.value
                                },
                            },
                            flatGroups.map((g) =>
                                h('option', { key: g.uuid, value: g.uuid }, `${'  '.repeat(g.depth)}${g.name}`),
                            ),
                        ),
                    ]),

                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Username'),
                        h('input', {
                            type: 'text',
                            class: 'kw-input kw-mono',
                            autocomplete: 'off',
                            value: this.editorForm.username,
                            onInput: (e) => {
                                this.editorForm.username = e.target.value
                            },
                        }),
                    ]),

                    h('div', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Password'),
                        h('div', { class: 'kw-input-row' }, [
                            h('input', {
                                type: this.showEditorPassword ? 'text' : 'password',
                                class: 'kw-input kw-mono',
                                autocomplete: 'new-password',
                                value: this.editorForm.password,
                                onInput: (e) => {
                                    this.editorForm.password = e.target.value
                                },
                            }),
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: 'kw-btn kw-btn-secondary',
                                    onClick: () => {
                                        this.showEditorPassword = !this.showEditorPassword
                                    },
                                },
                                this.showEditorPassword ? 'Hide' : 'Show',
                            ),
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: 'kw-btn kw-btn-secondary',
                                    onClick: () => {
                                        this.showPasswordGen = !this.showPasswordGen
                                    },
                                },
                                'Generator',
                            ),
                        ]),

                        this.showPasswordGen
                            ? h('div', { class: 'kw-pwgen-panel' }, [
                                h('div', { class: 'kw-pwgen-controls' }, [
                                    h('label', [
                                        `Length: ${this.pwGenOptions.length}`,
                                        h('input', {
                                            type: 'range',
                                            min: '8',
                                            max: '64',
                                            value: String(this.pwGenOptions.length),
                                            onInput: (e) => {
                                                this.pwGenOptions.length = Number(e.target.value)
                                                this.regenerateEditorPassword()
                                            },
                                        }),
                                    ]),
                                    h('label', [
                                        h('input', {
                                            type: 'checkbox',
                                            checked: this.pwGenOptions.upper,
                                            onChange: (e) => {
                                                this.pwGenOptions.upper = e.target.checked
                                                this.regenerateEditorPassword()
                                            },
                                        }),
                                        ' A-Z',
                                    ]),
                                    h('label', [
                                        h('input', {
                                            type: 'checkbox',
                                            checked: this.pwGenOptions.lower,
                                            onChange: (e) => {
                                                this.pwGenOptions.lower = e.target.checked
                                                this.regenerateEditorPassword()
                                            },
                                        }),
                                        ' a-z',
                                    ]),
                                    h('label', [
                                        h('input', {
                                            type: 'checkbox',
                                            checked: this.pwGenOptions.digits,
                                            onChange: (e) => {
                                                this.pwGenOptions.digits = e.target.checked
                                                this.regenerateEditorPassword()
                                            },
                                        }),
                                        ' 0-9',
                                    ]),
                                    h('label', [
                                        h('input', {
                                            type: 'checkbox',
                                            checked: this.pwGenOptions.symbols,
                                            onChange: (e) => {
                                                this.pwGenOptions.symbols = e.target.checked
                                                this.regenerateEditorPassword()
                                            },
                                        }),
                                        ' Symbols',
                                    ]),
                                    h(
                                        'button',
                                        {
                                            type: 'button',
                                            class: 'kw-btn kw-btn-small kw-btn-primary',
                                            onClick: () => this.regenerateEditorPassword(),
                                        },
                                        'Regenerate',
                                    ),
                                ]),
                            ])
                            : null,
                    ]),

                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'URL'),
                        h('input', {
                            type: 'text',
                            class: 'kw-input',
                            placeholder: 'https://example.org',
                            value: this.editorForm.url,
                            onInput: (e) => {
                                this.editorForm.url = e.target.value
                            },
                        }),
                    ]),

                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'TOTP secret (Base32 or otpauth:// URI)'),
                        h('input', {
                            type: 'text',
                            class: 'kw-input kw-mono',
                            placeholder: 'JBSWY3DPEHPK3PXP or otpauth://totp/...',
                            autocomplete: 'off',
                            value: this.editorForm.otpRaw,
                            onInput: (e) => {
                                this.editorForm.otpRaw = e.target.value
                            },
                        }),
                    ]),

                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Tags (comma-separated)'),
                        h('input', {
                            type: 'text',
                            class: 'kw-input',
                            placeholder: 'work, infrastructure',
                            value: this.editorForm.tagsText,
                            onInput: (e) => {
                                this.editorForm.tagsText = e.target.value
                            },
                        }),
                    ]),

                    h('label', { class: 'kw-field' }, [
                        h('span', { class: 'kw-label' }, 'Notes'),
                        h('textarea', {
                            rows: 4,
                            class: 'kw-input kw-textarea',
                            value: this.editorForm.notes,
                            onInput: (e) => {
                                this.editorForm.notes = e.target.value
                            },
                        }),
                    ]),

                    h('div', { class: 'kw-field' }, [
                        h('div', { class: 'kw-custom-fields-header' }, [
                            h('span', { class: 'kw-label' }, 'Custom fields'),
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: 'kw-btn kw-btn-small kw-btn-secondary',
                                    onClick: () => {
                                        this.editorForm.customFields.push({ key: '', value: '', protected: true })
                                    },
                                },
                                '+ Add field',
                            ),
                        ]),
                        ...this.editorForm.customFields.map((cf, idx) =>
                            h('div', { key: idx, class: 'kw-custom-field-row' }, [
                                h('input', {
                                    type: 'text',
                                    class: 'kw-input',
                                    placeholder: 'Field name',
                                    value: cf.key,
                                    onInput: (e) => {
                                        cf.key = e.target.value
                                    },
                                }),
                                h('input', {
                                    type: cf.protected ? 'password' : 'text',
                                    class: 'kw-input kw-mono',
                                    placeholder: 'Value',
                                    value: cf.value,
                                    onInput: (e) => {
                                        cf.value = e.target.value
                                    },
                                }),
                                h('label', { class: 'kw-checkbox-inline' }, [
                                    h('input', {
                                        type: 'checkbox',
                                        checked: cf.protected,
                                        onChange: (e) => {
                                            cf.protected = e.target.checked
                                        },
                                    }),
                                    'Protected',
                                ]),
                                h(
                                    'button',
                                    {
                                        type: 'button',
                                        class: 'kw-btn kw-btn-small kw-btn-danger',
                                        onClick: () => {
                                            this.editorForm.customFields.splice(idx, 1)
                                        },
                                    },
                                    'Remove',
                                ),
                            ]),
                        ),
                    ]),
                ]),
            ])
        },

        renderWorkspaceScreen() {
            const meta = this.vaultMeta || {}
            const totalAllEntries = queryEntries(this.dbRef, { groupUuid: null, searchQuery: '' }).length

            return h('div', { class: 'kw-workspace', 'data-testid': 'vault-workspace' }, [
                h('header', { class: 'kw-topbar' }, [
                    h('div', { class: 'kw-topbar-left' }, [
                        h('strong', { class: 'kw-topbar-title' }, meta.name || this.targetVault.name),
                        h(
                            'span',
                            { class: 'kw-badge kw-badge-accent' },
                            `${meta.versionLabel || 'KDBX'} (${meta.kdfName || 'Encrypted'})`,
                        ),
                        !this.targetVault.writable
                            ? h('span', { class: 'kw-badge kw-badge-readonly' }, this.targetVault.localOnly ? 'Local preview' : 'Read-only')
                            : null,
                        h('span', { class: ['kw-status-text', this.isDirty ? 'is-dirty' : ''] }, this.saveStatusText),
                    ]),
                    h('div', { class: 'kw-topbar-right' }, [
                        this.targetVault.writable && !this.targetVault.localOnly
                            ? h(
                                'button',
                                {
                                    type: 'button',
                                    class: 'kw-btn kw-btn-primary',
                                    disabled: this.savingVault || !this.isDirty,
                                    onClick: () => this.persistVaultToServer(),
                                },
                                this.savingVault ? 'Saving...' : 'Save',
                            )
                            : null,
                        h(
                            'button',
                            {
                                type: 'button',
                                class: 'kw-btn kw-btn-secondary',
                                onClick: () => this.exportEncryptedVault(),
                            },
                            'Export .kdbx',
                        ),
                        h(
                            'button',
                            {
                                type: 'button',
                                class: 'kw-btn kw-btn-secondary',
                                onClick: () => this.loadVaultPicker(),
                            },
                            'Switch vault',
                        ),
                        h(
                            'button',
                            {
                                type: 'button',
                                class: 'kw-btn kw-btn-secondary',
                                onClick: () => this.lockVault(),
                            },
                            'Lock',
                        ),
                    ]),
                ]),

                this.etagConflict
                    ? h('div', { class: 'kw-conflict-banner', role: 'alert' }, [
                        h(
                            'span',
                            'Conflict detected: this vault file was updated on Nextcloud by another session. Export your copy or reload from server.',
                        ),
                        h('div', { class: 'kw-inline-btns' }, [
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: 'kw-btn kw-btn-small kw-btn-secondary',
                                    onClick: () => this.exportEncryptedVault(),
                                },
                                'Export copy (.kdbx)',
                            ),
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: 'kw-btn kw-btn-small kw-btn-primary',
                                    onClick: () => this.prepareRemoteVaultUnlock(this.targetVault.path),
                                },
                                'Reload from server',
                            ),
                        ]),
                    ])
                    : this.saveError
                        ? h('div', { class: 'kw-conflict-banner', role: 'alert' }, this.saveError)
                        : null,

                h('div', { class: 'kw-panes' }, [
                    // Left sidebar: groups
                    h('aside', { class: 'kw-pane-groups' }, [
                        h('div', { class: 'kw-pane-header' }, [
                            h('span', { class: 'kw-pane-title' }, 'Groups'),
                            this.targetVault.writable
                                ? h(
                                    'button',
                                    {
                                        type: 'button',
                                        class: 'kw-btn kw-btn-small kw-btn-ghost',
                                        onClick: () => {
                                            this.showNewGroupInput = !this.showNewGroupInput
                                        },
                                    },
                                    '+ Group',
                                )
                                : null,
                        ]),
                        this.showNewGroupInput && this.targetVault.writable
                            ? h('form', { class: 'kw-new-group-form', onSubmit: (e) => this.submitNewGroup(e) }, [
                                h('input', {
                                    type: 'text',
                                    class: 'kw-input kw-input-compact',
                                    placeholder: 'Group name...',
                                    value: this.newGroupName,
                                    onInput: (e) => {
                                        this.newGroupName = e.target.value
                                    },
                                }),
                                h('button', { type: 'submit', class: 'kw-btn kw-btn-small kw-btn-primary' }, 'Add'),
                            ])
                            : null,
                        h('div', { class: 'kw-groups-scroll' }, [
                            h(
                                'button',
                                {
                                    type: 'button',
                                    class: ['kw-group-item', this.selectedGroupUuid === null ? 'is-selected' : ''],
                                    onClick: () => this.selectGroup(null),
                                },
                                [
                                    h('span', { class: 'kw-group-label' }, 'All entries'),
                                    h('span', { class: 'kw-count-pill' }, String(totalAllEntries)),
                                ],
                            ),
                            ...this.renderGroupNodes(this.groupTree),
                        ]),
                    ]),

                    // Center pane: search + entries
                    h('section', { class: 'kw-pane-entries' }, [
                        h('div', { class: 'kw-search-bar' }, [
                            h('input', {
                                type: 'search',
                                class: 'kw-input',
                                placeholder: 'Search entries...',
                                'aria-label': 'Search entries',
                                value: this.searchQuery,
                                onInput: (e) => this.updateSearch(e.target.value),
                            }),
                            this.targetVault.writable
                                ? h(
                                    'button',
                                    {
                                        type: 'button',
                                        class: 'kw-btn kw-btn-primary',
                                        onClick: () => this.openCreateEntryEditor(),
                                    },
                                    '+ New',
                                )
                                : null,
                        ]),

                        this.entries.length === 0
                            ? h('div', { class: 'kw-empty-entries' }, 'No matching entries.')
                            : h(
                                'ul',
                                { class: 'kw-entry-list', 'data-testid': 'entry-list' },
                                this.entries.map((item) =>
                                    h(
                                        'li',
                                        {
                                            key: item.uuid,
                                            class: ['kw-entry-item', this.selectedEntryUuid === item.uuid ? 'is-selected' : ''],
                                            onClick: () => this.selectEntry(item.uuid),
                                        },
                                        [
                                            h(
                                                'div',
                                                { class: 'kw-entry-avatar' },
                                                (item.title || '?').slice(0, 1).toUpperCase(),
                                            ),
                                            h('div', { class: 'kw-entry-summary' }, [
                                                h('div', { class: 'kw-entry-title-row' }, [
                                                    h('span', { class: 'kw-entry-title' }, item.title),
                                                    item.hasTotp ? h('span', { class: 'kw-mini-pill' }, '2FA') : null,
                                                ]),
                                                h(
                                                    'span',
                                                    { class: 'kw-entry-sub' },
                                                    item.username || item.url || item.groupName || 'No username',
                                                ),
                                            ]),
                                        ],
                                    ),
                                ),
                            ),
                    ]),

                    // Right pane: inspector or editor
                    h('main', { class: 'kw-pane-detail' }, [this.renderEntryDetailPane()]),
                ]),
            ])
        },
    },
    render() {
        if (this.screen === 'unlock') {
            return this.renderUnlockScreen()
        }
        if (this.screen === 'workspace') {
            return this.renderWorkspaceScreen()
        }
        return this.renderPickerScreen()
    },
})
