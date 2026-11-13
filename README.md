# Keeweb for Nextcloud

Open, search, create, and edit encrypted KeePass password databases (`.kdbx`) directly inside [Nextcloud](https://nextcloud.com/), with 100% client-side encryption and decryption in your browser.

Compatible with **Nextcloud 28 through 35** and **PHP 8.1+**.

## Highlights in v0.7.0

- **Native KDBX 3.1 and KDBX 4.0 / 4.1 support**: Powered directly by [`kdbxweb`](https://github.com/keeweb/kdbxweb) v2.1+ with WebAssembly Argon2d / Argon2id (`hash-wasm`) and pure-JS fallback (`@noble/hashes`), eliminating the KDBX 4 corruption bug of the legacy static KeeWeb bundle.
- **Zero-knowledge client-side cryptography**: Master passwords, key files, and decrypted entries never leave your browser. Nextcloud only stores and transfers encrypted `.kdbx` binaries.
- **Strict Content Security Policy (CSP)**: Runs natively inside Nextcloud without `<iframe>`, `unsafe-inline` scripts, `unsafe-eval`, `appcache`, or external requests to third-party servers. Argon2 key derivation runs in a same-origin Web Worker (`worker-src 'self'`, `wasm-unsafe-eval`).
- **Complete vault workflow**:
  - Unlock with master password, key file (uploaded locally or selected from Nextcloud Files), or both.
  - Create brand-new **KDBX 4.1 (Argon2id)** or **KDBX 3.1 (AES-KDF)** vaults directly in Nextcloud.
  - Browse nested groups, filter instantaneously across titles, usernames, URLs, tags, custom fields, and notes.
  - Masked passwords by default with one-click copy, CSPRNG password generator, custom protected fields, binary attachment downloads, and built-in **RFC 6238 TOTP (2FA)** live codes.
- **Safe concurrent storage & sharing**:
  - Atomic VFS persistence with **ETag (`If-Match`) concurrency verification** so concurrent edits from desktop/mobile WebDAV clients (KeePassXC, KeePassDX, Keepass2Android) are never silently overwritten.
  - Automatic **Read-only mode** when opening a `.kdbx` vault from a read-only share or external mount.
- **Nextcloud Files integration**: Registers `application/x-kdbx` and opens `.kdbx` files on direct click in Nextcloud Files across Nextcloud 28 to 35, adapting automatically to Nextcloud Light, Dark, and Breeze Dark themes.

## Installation

### From a release archive

1. Download `keeweb-0.7.0.tar.gz` from the Releases page.
2. Extract it into your Nextcloud `custom_apps` directory:
   ```bash
   tar xzf keeweb-0.7.0.tar.gz -C /path/to/nextcloud/custom_apps
   ```
3. Enable the app via `occ` or the Nextcloud Apps administration screen:
   ```bash
   php occ app:enable keeweb
   ```

## Development & Building from Source

Requirements: Node.js 20+ and npm 9+.

```bash
git clone https://github.com/eldertek/nextcloud-keeweb.git
cd nextcloud-keeweb/keeweb

# Install dependencies
npm ci

# Run the automated KDBX 3.1 / KDBX 4.1 Argon2 + TOTP test suite
npm test

# Compile production bundles (js/main.js, js/viewer.js, js/argon2-worker.js)
npm run build

# Build the Nextcloud App Store archive in build/artifacts/appstore/keeweb.tar.gz
make appstore
```

To run the full end-to-end HTTP + WebDAV + CSP + ETag verification suite against a running Nextcloud instance:

```bash
NC_BASE_URL="http://127.0.0.1:8035" NC_USER="qa-admin" NC_PASS="your-password" node tests/e2e-nextcloud.mjs
```

## Supporting the Project

- [GitHub Sponsors](https://github.com/sponsors/eldertek)
- [Patreon](https://patreon.com/eldertek)

## License

Licensed under the **GNU Affero General Public License v3.0 or later** (`AGPL-3.0-or-later`). See [COPYING](COPYING) for the full license text.

## Commercial Support & Custom Integration

Need custom features, enterprise integration, or priority support?
Maintained by **[Eclipse Technology](https://eclipse-technology.eu)** ([contact@eclipse-technology.eu](mailto:contact@eclipse-technology.eu)).
