<?php
declare(strict_types=1);

/**
 * Nextcloud - keeweb
 *
 * This file is licensed under the Affero General Public License version 3 or
 * later. See the COPYING file.
 *
 * @author André Théo LAURET <andrelauret@eclipse-technology.eu>
 * @copyright André Théo LAURET 2026
 */

namespace OCA\Keeweb\Controller;

use OCA\Keeweb\AppInfo\Application;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\DataDisplayResponse;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\Response;
use OCP\Files\File;
use OCP\Files\Folder;
use OCP\Files\IRootFolder;
use OCP\Files\NotFoundException;
use OCP\Files\NotPermittedException;
use OCP\IRequest;
use OCP\IUserSession;

class VaultController extends Controller {
    private const KDBX_MAGIC = "\x03\xd9\xa2\x9a";
    private const MIN_KDBX_BYTES = 64;

    public function __construct(
        IRequest $request,
        private IRootFolder $rootFolder,
        private IUserSession $userSession,
    ) {
        parent::__construct(Application::APP_ID, $request);
    }

    #[NoAdminRequired]
    #[NoCSRFRequired]
    public function files(?string $kind = 'kdbx'): JSONResponse {
        $userFolder = $this->resolveUserFolder();
        if ($userFolder === null) {
            return new JSONResponse(['error' => 'Authentication required', 'code' => 'UNAUTHENTICATED'], Http::STATUS_UNAUTHORIZED);
        }

        $seenIds = [];
        $items = [];

        if ($kind === 'keyfile') {
            $candidates = array_merge(
                $userFolder->search('.key'),
                $userFolder->search('.keyx'),
            );
            foreach ($candidates as $node) {
                if (!$node instanceof File || !$node->isReadable()) {
                    continue;
                }
                $lower = strtolower($node->getName());
                if (!str_ends_with($lower, '.key') && !str_ends_with($lower, '.keyx')) {
                    continue;
                }
                $id = $node->getId();
                if (isset($seenIds[$id])) {
                    continue;
                }
                $seenIds[$id] = true;
                $items[] = $this->serializeFileNode($userFolder, $node);
            }
        } else {
            $candidates = array_merge(
                $userFolder->searchByMime('application/x-kdbx'),
                $userFolder->search('.kdbx'),
            );
            foreach ($candidates as $node) {
                if (!$node instanceof File || !$node->isReadable()) {
                    continue;
                }
                $lower = strtolower($node->getName());
                if ($node->getMimeType() !== 'application/x-kdbx' && !str_ends_with($lower, '.kdbx')) {
                    continue;
                }
                $id = $node->getId();
                if (isset($seenIds[$id])) {
                    continue;
                }
                $seenIds[$id] = true;
                $items[] = $this->serializeFileNode($userFolder, $node);
            }
        }

        usort($items, static fn (array $a, array $b): int => ($b['mtime'] <=> $a['mtime']));

        return new JSONResponse(['files' => $items]);
    }

    #[NoAdminRequired]
    #[NoCSRFRequired]
    public function load(?string $path = null): Response {
        $userFolder = $this->resolveUserFolder();
        if ($userFolder === null) {
            return new JSONResponse(['error' => 'Authentication required', 'code' => 'UNAUTHENTICATED'], Http::STATUS_UNAUTHORIZED);
        }

        $relativePath = $this->normalizeRelativePath($path);
        if ($relativePath === null || $relativePath === '/') {
            return new JSONResponse(['error' => 'Invalid vault path', 'code' => 'INVALID_PATH'], Http::STATUS_BAD_REQUEST);
        }

        try {
            $node = $userFolder->get($relativePath);
        } catch (NotFoundException) {
            return new JSONResponse(['error' => 'Vault file not found', 'code' => 'NOT_FOUND'], Http::STATUS_NOT_FOUND);
        }

        if (!$node instanceof File) {
            return new JSONResponse(['error' => 'Target path is not a file', 'code' => 'NOT_A_FILE'], Http::STATUS_BAD_REQUEST);
        }

        if (!$node->isReadable()) {
            return new JSONResponse(['error' => 'Read permission denied', 'code' => 'FORBIDDEN'], Http::STATUS_FORBIDDEN);
        }

        try {
            $content = $node->getContent();
        } catch (NotPermittedException) {
            return new JSONResponse(['error' => 'Unable to read vault content', 'code' => 'FORBIDDEN'], Http::STATUS_FORBIDDEN);
        }

        $etag = (string)$node->getEtag();
        $writable = $node->isUpdateable();

        $headers = [
            'Content-Type' => 'application/x-kdbx',
            'Cache-Control' => 'no-store, no-cache, must-revalidate',
            'ETag' => '"' . $etag . '"',
            'X-Keeweb-Etag' => $etag,
            'X-Keeweb-Writable' => $writable ? '1' : '0',
            'X-Keeweb-Mtime' => (string)$node->getMTime(),
            'X-Keeweb-Filename' => rawurlencode($node->getName()),
        ];

        return new DataDisplayResponse($content, Http::STATUS_OK, $headers);
    }

    #[NoAdminRequired]
    public function save(?string $path = null): JSONResponse {
        $rawBody = file_get_contents('php://input');
        if (!is_string($rawBody)) {
            $rawBody = '';
        }
        $ifMatch = $this->request->getHeader('If-Match');
        if ($ifMatch === '') {
            $ifMatch = $this->request->getHeader('X-Keeweb-If-Match');
        }
        return $this->persistExistingVault($path, $ifMatch, $rawBody);
    }

    #[NoAdminRequired]
    public function update(?string $path = null, ?string $etag = null, ?string $dataBase64 = null): JSONResponse {
        $bytes = '';
        if (is_string($dataBase64) && $dataBase64 !== '') {
            $decoded = base64_decode($dataBase64, true);
            if ($decoded === false) {
                return new JSONResponse(['error' => 'Invalid base64 payload', 'code' => 'INVALID_PAYLOAD'], Http::STATUS_BAD_REQUEST);
            }
            $bytes = $decoded;
        } else {
            $rawBody = file_get_contents('php://input');
            if (is_string($rawBody)) {
                $bytes = $rawBody;
            }
        }

        $expectedEtag = $etag ?? '';
        if ($expectedEtag === '') {
            $expectedEtag = $this->request->getHeader('If-Match');
        }
        if ($expectedEtag === '') {
            $expectedEtag = $this->request->getHeader('X-Keeweb-If-Match');
        }

        return $this->persistExistingVault($path, $expectedEtag, $bytes);
    }

    #[NoAdminRequired]
    public function create(?string $path = null, ?string $dataBase64 = null): JSONResponse {
        $userFolder = $this->resolveUserFolder();
        if ($userFolder === null) {
            return new JSONResponse(['error' => 'Authentication required', 'code' => 'UNAUTHENTICATED'], Http::STATUS_UNAUTHORIZED);
        }

        $relativePath = $this->normalizeRelativePath($path);
        if ($relativePath === null || $relativePath === '/') {
            return new JSONResponse(['error' => 'Invalid vault path', 'code' => 'INVALID_PATH'], Http::STATUS_BAD_REQUEST);
        }

        if (!str_ends_with(strtolower($relativePath), '.kdbx')) {
            $relativePath .= '.kdbx';
        }

        if ($userFolder->nodeExists($relativePath)) {
            return new JSONResponse(['error' => 'A file already exists at this path', 'code' => 'ALREADY_EXISTS'], Http::STATUS_CONFLICT);
        }

        $bytes = '';
        if (is_string($dataBase64) && $dataBase64 !== '') {
            $decoded = base64_decode($dataBase64, true);
            if ($decoded === false) {
                return new JSONResponse(['error' => 'Invalid base64 payload', 'code' => 'INVALID_PAYLOAD'], Http::STATUS_BAD_REQUEST);
            }
            $bytes = $decoded;
        } else {
            $rawBody = file_get_contents('php://input');
            if (is_string($rawBody)) {
                $bytes = $rawBody;
            }
        }

        if (!$this->isValidKdbxBytes($bytes)) {
            return new JSONResponse(['error' => 'Payload is not a valid KDBX archive', 'code' => 'INVALID_KDBX'], Http::STATUS_UNPROCESSABLE_ENTITY);
        }

        $parentPath = dirname($relativePath);
        if ($parentPath === '.' || $parentPath === '\\') {
            $parentPath = '/';
        }
        $fileName = basename($relativePath);

        try {
            $parentFolder = $this->ensureFolder($userFolder, $parentPath);
            if (!$parentFolder->isCreatable()) {
                return new JSONResponse(['error' => 'Cannot create files in target folder', 'code' => 'READ_ONLY'], Http::STATUS_FORBIDDEN);
            }
            $file = $parentFolder->newFile($fileName);
            $file->putContent($bytes);
            $fresh = $userFolder->get($relativePath);
        } catch (NotPermittedException) {
            return new JSONResponse(['error' => 'Write permission denied', 'code' => 'READ_ONLY'], Http::STATUS_FORBIDDEN);
        } catch (NotFoundException) {
            return new JSONResponse(['error' => 'Target folder not found', 'code' => 'NOT_FOUND'], Http::STATUS_NOT_FOUND);
        }

        if (!$fresh instanceof File) {
            return new JSONResponse(['error' => 'Created node is invalid', 'code' => 'INTERNAL_ERROR'], Http::STATUS_INTERNAL_SERVER_ERROR);
        }

        return new JSONResponse([
            'status' => 'ok',
            'path' => $relativePath,
            'name' => $fresh->getName(),
            'etag' => (string)$fresh->getEtag(),
            'mtime' => $fresh->getMTime(),
            'size' => $fresh->getSize(),
            'writable' => $fresh->isUpdateable(),
        ], Http::STATUS_CREATED);
    }

    private function persistExistingVault(?string $path, string $rawExpectedEtag, string $bytes): JSONResponse {
        $userFolder = $this->resolveUserFolder();
        if ($userFolder === null) {
            return new JSONResponse(['error' => 'Authentication required', 'code' => 'UNAUTHENTICATED'], Http::STATUS_UNAUTHORIZED);
        }

        $relativePath = $this->normalizeRelativePath($path);
        if ($relativePath === null || $relativePath === '/') {
            return new JSONResponse(['error' => 'Invalid vault path', 'code' => 'INVALID_PATH'], Http::STATUS_BAD_REQUEST);
        }

        try {
            $node = $userFolder->get($relativePath);
        } catch (NotFoundException) {
            return new JSONResponse(['error' => 'Vault file not found', 'code' => 'NOT_FOUND'], Http::STATUS_NOT_FOUND);
        }

        if (!$node instanceof File) {
            return new JSONResponse(['error' => 'Target path is not a file', 'code' => 'NOT_A_FILE'], Http::STATUS_BAD_REQUEST);
        }

        if (!$node->isUpdateable()) {
            return new JSONResponse([
                'error' => 'This vault is read-only. You do not have write permission on this file.',
                'code' => 'READ_ONLY',
            ], Http::STATUS_FORBIDDEN);
        }

        $expectedEtag = $this->cleanEtag($rawExpectedEtag);
        if ($expectedEtag === '') {
            return new JSONResponse([
                'error' => 'Missing ETag precondition (If-Match header required).',
                'code' => 'MISSING_ETAG',
            ], 428);
        }

        $currentEtag = (string)$node->getEtag();
        if ($expectedEtag !== $currentEtag) {
            return new JSONResponse([
                'error' => 'Vault was modified on the server since it was loaded. Reload or export a copy to avoid overwriting concurrent edits.',
                'code' => 'ETAG_CONFLICT',
                'currentEtag' => $currentEtag,
                'mtime' => $node->getMTime(),
            ], Http::STATUS_CONFLICT);
        }

        if (!$this->isValidKdbxBytes($bytes)) {
            return new JSONResponse([
                'error' => 'Payload is not a valid KDBX archive.',
                'code' => 'INVALID_KDBX',
            ], Http::STATUS_UNPROCESSABLE_ENTITY);
        }

        try {
            $node->putContent($bytes);
            $fresh = $userFolder->get($relativePath);
        } catch (NotPermittedException) {
            return new JSONResponse([
                'error' => 'Write permission denied while saving vault.',
                'code' => 'READ_ONLY',
            ], Http::STATUS_FORBIDDEN);
        }

        $updatedFile = $fresh instanceof File ? $fresh : $node;

        return new JSONResponse([
            'status' => 'ok',
            'path' => $relativePath,
            'etag' => (string)$updatedFile->getEtag(),
            'mtime' => $updatedFile->getMTime(),
            'size' => $updatedFile->getSize(),
            'writable' => $updatedFile->isUpdateable(),
        ], Http::STATUS_OK);
    }

    private function resolveUserFolder(): ?Folder {
        $user = $this->userSession->getUser();
        if ($user === null) {
            return null;
        }
        try {
            return $this->rootFolder->getUserFolder($user->getUID());
        } catch (NotPermittedException) {
            return null;
        }
    }

    private function normalizeRelativePath(?string $path): ?string {
        if (!is_string($path)) {
            return null;
        }
        $trimmed = trim($path);
        if ($trimmed === '' || str_contains($trimmed, "\0")) {
            return null;
        }
        $normalized = str_replace('\\', '/', $trimmed);
        $parts = explode('/', $normalized);
        $clean = [];
        foreach ($parts as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                return null;
            }
            $clean[] = $segment;
        }
        if ($clean === []) {
            return '/';
        }
        return '/' . implode('/', $clean);
    }

    private function cleanEtag(string $raw): string {
        $trimmed = trim($raw);
        if (str_starts_with($trimmed, 'W/')) {
            $trimmed = trim(substr($trimmed, 2));
        }
        return trim($trimmed, "\"' \t\r\n");
    }

    private function isValidKdbxBytes(string $bytes): bool {
        return strlen($bytes) >= self::MIN_KDBX_BYTES
            && substr($bytes, 0, 4) === self::KDBX_MAGIC;
    }

    private function ensureFolder(Folder $userFolder, string $folderPath): Folder {
        if ($folderPath === '/' || $folderPath === '') {
            return $userFolder;
        }
        $segments = array_values(array_filter(explode('/', $folderPath), static fn (string $s): bool => $s !== ''));
        $current = $userFolder;
        foreach ($segments as $segment) {
            if ($current->nodeExists($segment)) {
                $next = $current->get($segment);
                if (!$next instanceof Folder) {
                    throw new NotPermittedException('Parent segment is not a folder');
                }
                $current = $next;
            } else {
                $current = $current->newFolder($segment);
            }
        }
        return $current;
    }

    /**
     * @return array<string, int|string|bool>
     */
    private function serializeFileNode(Folder $userFolder, File $node): array {
        $relative = $userFolder->getRelativePath($node->getPath());
        $path = is_string($relative) && $relative !== '' ? $relative : ('/' . $node->getName());
        if (!str_starts_with($path, '/')) {
            $path = '/' . $path;
        }
        return [
            'id' => $node->getId(),
            'path' => $path,
            'name' => $node->getName(),
            'size' => $node->getSize(),
            'mtime' => $node->getMTime(),
            'etag' => (string)$node->getEtag(),
            'writable' => $node->isUpdateable(),
        ];
    }
}
