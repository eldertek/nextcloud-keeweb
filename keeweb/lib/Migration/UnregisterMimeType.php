<?php
declare(strict_types=1);

namespace OCA\Keeweb\Migration;

use OCP\Migration\IOutput;

class UnregisterMimeType extends MimeTypeMigration {
    private const ALIASES_FILE = 'mimetypealiases.json';
    private const MAPPING_FILE = 'mimetypemapping.json';

    public function getName(): string {
        return 'Unregister MIME type for "application/x-kdbx"';
    }

    public function run(IOutput $output): void {
        $output->info('Unregistering the application/x-kdbx mimetype...');

        $mimeTypeId = $this->mimeTypeLoader->getId('application/octet-stream');
        $this->mimeTypeLoader->updateFilecache('kdbx', $mimeTypeId);

        $configDir = $this->resolveConfigDir();
        if ($configDir !== null && is_dir($configDir)) {
            $this->removeKeysFromJsonFile($configDir . self::ALIASES_FILE, ['application/x-kdbx']);
            $this->removeKeysFromJsonFile($configDir . self::MAPPING_FILE, ['kdbx']);
        }

        $output->info('The application/x-kdbx mimetype was unregistered.');
    }

    /**
     * @param list<string> $keys
     */
    private function removeKeysFromJsonFile(string $filename, array $keys): void {
        if (!is_file($filename) || !is_readable($filename) || !is_writable($filename)) {
            return;
        }
        $raw = file_get_contents($filename);
        if (!is_string($raw) || trim($raw) === '') {
            return;
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return;
        }
        foreach ($keys as $key) {
            unset($decoded[$key]);
        }
        $encoded = json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (is_string($encoded)) {
            file_put_contents($filename, $encoded . "\n", LOCK_EX);
        }
    }
}
