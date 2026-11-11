<?php
declare(strict_types=1);

namespace OCA\Keeweb\Migration;

use OCP\Migration\IOutput;

class RegisterMimeType extends MimeTypeMigration {
    private const ALIASES_FILE = 'mimetypealiases.json';
    private const MAPPING_FILE = 'mimetypemapping.json';

    public function getName(): string {
        return 'Register MIME type for "application/x-kdbx"';
    }

    public function run(IOutput $output): void {
        $output->info('Registering the application/x-kdbx mimetype...');

        $mimeTypeId = $this->mimeTypeLoader->getId('application/x-kdbx');
        $this->mimeTypeLoader->updateFilecache('kdbx', $mimeTypeId);

        $configDir = $this->resolveConfigDir();
        if ($configDir !== null && is_dir($configDir) && is_writable($configDir)) {
            $this->mergeJsonFile($configDir . self::ALIASES_FILE, ['application/x-kdbx' => 'kdbx']);
            $this->mergeJsonFile($configDir . self::MAPPING_FILE, ['kdbx' => ['application/x-kdbx']]);
        }

        $output->info('The application/x-kdbx mimetype was registered.');
    }

    /**
     * @param array<string, mixed> $entries
     */
    private function mergeJsonFile(string $filename, array $entries): void {
        $current = [];
        if (is_file($filename) && is_readable($filename)) {
            $raw = file_get_contents($filename);
            if (is_string($raw) && trim($raw) !== '') {
                $decoded = json_decode($raw, true);
                if (is_array($decoded)) {
                    $current = $decoded;
                }
            }
        }

        if (is_file($filename) && !is_writable($filename)) {
            return;
        }

        foreach ($entries as $key => $value) {
            $current[$key] = $value;
        }

        $encoded = json_encode($current, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (is_string($encoded)) {
            file_put_contents($filename, $encoded . "\n", LOCK_EX);
        }
    }
}
