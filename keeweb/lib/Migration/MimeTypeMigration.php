<?php
declare(strict_types=1);

namespace OCA\Keeweb\Migration;

use OCP\Files\IMimeTypeLoader;
use OCP\Migration\IRepairStep;

abstract class MimeTypeMigration implements IRepairStep {
    public const CUSTOM_MIMETYPEMAPPING = 'mimetypemapping.json';
    public const CUSTOM_MIMETYPEALIASES = 'mimetypealiases.json';

    public function __construct(
        protected IMimeTypeLoader $mimeTypeLoader,
    ) {
    }

    protected function resolveConfigDir(): ?string {
        if (isset(\OC::$configDir) && is_string(\OC::$configDir) && \OC::$configDir !== '') {
            return rtrim(\OC::$configDir, '/\\') . DIRECTORY_SEPARATOR;
        }
        return null;
    }
}
