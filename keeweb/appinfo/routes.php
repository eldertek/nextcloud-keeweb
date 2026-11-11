<?php
declare(strict_types=1);

/**
 * Nextcloud - keeweb
 *
 * This file is licensed under the Affero General Public License version 3 or
 * later. See the COPYING file.
 *
 * @author Jonne Haß <me@jhass.eu>
 * @author André Théo LAURET <andrelauret@eclipse-technology.eu>
 * @copyright Jonne Haß 2016
 */

return [
    'routes' => [
        ['name' => 'page#index', 'url' => '/', 'verb' => 'GET'],
        ['name' => 'vault#files', 'url' => '/api/files', 'verb' => 'GET'],
        ['name' => 'vault#load', 'url' => '/api/vault', 'verb' => 'GET'],
        ['name' => 'vault#save', 'url' => '/api/vault', 'verb' => 'PUT'],
        ['name' => 'vault#update', 'url' => '/api/vault/save', 'verb' => 'POST'],
        ['name' => 'vault#create', 'url' => '/api/vault/create', 'verb' => 'POST'],
    ],
];
