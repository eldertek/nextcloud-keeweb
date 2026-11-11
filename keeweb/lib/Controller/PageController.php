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

namespace OCA\Keeweb\Controller;

use OCA\Keeweb\AppInfo\Application;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\ContentSecurityPolicy;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\Util;

class PageController extends Controller {
    public function __construct(
        IRequest $request,
        private IURLGenerator $urlGenerator,
    ) {
        parent::__construct(Application::APP_ID, $request);
    }

    #[NoAdminRequired]
    #[NoCSRFRequired]
    public function index(?string $open = null): TemplateResponse {
        Util::addScript(Application::APP_ID, 'main');
        Util::addStyle(Application::APP_ID, 'style');

        $normalizedOpen = '';
        if (is_string($open) && $open !== '' && !str_contains($open, "\0")) {
            $normalizedOpen = '/' . ltrim(trim($open), '/');
        }

        $params = [
            'open' => $normalizedOpen,
            'apiBase' => $this->urlGenerator->linkToRoute('keeweb.page.index'),
            'workerUrl' => $this->urlGenerator->linkTo(Application::APP_ID, 'js/argon2-worker.js'),
        ];

        $response = new TemplateResponse(Application::APP_ID, 'main', $params);
        $response->setContentSecurityPolicy($this->buildContentSecurityPolicy());
        return $response;
    }

    private function buildContentSecurityPolicy(): ContentSecurityPolicy {
        $csp = new ContentSecurityPolicy();
        $csp->allowEvalWasm(true);
        $csp->addAllowedWorkerSrcDomain("'self'");
        return $csp;
    }
}
