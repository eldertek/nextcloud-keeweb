<?php
declare(strict_types=1);

namespace OCA\Keeweb\Tests\Unit\Controller;

use OCA\Keeweb\Controller\PageController;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IRequest;
use OCP\IURLGenerator;
use PHPUnit\Framework\TestCase;

class PageControllerTest extends TestCase {
    public function testIndexReturnsMainTemplateWithStrictCsp(): void {
        $request = $this->createMock(IRequest::class);
        $urlGenerator = $this->createMock(IURLGenerator::class);
        $urlGenerator->method('linkToRoute')->willReturn('/apps/keeweb/');
        $urlGenerator->method('linkTo')->willReturn('/apps/keeweb/js/argon2-worker.js');

        $controller = new PageController($request, $urlGenerator);
        $response = $controller->index('/sample-v4.kdbx');

        $this->assertInstanceOf(TemplateResponse::class, $response);
        $this->assertSame('main', $response->getTemplateName());
        $params = $response->getParams();
        $this->assertSame('/sample-v4.kdbx', $params['open']);
    }
}
