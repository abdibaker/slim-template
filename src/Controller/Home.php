<?php

declare(strict_types=1);

namespace App\Controller;

use App\CustomResponse as Response;
use Pimple\Psr11\Container;
use Psr\Http\Message\ServerRequestInterface as Request;
use Exception;

final class Home
{
  private const API_NAME = 'slim4-api';
  private const API_VERSION = '0.41.0';

  private Container $container;

  public function __construct(Container $container)
  {
    $this->container = $container;
  }

  public function home(Request $request, Response $response): Response
  {
    $dbStatus = 'ERROR';

    try {
      $db = $this->container->get('db');
      $dbStatus = 'OK';
    } catch (Exception $e) {
      $dbStatus = 'ERROR: ' . $e->getMessage();
    }

    $status = [
      'status'    => [
        'database' => $dbStatus,
      ],
      'api'       => self::API_NAME,
      'version'   => self::API_VERSION,
      'timestamp' => time(),
    ];

    // Check if the request wants JSON format
    $acceptHeader = $request->getHeaderLine('Accept');
    if (strpos($acceptHeader, 'application/json') !== false) {
      return $response->withJson($status);
    }

    // Otherwise render HTML template
    $templatePath = __DIR__ . '/../templates/home.html';
    $template = file_get_contents($templatePath);

    // Simple template variable replacement
    $replacements = [
      '{{api}}' => self::API_NAME,
      '{{version}}' => self::API_VERSION,
      '{{db_status}}' => $dbStatus,
      '{{db_status_class}}' => strpos($dbStatus, 'ERROR') !== false ? 'status-error' : 'status-ok',
      '{{timestamp}}' => date('Y-m-d H:i:s', time()),
      '{{current_year}}' => date('Y')
    ];

    $html = str_replace(array_keys($replacements), array_values($replacements), $template);

    $response->getBody()->write($html);
    return $response->withHeader('Content-Type', 'text/html');
  }
}
