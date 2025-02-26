<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\App;

return static function (App $app) {

  $authMiddleware = function (Request $request, RequestHandler $handler): Response {
    $jwt = $request->getHeaderLine('Authorization');

    if (empty($jwt)) {
      throw new Exception('JWT Token required.', 400);
    }

    try {
      $key = new Key('7w8&^7af9*!o%j#)b$#k*p2w#q9@s1z&3n1!&y^vq36znm7!%h', 'HS256');
      $decoded = JWT::decode($jwt, $key);
    } catch (Exception) {
      throw new Exception('Forbidden: you are not authorized.', 403);
    }

    $parsedBody = $request->getParsedBody() ?: [];
    $parsedBody['decoded'] = $decoded;
    $request = $request->withParsedBody($parsedBody);

    return $handler->handle($request);
  };

  // --------------- Home Routes ---------------- //
  $app->get('/', "App\Controller\Home:home");
  $app->get('/status', "App\Controller\Home:home");

  return $app;
};
