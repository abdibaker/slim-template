<?php

declare(strict_types=1);

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

return function (
    ServerRequestInterface $request,
    Throwable $exception,
    bool $displayErrorDetails,
    bool $logErrors,
    bool $logErrorDetails,
    ?LoggerInterface $logger = null
) use ($app): Response {
    // Determine appropriate status code
    $statusCode = 500;
    if (
        is_int($exception->getCode()) &&
        $exception->getCode() >= 400 &&
        $exception->getCode() <= 599
    ) {
        $statusCode = $exception->getCode();
    }

    // Get exception details
    $className = new \ReflectionClass($exception::class);
    $exceptionType = $className->getShortName();

    // Log the error if enabled
    if ($logErrors && $logger) {
        $context = [
            'exception' => $exception,
            'request_method' => $request->getMethod(),
            'request_path' => (string)$request->getUri(),
        ];

        if ($logErrorDetails) {
            $context['trace'] = $exception->getTraceAsString();
        }

        $logger->error($exception->getMessage(), $context);
    }

    // Build response according to RFC 7807 Problem Details
    $data = [
        'type' => 'https://httpstatuses.com/' . $statusCode,
        'title' => $exceptionType,
        'status' => $statusCode,
        'detail' => $exception->getMessage(),
    ];

    // Add instance (URI) from the request
    $data['instance'] = (string)$request->getUri();

    // Include stack trace if display details is enabled
    if ($displayErrorDetails) {
        $data['trace'] = explode("\n", $exception->getTraceAsString());
        $data['file'] = $exception->getFile();
        $data['line'] = $exception->getLine();
    }

    // Create and return the response
    $payload = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    $response = $app->getResponseFactory()->createResponse();
    $response->getBody()->write($payload);

    return $response
        ->withStatus($statusCode)
        ->withHeader('Content-Type', 'application/problem+json');
};
