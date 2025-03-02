<?php

declare(strict_types=1);

use App\CustomResponse;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface as Response;

/**
 * ResponseFactory creates PSR-7 compatible response objects.
 * 
 * This factory creates CustomResponse objects that extend the base Slim Response
 * with additional functionality.
 */
final class ResponseFactory implements ResponseFactoryInterface
{
    /**
     * Creates a new response with the given status code and reason phrase.
     *
     * @param int $code The HTTP status code
     * @param string $reasonPhrase The reason phrase to use with the status code
     * 
     * @return Response
     */
    public function createResponse(
        int $code = StatusCodeInterface::STATUS_OK,
        string $reasonPhrase = ''
    ): Response {
        return (new CustomResponse())->withStatus($code, $reasonPhrase);
    }
}
