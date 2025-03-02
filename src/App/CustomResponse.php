<?php

declare(strict_types=1);

namespace App;

use Slim\Psr7\Response as ResponseBase;

/**
 * CustomResponse extends the base Slim Response with additional functionality.
 * 
 * This class provides methods for creating JSON responses with proper headers.
 */
final class CustomResponse extends ResponseBase
{
    /**
     * Creates a JSON response with the provided data.
     *
     * @param mixed $data The data to encode as JSON
     * @param int $status The HTTP status code
     * @param int $encodingOptions JSON encoding options
     * 
     * @throws \RuntimeException If JSON encoding fails
     * 
     * @return self
     */
    public function withJson(
        mixed $data,
        int $status = 200,
        int $encodingOptions = 0
    ): self {
        // Encode the data as JSON
        $json = json_encode($data, $encodingOptions);

        // Check if JSON encoding was successful
        if ($json === false) {
            throw new \RuntimeException(
                json_last_error_msg(),
                json_last_error()
            );
        }

        // Write the JSON to the response body
        $this->getBody()->write($json);

        // Set the Content-Type header and status code
        return $this
            ->withHeader('Content-Type', 'application/json;charset=utf-8')
            ->withStatus($status);
    }
}