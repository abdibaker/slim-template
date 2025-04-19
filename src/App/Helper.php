<?php

declare(strict_types=1);

namespace App;

use Pimple\Psr11\Container;
use Exception;
use App\CustomResponse as Response;

class Helper
{
  /**
   * Error codes for database operations.
   */
  // MySQL error codes
  private const MYSQL_ERROR_DUPLICATE = 1062;
  private const MYSQL_ERROR_FOREIGN_KEY = 1452;
  private const MYSQL_ERROR_FOREIGN_KEY_DELETE = 1451;
  private const MYSQL_ERROR_NOT_NULL = 1048;
  private const MYSQL_ERROR_UNKNOWN_COLUMN = 1054;
  private const MYSQL_ERROR_TABLE_NOT_EXISTS = 1146;
  private const MYSQL_ERROR_SYNTAX = 1064;
  private const MYSQL_ERROR_DATA_TOO_LONG = 1406;
  private const MYSQL_ERROR_DEADLOCK = 1213;
  private const MYSQL_ERROR_LOCK_WAIT_TIMEOUT = 1205;
  private const MYSQL_ERROR_UNIQUE_CONSTRAINT = 1586;
  private const MYSQL_ERROR_CONNECTION = 2002;
  private const MYSQL_ERROR_ACCESS_DENIED = 1045;

  // PostgreSQL error codes (SQLSTATE)
  private const PG_ERROR_DUPLICATE = '23505'; // unique_violation
  private const PG_ERROR_FOREIGN_KEY = '23503'; // foreign_key_violation
  private const PG_ERROR_NOT_NULL = '23502'; // not_null_violation
  private const PG_ERROR_UNDEFINED_COLUMN = '42703'; // undefined_column
  private const PG_ERROR_UNDEFINED_TABLE = '42P01'; // undefined_table
  private const PG_ERROR_SYNTAX = '42601'; // syntax_error
  private const PG_ERROR_STRING_DATA_RIGHT_TRUNCATION = '22001'; // string_data_right_truncation
  private const PG_ERROR_DEADLOCK_DETECTED = '40P01'; // deadlock_detected
  private const PG_ERROR_LOCK_NOT_AVAILABLE = '55P03'; // lock_not_available
  private const PG_ERROR_CONNECTION_FAILURE = '08006'; // connection_failure
  private const PG_ERROR_INSUFFICIENT_PRIVILEGE = '42501'; // insufficient_privilege

  /**
   * Check if the database client is MySQL
   */
  private static function isMySQL(): bool
  {
    static $isMySQL = null;

    if ($isMySQL === null) {
      $isMySQL = getenv('DB_CLIENT') === 'mysql';
    }

    return $isMySQL;
  }

  /**
   * Map PostgreSQL error codes to MySQL error codes for consistent handling
   */
  private static function mapErrorCode($errorCode): int|string
  {
    // If we're using MySQL, return the error code as is
    if (self::isMySQL()) {
      return $errorCode;
    }

    // Static mapping for better performance
    static $errorMap = null;

    if ($errorMap === null) {
      $errorMap = [
        self::PG_ERROR_DUPLICATE => self::MYSQL_ERROR_DUPLICATE,
        self::PG_ERROR_FOREIGN_KEY => self::MYSQL_ERROR_FOREIGN_KEY,
        self::PG_ERROR_NOT_NULL => self::MYSQL_ERROR_NOT_NULL,
        self::PG_ERROR_UNDEFINED_COLUMN => self::MYSQL_ERROR_UNKNOWN_COLUMN,
        self::PG_ERROR_UNDEFINED_TABLE => self::MYSQL_ERROR_TABLE_NOT_EXISTS,
        self::PG_ERROR_SYNTAX => self::MYSQL_ERROR_SYNTAX,
        self::PG_ERROR_STRING_DATA_RIGHT_TRUNCATION => self::MYSQL_ERROR_DATA_TOO_LONG,
        self::PG_ERROR_DEADLOCK_DETECTED => self::MYSQL_ERROR_DEADLOCK,
        self::PG_ERROR_LOCK_NOT_AVAILABLE => self::MYSQL_ERROR_LOCK_WAIT_TIMEOUT,
        self::PG_ERROR_CONNECTION_FAILURE => self::MYSQL_ERROR_CONNECTION,
        self::PG_ERROR_INSUFFICIENT_PRIVILEGE => self::MYSQL_ERROR_ACCESS_DENIED
      ];
    }

    return $errorMap[$errorCode] ?? $errorCode;
  }

  /**
   * Hash a password using Argon2i
   */
  public static function hashPassword(string $password): string
  {
    // Use PHP 8.4+ optimized default parameters instead of specifying our own
    return password_hash($password, PASSWORD_ARGON2ID);
  }

  /**
   * Extract and format foreign key error message
   */
  private static function getForeignKeyErrorMessage(string $errorMessage): string
  {
    if (self::isMySQL()) {
      // MySQL foreign key error handling - For foreign key constraint on insert/update
      if (preg_match(
        "/FOREIGN KEY \(`(\w+)`\) REFERENCES `(\w+)` \(`(\w+)`\)/",
        $errorMessage,
        $insertMatches
      ) && count($insertMatches) >= 4) {
        $childColumnName = $insertMatches[1];
        $parentTableName = $insertMatches[2];
        $parentColumnName = $insertMatches[3];

        return "The '{$childColumnName}' does not exist in the '{$parentTableName}' table column '{$parentColumnName}'.";
      }

      // For foreign key constraint on delete
      if (preg_match(
        "/a foreign key constraint fails \(`.*?`.`(.*?)`, CONSTRAINT `.*?` FOREIGN KEY \(`(.*?)`\) REFERENCES `(.*?)`/",
        $errorMessage,
        $deleteMatches
      ) && count($deleteMatches) >= 4) {
        $childTable = $deleteMatches[1];
        $childColumn = $deleteMatches[2];
        $parentTable = $deleteMatches[3];

        return "Cannot delete this record because it is referenced by existing records in the '{$childTable}' table through the '{$childColumn}' column.";
      }
    } else {
      // PostgreSQL foreign key error handling - For insert violations
      if (preg_match(
        "/insert or update on table \"(.*?)\".*?violates foreign key constraint.*?DETAIL:.*?Key \((.*?)\)=\((.*?)\) is not present in table \"(.*?)\"/s",
        $errorMessage,
        $pgInsertMatches
      ) && count($pgInsertMatches) >= 5) {
        $childTable = $pgInsertMatches[1];
        $childColumn = $pgInsertMatches[2];
        $value = $pgInsertMatches[3];
        $parentTable = $pgInsertMatches[4];

        return "The value '{$value}' for '{$childColumn}' does not exist in the '{$parentTable}' table.";
      }

      // For delete violations
      if (preg_match(
        "/update or delete on table \"(.*?)\".*?violates foreign key constraint.*?on table \"(.*?)\".*?DETAIL:.*?Key \((.*?)\)=\((.*?)\) is still referenced from table \"(.*?)\"/s",
        $errorMessage,
        $pgDeleteMatches
      ) && count($pgDeleteMatches) >= 6) {
        $parentTable = $pgDeleteMatches[1];
        $childTable = $pgDeleteMatches[5];

        return "Cannot delete this record from '{$parentTable}' because it is referenced by existing records in the '{$childTable}' table.";
      }
    }

    return "Foreign key constraint violation occurred, but couldn't extract specific details from the error message.";
  }

  /**
   * Extract and format duplicate entry error message
   */
  private static function getDuplicateEntryMessage(string $errorMessage): string
  {
    if (self::isMySQL()) {
      // MySQL duplicate entry error handling
      if (preg_match("/Duplicate entry '(.+?)' for key '(.+?)'/", $errorMessage, $matches) && count($matches) >= 3) {
        $value = $matches[1];
        $key = $matches[2];

        // Clean up the key name (remove table name prefix if present)
        $keyParts = explode('.', $key);
        $cleanKey = end($keyParts);

        // Use match expression (PHP 8.0+) for better performance and readability
        return match (true) {
          stripos($cleanKey, 'PRIMARY') !== false => "A record with this ID '{$value}' already exists.",
          stripos($cleanKey, 'email') !== false || stripos($cleanKey, 'mail') !== false => "The email address '{$value}' is already registered.",
          stripos($cleanKey, 'username') !== false || stripos($cleanKey, 'user_name') !== false => "The username '{$value}' is already taken.",
          stripos($cleanKey, 'phone') !== false => "The phone number '{$value}' is already registered.",
          default => "A duplicate value '{$value}' was found for '{$cleanKey}'."
        };
      }
    } else {
      // PostgreSQL duplicate entry error handling
      if (preg_match("/duplicate key value violates unique constraint \"(.*?)\".*?DETAIL:.*?Key \((.*?)\)=\((.*?)\) already exists/s", $errorMessage, $pgMatches) && count($pgMatches) >= 4) {
        $constraintName = $pgMatches[1];
        $columnName = $pgMatches[2];
        $value = $pgMatches[3];

        return match (true) {
          stripos($constraintName, 'pkey') !== false || stripos($columnName, 'id') !== false => "A record with this ID '{$value}' already exists.",
          stripos($columnName, 'email') !== false || stripos($columnName, 'mail') !== false => "The email address '{$value}' is already registered.",
          stripos($columnName, 'username') !== false || stripos($columnName, 'user_name') !== false => "The username '{$value}' is already taken.",
          stripos($columnName, 'phone') !== false => "The phone number '{$value}' is already registered.",
          default => "A duplicate value '{$value}' was found for '{$columnName}'."
        };
      }
    }

    return "A duplicate entry was detected, but couldn't extract specific details from the error message.";
  }

  /**
   * Extract and format NOT NULL error message
   */
  private static function getNotNullMessage(string $errorMessage): string
  {
    if (self::isMySQL()) {
      // MySQL NOT NULL constraint error handling
      if (preg_match("/Column '(\w+)' cannot be null/", $errorMessage, $matches) && count($matches) >= 2) {
        $columnName = $matches[1];
        return "The '{$columnName}' field is required and cannot be empty.";
      }
    } else {
      // PostgreSQL NOT NULL constraint error handling
      if (preg_match("/null value in column \"(.*?)\" violates not-null constraint/", $errorMessage, $pgMatches) && count($pgMatches) >= 2) {
        $columnName = $pgMatches[1];
        return "The '{$columnName}' field is required and cannot be empty.";
      }
    }

    return "A required field was left empty.";
  }

  /**
   * Extract and format data too long error message
   */
  private static function getDataTooLongMessage(string $errorMessage): string
  {
    if (self::isMySQL()) {
      // MySQL data too long error handling
      if (preg_match("/Data too long for column '(\w+)'/", $errorMessage, $matches) && count($matches) >= 2) {
        $columnName = $matches[1];
        return "The value for '{$columnName}' exceeds the maximum allowed length.";
      }
    } else {
      // PostgreSQL data too long error handling
      if (preg_match("/value too long for type (.*?) in column \"(.*?)\"/", $errorMessage, $pgMatches) && count($pgMatches) >= 3) {
        $dataType = $pgMatches[1];
        $columnName = $pgMatches[2];
        return "The value for '{$columnName}' exceeds the maximum allowed length for type {$dataType}.";
      }
    }

    return "One of the provided values exceeds the maximum allowed length.";
  }

  /**
   * Extract and format unknown column error message
   */
  private static function getUnknownColumnMessage(string $errorMessage): string
  {
    if (self::isMySQL()) {
      // MySQL unknown column error handling
      if (preg_match("/Unknown column '([^']+)' in/", $errorMessage, $matches) && count($matches) >= 2) {
        $columnName = $matches[1];
        return "The field '{$columnName}' does not exist in the database.";
      }
    } else {
      // PostgreSQL unknown column error handling
      if (preg_match("/column \"(.*?)\" does not exist/", $errorMessage, $pgMatches) && count($pgMatches) >= 2) {
        $columnName = $pgMatches[1];
        return "The field '{$columnName}' does not exist in the database.";
      }
    }

    return "An unknown field was referenced in the database operation.";
  }

  /**
   * Handle database exceptions and return appropriate response
   */
  public static function handleError(Exception $e, Response $response): Response
  {
    $errorCode = $e->getCode();
    $errorMessage = $e->getMessage();

    // Map PostgreSQL error codes to MySQL error codes for consistent handling
    $mappedErrorCode = self::mapErrorCode($errorCode);

    // Use match expression (PHP 8.0+) for better performance and readability
    return match ($mappedErrorCode) {
      self::MYSQL_ERROR_DUPLICATE =>
      $response->withJson(['error' => self::getDuplicateEntryMessage($errorMessage)], 409),

      self::MYSQL_ERROR_FOREIGN_KEY =>
      $response->withJson(['error' => self::getForeignKeyErrorMessage($errorMessage)], 404),

      self::MYSQL_ERROR_FOREIGN_KEY_DELETE =>
      $response->withJson(['error' => self::getForeignKeyErrorMessage($errorMessage)], 409),

      self::MYSQL_ERROR_NOT_NULL =>
      $response->withJson(['error' => self::getNotNullMessage($errorMessage)], 400),

      self::MYSQL_ERROR_UNKNOWN_COLUMN =>
      $response->withJson(['error' => self::getUnknownColumnMessage($errorMessage)], 400),

      self::MYSQL_ERROR_DATA_TOO_LONG =>
      $response->withJson(['error' => self::getDataTooLongMessage($errorMessage)], 400),

      self::MYSQL_ERROR_TABLE_NOT_EXISTS =>
      $response->withJson([
        'error' => 'Database schema issue: A required table does not exist.',
        'details' => $errorMessage
      ], 500),

      self::MYSQL_ERROR_SYNTAX =>
      $response->withJson([
        'error' => 'There was an issue with the database query syntax.',
        'details' => $errorMessage
      ], 500),

      self::MYSQL_ERROR_DEADLOCK, self::MYSQL_ERROR_LOCK_WAIT_TIMEOUT =>
      $response->withJson([
        'error' => 'The operation could not complete due to a database lock. Please try again.',
        'details' => $errorMessage
      ], 503),

      self::MYSQL_ERROR_UNIQUE_CONSTRAINT =>
      $response->withJson([
        'error' => 'The operation violates a unique constraint.',
        'details' => $errorMessage
      ], 409),

      self::MYSQL_ERROR_CONNECTION =>
      $response->withJson([
        'error' => 'Could not connect to the database. Please try again later.',
        'details' => 'Database connection issue'
      ], 503),

      self::MYSQL_ERROR_ACCESS_DENIED =>
      $response->withJson([
        'error' => 'Database access denied.',
        'details' => 'Authentication issue with the database'
      ], 500),

      default => (function () use ($response, $errorCode, $errorMessage) {
        // Log the unknown error for debugging
        error_log("Unhandled database error: Code {$errorCode}, Message: {$errorMessage}");

        // Provide a generic error message to the user
        return $response->withJson([
          'error' => 'An unexpected Server error occurred.',
          'details' => $errorMessage
        ], 500);
      })()
    };
  }
}
