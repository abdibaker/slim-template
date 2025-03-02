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

  private static function isMySQL(): bool
  {
    return getenv('DB_CLIENT') === 'mysql';
  }

  private static function mapErrorCode($errorCode)
  {
    // If we're using MySQL, return the error code as is
    if (self::isMySQL()) {
      return $errorCode;
    }

    // For PostgreSQL, map the SQLSTATE code to our internal error types
    switch ($errorCode) {
      case self::PG_ERROR_DUPLICATE:
        return self::MYSQL_ERROR_DUPLICATE;
      case self::PG_ERROR_FOREIGN_KEY:
        // Need to check the error message to determine if it's an insert or delete violation
        return self::MYSQL_ERROR_FOREIGN_KEY; // Default to insert violation
      case self::PG_ERROR_NOT_NULL:
        return self::MYSQL_ERROR_NOT_NULL;
      case self::PG_ERROR_UNDEFINED_COLUMN:
        return self::MYSQL_ERROR_UNKNOWN_COLUMN;
      case self::PG_ERROR_UNDEFINED_TABLE:
        return self::MYSQL_ERROR_TABLE_NOT_EXISTS;
      case self::PG_ERROR_SYNTAX:
        return self::MYSQL_ERROR_SYNTAX;
      case self::PG_ERROR_STRING_DATA_RIGHT_TRUNCATION:
        return self::MYSQL_ERROR_DATA_TOO_LONG;
      case self::PG_ERROR_DEADLOCK_DETECTED:
        return self::MYSQL_ERROR_DEADLOCK;
      case self::PG_ERROR_LOCK_NOT_AVAILABLE:
        return self::MYSQL_ERROR_LOCK_WAIT_TIMEOUT;
      case self::PG_ERROR_CONNECTION_FAILURE:
        return self::MYSQL_ERROR_CONNECTION;
      case self::PG_ERROR_INSUFFICIENT_PRIVILEGE:
        return self::MYSQL_ERROR_ACCESS_DENIED;
      default:
        return $errorCode;
    }
  }

  public static function hashPassword(string $password): string
  {
    $options = [
      'memory_cost' => 2048,
      'time_cost' => 4,
      'threads' => 3
    ];

    return password_hash($password, PASSWORD_ARGON2I, $options);
  }

  public static function getForeignKeyErrorMessage(string $errorMessage): string
  {
    if (self::isMySQL()) {
      // MySQL foreign key error handling

      // For foreign key constraint on insert/update
      $insertMatches = [];
      if (preg_match(
        "/FOREIGN KEY \(`(\w+)`\) REFERENCES `(\w+)` \(`(\w+)`\)/",
        $errorMessage,
        $insertMatches
      )) {
        if (count($insertMatches) >= 4) {
          $childColumnName = $insertMatches[1];
          $parentTableName = $insertMatches[2];
          $parentColumnName = $insertMatches[3];

          return "The '{$childColumnName}' does not exist in the '{$parentTableName}' table column '{$parentColumnName}'.";
        }
      }

      // For foreign key constraint on delete
      $deleteMatches = [];
      if (preg_match(
        "/a foreign key constraint fails \(`.*?`.`(.*?)`, CONSTRAINT `.*?` FOREIGN KEY \(`(.*?)`\) REFERENCES `(.*?)`/",
        $errorMessage,
        $deleteMatches
      )) {
        if (count($deleteMatches) >= 4) {
          $childTable = $deleteMatches[1];
          $childColumn = $deleteMatches[2];
          $parentTable = $deleteMatches[3];

          return "Cannot delete this record because it is referenced by existing records in the '{$childTable}' table through the '{$childColumn}' column.";
        }
      }
    } else {
      // PostgreSQL foreign key error handling

      // For insert violations (value not present in parent table)
      $pgInsertMatches = [];
      if (preg_match(
        "/insert or update on table \"(.*?)\".*?violates foreign key constraint.*?DETAIL:.*?Key \((.*?)\)=\((.*?)\) is not present in table \"(.*?)\"/s",
        $errorMessage,
        $pgInsertMatches
      )) {
        if (count($pgInsertMatches) >= 5) {
          $childTable = $pgInsertMatches[1];
          $childColumn = $pgInsertMatches[2];
          $value = $pgInsertMatches[3];
          $parentTable = $pgInsertMatches[4];

          return "The value '{$value}' for '{$childColumn}' does not exist in the '{$parentTable}' table.";
        }
      }

      // For delete violations (referenced by child records)
      $pgDeleteMatches = [];
      if (preg_match(
        "/update or delete on table \"(.*?)\".*?violates foreign key constraint.*?on table \"(.*?)\".*?DETAIL:.*?Key \((.*?)\)=\((.*?)\) is still referenced from table \"(.*?)\"/s",
        $errorMessage,
        $pgDeleteMatches
      )) {
        if (count($pgDeleteMatches) >= 6) {
          $parentTable = $pgDeleteMatches[1];
          $constraintTable = $pgDeleteMatches[2];
          $parentColumn = $pgDeleteMatches[3];
          $value = $pgDeleteMatches[4];
          $childTable = $pgDeleteMatches[5];

          return "Cannot delete this record from '{$parentTable}' because it is referenced by existing records in the '{$childTable}' table.";
        }
      }
    }

    return "Foreign key constraint violation occurred, but couldn't extract specific details from the error message.";
  }

  public static function getDuplicateEntryMessage(string $errorMessage): string
  {
    if (self::isMySQL()) {
      // MySQL duplicate entry error handling
      $matches = [];
      if (preg_match("/Duplicate entry '(.+?)' for key '(.+?)'/", $errorMessage, $matches)) {
        if (count($matches) >= 3) {
          $value = $matches[1];
          $key = $matches[2];

          // Clean up the key name (remove table name prefix if present)
          $keyParts = explode('.', $key);
          $cleanKey = end($keyParts);

          // Handle common key types
          if (stripos($cleanKey, 'PRIMARY') !== false) {
            return "A record with this ID '{$value}' already exists.";
          } elseif (stripos($cleanKey, 'email') !== false || stripos($cleanKey, 'mail') !== false) {
            return "The email address '{$value}' is already registered.";
          } elseif (stripos($cleanKey, 'username') !== false || stripos($cleanKey, 'user_name') !== false) {
            return "The username '{$value}' is already taken.";
          } elseif (stripos($cleanKey, 'phone') !== false) {
            return "The phone number '{$value}' is already registered.";
          } else {
            return "A duplicate value '{$value}' was found for '{$cleanKey}'.";
          }
        }
      }
    } else {
      // PostgreSQL duplicate entry error handling
      $pgMatches = [];
      if (preg_match("/duplicate key value violates unique constraint \"(.*?)\".*?DETAIL:.*?Key \((.*?)\)=\((.*?)\) already exists/s", $errorMessage, $pgMatches)) {
        if (count($pgMatches) >= 4) {
          $constraintName = $pgMatches[1];
          $columnName = $pgMatches[2];
          $value = $pgMatches[3];

          // Handle common column types
          if (stripos($constraintName, 'pkey') !== false || stripos($columnName, 'id') !== false) {
            return "A record with this ID '{$value}' already exists.";
          } elseif (stripos($columnName, 'email') !== false || stripos($columnName, 'mail') !== false) {
            return "The email address '{$value}' is already registered.";
          } elseif (stripos($columnName, 'username') !== false || stripos($columnName, 'user_name') !== false) {
            return "The username '{$value}' is already taken.";
          } elseif (stripos($columnName, 'phone') !== false) {
            return "The phone number '{$value}' is already registered.";
          } else {
            return "A duplicate value '{$value}' was found for '{$columnName}'.";
          }
        }
      }
    }

    return "A duplicate entry was detected, but couldn't extract specific details from the error message.";
  }

  public static function getNotNullMessage(string $errorMessage): string
  {
    if (self::isMySQL()) {
      // MySQL NOT NULL constraint error handling
      $matches = [];
      if (preg_match("/Column '(\w+)' cannot be null/", $errorMessage, $matches)) {
        if (count($matches) >= 2) {
          $columnName = $matches[1];
          return "The '{$columnName}' field is required and cannot be empty.";
        }
      }
    } else {
      // PostgreSQL NOT NULL constraint error handling
      $pgMatches = [];
      if (preg_match("/null value in column \"(.*?)\" violates not-null constraint/", $errorMessage, $pgMatches)) {
        if (count($pgMatches) >= 2) {
          $columnName = $pgMatches[1];
          return "The '{$columnName}' field is required and cannot be empty.";
        }
      }
    }

    return "A required field was left empty.";
  }

  public static function getDataTooLongMessage(string $errorMessage): string
  {
    if (self::isMySQL()) {
      // MySQL data too long error handling
      $matches = [];
      if (preg_match("/Data too long for column '(\w+)'/", $errorMessage, $matches)) {
        if (count($matches) >= 2) {
          $columnName = $matches[1];
          return "The value for '{$columnName}' exceeds the maximum allowed length.";
        }
      }
    } else {
      // PostgreSQL data too long error handling
      $pgMatches = [];
      if (preg_match("/value too long for type (.*?) in column \"(.*?)\"/", $errorMessage, $pgMatches)) {
        if (count($pgMatches) >= 3) {
          $dataType = $pgMatches[1];
          $columnName = $pgMatches[2];
          return "The value for '{$columnName}' exceeds the maximum allowed length for type {$dataType}.";
        }
      }
    }

    return "One of the provided values exceeds the maximum allowed length.";
  }

  public static function getUnknownColumnMessage(string $errorMessage): string
  {
    if (self::isMySQL()) {
      // MySQL unknown column error handling
      $matches = [];
      if (preg_match("/Unknown column '([^']+)' in/", $errorMessage, $matches)) {
        if (count($matches) >= 2) {
          $columnName = $matches[1];
          return "The field '{$columnName}' does not exist in the database.";
        }
      }
    } else {
      // PostgreSQL unknown column error handling
      $pgMatches = [];
      if (preg_match("/column \"(.*?)\" does not exist/", $errorMessage, $pgMatches)) {
        if (count($pgMatches) >= 2) {
          $columnName = $pgMatches[1];
          return "The field '{$columnName}' does not exist in the database.";
        }
      }
    }

    return "An unknown field was referenced in the database operation.";
  }

  public static function handleDatabaseError(Exception $e, Response $response): Response
  {
    $errorCode = $e->getCode();
    $errorMessage = $e->getMessage();

    // Map PostgreSQL error codes to MySQL error codes for consistent handling
    $mappedErrorCode = self::mapErrorCode($errorCode);

    switch ($mappedErrorCode) {
      case self::MYSQL_ERROR_DUPLICATE:
        $error = self::getDuplicateEntryMessage($errorMessage);
        return $response->withJson(['error' => $error], 409);

      case self::MYSQL_ERROR_FOREIGN_KEY:
        $error = self::getForeignKeyErrorMessage($errorMessage);
        return $response->withJson(['error' => $error], 404);

      case self::MYSQL_ERROR_FOREIGN_KEY_DELETE:
        $error = self::getForeignKeyErrorMessage($errorMessage);
        return $response->withJson(['error' => $error], 409);

      case self::MYSQL_ERROR_NOT_NULL:
        $error = self::getNotNullMessage($errorMessage);
        return $response->withJson(['error' => $error], 400);

      case self::MYSQL_ERROR_UNKNOWN_COLUMN:
        $error = self::getUnknownColumnMessage($errorMessage);
        return $response->withJson(['error' => $error], 400);

      case self::MYSQL_ERROR_DATA_TOO_LONG:
        $error = self::getDataTooLongMessage($errorMessage);
        return $response->withJson(['error' => $error], 400);

      case self::MYSQL_ERROR_TABLE_NOT_EXISTS:
        return $response->withJson([
          'error' => 'Database schema issue: A required table does not exist.',
          'details' => $errorMessage
        ], 500);

      case self::MYSQL_ERROR_SYNTAX:
        return $response->withJson([
          'error' => 'There was an issue with the database query syntax.',
          'details' => $errorMessage
        ], 500);

      case self::MYSQL_ERROR_DEADLOCK:
        return $response->withJson([
          'error' => 'The operation could not complete due to a database deadlock. Please try again.',
          'details' => $errorMessage
        ], 503);

      case self::MYSQL_ERROR_LOCK_WAIT_TIMEOUT:
        return $response->withJson([
          'error' => 'The operation timed out while waiting for a database lock. Please try again.',
          'details' => $errorMessage
        ], 503);

      case self::MYSQL_ERROR_UNIQUE_CONSTRAINT:
        return $response->withJson([
          'error' => 'The operation violates a unique constraint.',
          'details' => $errorMessage
        ], 409);

      case self::MYSQL_ERROR_CONNECTION:
        return $response->withJson([
          'error' => 'Could not connect to the database. Please try again later.',
          'details' => 'Database connection issue'
        ], 503);

      case self::MYSQL_ERROR_ACCESS_DENIED:
        return $response->withJson([
          'error' => 'Database access denied.',
          'details' => 'Authentication issue with the database'
        ], 500);

      default:
        // Log the unknown error for debugging
        error_log("Unhandled database error: Code {$errorCode}, Message: {$errorMessage}");

        // Provide a generic error message to the user
        return $response->withJson([
          'error' => 'An unexpected database error occurred.',
          'details' => $errorMessage
        ], 500);
    }
  }
}
