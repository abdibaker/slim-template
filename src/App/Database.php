<?php

declare(strict_types=1);

use Doctrine\DBAL\DriverManager;

$container['db'] = static function () {
    $connectionParams = [
        'dbname'   => getenv('DB_NAME'),
        'user'     => getenv('DB_USER'),
        'password' => getenv('DB_PASS'),
        'host'     => getenv('DB_HOST'),
        'driver'   => getenv('DB_CLIENT') === 'mysql' ? 'pdo_mysql' : 'pdo_pgsql',
    ];
    $conn = DriverManager::getConnection($connectionParams);

    return $conn;
};
