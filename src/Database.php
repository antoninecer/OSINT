<?php

namespace App;

use PDO;
use PDOException;
use Exception;

class Database
{
    private static ?self $instance = null;
    private PDO $pdo;

    private function __construct()
    {
        // Load configuration from absolute path relative to this file
        $config = require __DIR__ . '/../config/config.php';
        
        $dsn = "mysql:host={$config['database']['host']};dbname={$config['database']['dbname']};charset={$config['database']['charset']}";
        
        $options = $config['database']['options'] ?? [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];

        try {
            $this->pdo = new PDO($dsn, $config['database']['username'], $config['database']['password'], $options);
        } catch (PDOException $e) {
            // Log database error and throw a generic message (to prevent password leakage in stack traces)
            error_log("Database Connection Error: " . $e->getMessage());
            throw new Exception('A database connection error occurred. Please try again later.');
        }
    }

    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getConnection(): PDO
    {
        return $this->pdo;
    }

    public function run(string $sql, array $args = []): \PDOStatement
    {
        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($args);
            return $stmt;
        } catch (PDOException $e) {
            error_log("Database Query Error: " . $e->getMessage() . " | SQL: " . $sql);
            throw new Exception('A database query error occurred.');
        }
    }

    public function fetch(string $sql, array $args = []): ?array
    {
        $stmt = $this->run($sql, $args);
        $result = $stmt->fetch();
        return $result ? $result : null;
    }

    public function fetchAll(string $sql, array $args = []): array
    {
        $stmt = $this->run($sql, $args);
        return $stmt->fetchAll();
    }

    public function insert(string $table, array $data): \PDOStatement
    {
        // Prevent SQL injection via table name (whitelist or strip illegal characters)
        $cleanTable = preg_replace('/[^a-zA-Z0-9_]/', '', $table);
        
        $columns = [];
        $placeholders = [];
        
        foreach (array_keys($data) as $column) {
            $cleanColumn = preg_replace('/[^a-zA-Z0-9_]/', '', $column);
            $columns[] = "`$cleanColumn`";
            $placeholders[] = ":$cleanColumn";
        }
        
        $columnsStr = implode(', ', $columns);
        $placeholdersStr = implode(', ', $placeholders);
        
        $sql = "INSERT INTO `$cleanTable` ($columnsStr) VALUES ($placeholdersStr)";
        return $this->run($sql, $data);
    }

    public function lastInsertId(): string
    {
        return $this->pdo->lastInsertId();
    }
}