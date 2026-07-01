<?php

namespace App;

class SessionManager
{
    public static function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        // Avoid session errors if output started
        if (headers_sent()) {
            return;
        }

        // Load config
        $configData = require __DIR__ . '/../config/config.php';
        $config = $configData['session_security'];

        // Secure cookie settings
        session_set_cookie_params([
            'lifetime' => $config['lifetime'] ?? 1440,
            'path' => $config['path'] ?? '/',
            'domain' => $config['domain'] ?? '',
            'secure' => $config['secure'] ?? true,
            'httponly' => $config['httponly'] ?? true,
            'samesite' => $config['samesite'] ?? 'Strict'
        ]);

        session_name($config['name'] ?? 'RD_INTELLIGENCE_SESS');
        
        if (!session_start()) {
            error_log("Failed to start session.");
            return;
        }

        $clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

        // Check for session hijacking
        if (isset($_SESSION['client_ip']) && $_SESSION['client_ip'] !== $clientIp ||
            isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== $userAgent) {
            // Hijack suspect: destroy session completely and start fresh
            $_SESSION = [];
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(
                    session_name(),
                    '',
                    time() - 42000,
                    $params["path"],
                    $params["domain"],
                    $params["secure"],
                    $params["httponly"]
                );
            }
            session_destroy();
            session_start();
            session_regenerate_id(true);
        }

        // Periodic ID regeneration to prevent session fixation
        $lastRegen = $_SESSION['last_regeneration'] ?? 0;
        if (time() - $lastRegen > 600) { // regenerate ID every 10 minutes
            session_regenerate_id(true);
            $_SESSION['last_regeneration'] = time();
        }

        $_SESSION['client_ip'] = $clientIp;
        $_SESSION['user_agent'] = $userAgent;
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        self::start();
        return $_SESSION[$key] ?? $default;
    }

    public static function set(string $key, mixed $value): void
    {
        self::start();
        $_SESSION[$key] = $value;
    }

    public static function has(string $key): bool
    {
        self::start();
        return isset($_SESSION[$key]);
    }

    public static function remove(string $key): void
    {
        self::start();
        unset($_SESSION[$key]);
    }

    public static function destroy(): void
    {
        self::start();
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params["path"],
                $params["domain"],
                $params["secure"],
                $params["httponly"]
            );
        }
        session_destroy();
    }
}