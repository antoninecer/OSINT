<?php

namespace App;

class Security
{
    private static ?string $cspNonce = null;

    /**
     * Get or generate a secure CSP nonce.
     */
    public static function getNonce(): string
    {
        if (self::$cspNonce === null) {
            self::$cspNonce = base64_encode(random_bytes(16));
        }
        return self::$cspNonce;
    }

    /**
     * XSS Prevention - Escaping output
     */
    public static function escape(?string $value): string
    {
        if ($value === null) {
            return '';
        }
        return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * CSRF Prevention - Token generation
     */
    public static function generateCsrfToken(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = $token;
        return $token;
    }

    /**
     * CSRF Prevention - Token verification
     */
    public static function verifyCsrfToken(?string $token): bool
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if ($token && isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token)) {
            // Keep CSRF token active for multi-step AJAX request validation if needed, or regenerate
            return true;
        }
        return false;
    }

    /**
     * Input Validation - Czech IČO checksum validation
     */
    public static function validateIco(string $ico): bool
    {
        $ico = trim($ico);
        if (!preg_match('/^\d{8}$/', $ico)) {
            return false;
        }

        // Weighted sum calculation: weights 8, 7, 6, 5, 4, 3, 2
        $weights = [8, 7, 6, 5, 4, 3, 2];
        $sum = 0;
        for ($i = 0; $i < 7; $i++) {
            $sum += intval($ico[$i]) * $weights[$i];
        }

        $remainder = $sum % 11;
        $checkDigit = intval($ico[7]);

        if ($remainder === 0) {
            return $checkDigit === 1;
        } elseif ($remainder === 1) {
            return $checkDigit === 0;
        } else {
            return $checkDigit === (11 - $remainder);
        }
    }

    /**
     * Input Validation - Valid domain name regex
     */
    public static function validateDomain(string $domain): bool
    {
        $domain = trim($domain);
        if (strlen($domain) > 255) {
            return false;
        }
        // Validates subdomains and main domains
        return (bool)preg_match('/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/', $domain);
    }

    /**
     * Input Validation - Valid IP Address
     */
    public static function validateIp(string $ip): bool
    {
        return (bool)filter_var(trim($ip), FILTER_VALIDATE_IP);
    }

    /**
     * General sanitization of basic text input (strips control characters)
     */
    public static function sanitizeInput(string $input): string
    {
        return trim(preg_replace('/[\x00-\x1F\x7F]/', '', $input));
    }

    /**
     * Send Secure Headers including dynamic Content Security Policy (CSP)
     */
    public static function sendSecurityHeaders(): void
    {
        if (headers_sent()) {
            return;
        }

        $nonce = self::getNonce();

        // Security headers
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('X-XSS-Protection: 1; mode=block');

        // CSP (allows self assets, CDN-based Chart.js/Cytoscape.js/Bootstrap 5 via self/CDN configurations)
        // We whitelist common CDNs for Cytoscape, ChartJS and Bootstrap, but lock scripts and styles with our request nonce.
        $csp = "default-src 'self'; " .
               "script-src 'self' 'nonce-{$nonce}' https://cdn.jsdelivr.net; " .
               "style-src 'self' 'nonce-{$nonce}' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; " .
               "img-src 'self' data:; " .
               "font-src 'self' https://fonts.gstatic.com; " .
               "connect-src 'self'; " .
               "frame-src 'self';";
        
        header("Content-Security-Policy: " . $csp);
    }
}