<?php
return [
    'database' => [
        'host' => 'localhost',
        'dbname' => 'rightdone_intelligence',
        'username' => 'root',
        'password' => '',
        'charset' => 'utf8mb4',
        'options' => [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ],
    ],
    'redis' => [
        'host' => '127.0.0.1',
        'port' => 6379,
        'scheme' => 'tcp',
        'database' => 0,
    ],
    'session_security' => [
        'name' => 'RD_INTELLIGENCE_SESS',
        'lifetime' => 1440,
        'path' => '/',
        'domain' => '',
        'secure' => false, // Set to true in production with HTTPS
        'httponly' => true,
        'samesite' => 'Strict',
    ],
    'security' => [
        'encryption_key' => bin2hex(random_bytes(32)), // fallback key generator
        'allowed_domains' => [
            'localhost',
        ],
        'rate_limits' => [
            'requests_per_minute' => 60,
        ],
    ],
    'pricing_levels' => [
        'free' => [
            'ares_basic',
            'dns_basic',
        ],
        'surcharge1' => [
            'ares_basic',
            'dns_basic',
            'dns_full',
            'whois',
            'web_tech',
            'leaks_summary',
        ],
        'surcharge2' => [
            'ares_basic',
            'dns_basic',
            'dns_full',
            'whois',
            'web_tech',
            'leaks_summary',
            'company_relations',
            'change_history',
            'leaks_details',
            'timeline',
        ],
    ],
];
