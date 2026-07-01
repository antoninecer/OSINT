<?php

namespace App\Analyzer;

use App\Database;
use App\Security;
use Exception;

class InfrastructureAnalyzer
{
    private Database $database;

    public function __construct(Database $database)
    {
        $this->database = $database;
    }

    public function analyze(string $target): array
    {
        $target = trim($target);
        $type = Security::validateIp($target) ? 'IP' : 'DOMAIN';

        if ($type === 'DOMAIN' && !Security::validateDomain($target)) {
            throw new Exception('Neplatný formát domény.');
        }

        $data = [
            'target' => $target,
            'type' => $type,
            'dns' => [],
            'ssl' => null,
            'whois' => '',
            'web_tech' => [],
            'risks' => []
        ];

        if ($type === 'DOMAIN') {
            // DNS resolution
            $data['dns'] = $this->resolveDns($target);

            // SSL Certificate checks
            $data['ssl'] = $this->checkSsl($target);

            // WHOIS lookup
            $data['whois'] = $this->queryWhois($target);

            // Web technologies & Security headers
            $data['web_tech'] = $this->detectWebTechnologies($target);
        } else {
            // IP resolution
            $data['dns'] = [
                'ptr' => gethostbyaddr($target) ?: 'Unknown'
            ];
            $data['whois'] = $this->queryWhoisIp($target);
        }

        // Evaluate risks found in data
        $data['risks'] = $this->evaluateRisks($data);

        return $data;
    }

    private function resolveDns(string $domain): array
    {
        $records = [];
        $types = [
            'A' => DNS_A,
            'AAAA' => DNS_AAAA,
            'MX' => DNS_MX,
            'NS' => DNS_NS,
            'TXT' => DNS_TXT
        ];

        foreach ($types as $name => $dnsType) {
            $res = @dns_get_record($domain, $dnsType);
            if (is_array($res)) {
                foreach ($res as $record) {
                    $records[$name][] = $record;
                }
            }
        }
        return $records;
    }

    private function checkSsl(string $domain): ?array
    {
        $g = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "verify_peer" => false,
                "verify_peer_name" => false
            ]
        ]);
        
        $r = @stream_socket_client(
            "ssl://{$domain}:443",
            $errno,
            $errstr,
            2.0,
            STREAM_CLIENT_CONNECT,
            $g
        );
        
        if (!$r) {
            return null;
        }

        $cont = stream_context_get_params($r);
        if (empty($cont["options"]["ssl"]["peer_certificate"])) {
            return null;
        }

        $cert = $cont["options"]["ssl"]["peer_certificate"];
        $info = openssl_x509_parse($cert);

        if (!$info) {
            return null;
        }

        return [
            'subject' => $info['subject']['CN'] ?? $domain,
            'issuer' => $info['issuer']['O'] ?? ($info['issuer']['CN'] ?? 'Unknown'),
            'valid_from' => date('Y-m-d H:i:s', $info['validFrom_time_t']),
            'valid_to' => date('Y-m-d H:i:s', $info['validTo_time_t']),
            'expired' => ($info['validTo_time_t'] < time()),
            'expiring_soon' => ($info['validTo_time_t'] - time() < 30 * 86400) // 30 days
        ];
    }

    private function queryWhois(string $domain): string
    {
        // Simple TCP Socket WHOIS client to query IANA and TLD WHOIS servers
        // Prevents calling shell command 'whois' for bulletproof security.
        $tld = pathinfo($domain, PATHINFO_EXTENSION);
        $whoisServer = 'whois.iana.org';

        // Czech domain (.cz) WHOIS server
        if ($tld === 'cz') {
            $whoisServer = 'whois.nic.cz';
        }

        try {
            $fp = @fsockopen($whoisServer, 43, $errno, $errstr, 2.0);
            if (!$fp) {
                return "WHOIS server {$whoisServer} nedostupný.";
            }
            
            $query = $domain . "\r\n";
            fwrite($fp, $query);
            
            $response = '';
            while (!feof($fp)) {
                $response .= fgets($fp, 128);
            }
            fclose($fp);
            return $response;
        } catch (Exception $e) {
            return "WHOIS dotaz selhal: " . $e->getMessage();
        }
    }

    private function queryWhoisIp(string $ip): string
    {
        // Query RIPE WHOIS for IP info
        try {
            $fp = @fsockopen('whois.ripe.net', 43, $errno, $errstr, 2.0);
            if (!$fp) {
                return "RIPE WHOIS server nedostupný.";
            }
            fwrite($fp, $ip . "\r\n");
            $response = '';
            while (!feof($fp)) {
                $response .= fgets($fp, 128);
            }
            fclose($fp);
            return $response;
        } catch (Exception $e) {
            return "WHOIS dotaz na IP selhal.";
        }
    }

    private function detectWebTechnologies(string $domain): array
    {
        // Query homepage via native curl or file_get_contents to fetch headers
        $url = "https://{$domain}";
        
        $opts = [
            "http" => [
                "method" => "GET",
                "header" => "User-Agent: RightDoneIntelligence/1.0\r\nConnection: close\r\n",
                "timeout" => 3.0,
                "follow_location" => 0
            ],
            "ssl" => [
                "verify_peer" => false,
                "verify_peer_name" => false
            ]
        ];

        $context = stream_context_create($opts);
        $headersRaw = @get_headers($url, 1, $context);
        
        if (!$headersRaw) {
            // Retry with http
            $url = "http://{$domain}";
            $headersRaw = @get_headers($url, 1, $context);
        }

        if (!$headersRaw) {
            return [
                'server' => 'Neznámý',
                'powered_by' => 'Neznámý',
                'security_headers_missing' => ['CSP', 'HSTS', 'X-Frame-Options']
            ];
        }

        // Normalize header keys to lowercase
        $headers = [];
        foreach ($headersRaw as $key => $value) {
            if (is_string($key)) {
                $headers[strtolower($key)] = is_array($value) ? end($value) : $value;
            }
        }

        $missingHeaders = [];
        if (!isset($headers['content-security-policy'])) $missingHeaders[] = 'CSP';
        if (!isset($headers['strict-transport-security'])) $missingHeaders[] = 'HSTS';
        if (!isset($headers['x-frame-options'])) $missingHeaders[] = 'X-Frame-Options';
        if (!isset($headers['x-content-type-options'])) $missingHeaders[] = 'X-Content-Type-Options';

        return [
            'server' => $headers['server'] ?? 'Neznámý',
            'powered_by' => $headers['x-powered-by'] ?? 'Neznámý',
            'security_headers_missing' => $missingHeaders
        ];
    }

    private function evaluateRisks(array $data): array
    {
        $risks = [];

        // Check SSL
        if ($data['type'] === 'DOMAIN') {
            if ($data['ssl'] === null) {
                $risks[] = [
                    'risk_level' => 'high',
                    'description' => 'Chybí SSL certifikát nebo port 443 není dostupný.',
                    'details' => 'Komunikace s webem není šifrovaná.'
                ];
            } else {
                if ($data['ssl']['expired']) {
                    $risks[] = [
                        'risk_level' => 'critical',
                        'description' => 'SSL certifikát vypršel!',
                        'details' => "Vypršel dne: {$data['ssl']['valid_to']}."
                    ];
                } elseif ($data['ssl']['expiring_soon']) {
                    $risks[] = [
                        'risk_level' => 'medium',
                        'description' => 'SSL certifikát brzy vyprší.',
                        'details' => "Platnost do: {$data['ssl']['valid_to']}."
                    ];
                }
            }

            // Check DNS for SPF / DMARC
            $hasSpf = false;
            $hasDmarc = false;

            if (isset($data['dns']['TXT'])) {
                foreach ($data['dns']['TXT'] as $record) {
                    $txt = $record['txt'] ?? '';
                    if (str_contains($txt, 'v=spf1')) $hasSpf = true;
                    if (str_contains($txt, 'v=DMARC1')) $hasDmarc = true;
                }
            }

            if (!$hasSpf) {
                $risks[] = [
                    'risk_level' => 'low',
                    'description' => 'Chybí SPF záznam v DNS.',
                    'details' => 'Zvyšuje riziko podvržení e-mailů odeslaných z této domény.'
                ];
            }

            if (!$hasDmarc) {
                $risks[] = [
                    'risk_level' => 'low',
                    'description' => 'Chybí DMARC záznam v DNS.',
                    'details' => 'Chybí definice politik pro kontrolu spamu a phishingu.'
                ];
            }

            // Check security headers
            $missing = $data['web_tech']['security_headers_missing'] ?? [];
            if (in_array('CSP', $missing)) {
                $risks[] = [
                    'risk_level' => 'medium',
                    'description' => 'Chybí Content Security Policy (CSP) hlavička.',
                    'details' => 'Ochrana proti XSS útokům a vkládání škodlivých kódů je oslabena.'
                ];
            }
            if (in_array('HSTS', $missing)) {
                $risks[] = [
                    'risk_level' => 'low',
                    'description' => 'Chybí HTTP Strict Transport Security (HSTS).',
                    'details' => 'Uživatelé se mohou připojovat přes nešifrované HTTP.'
                ];
            }
        }

        return $risks;
    }

    public function saveReportData(int $reportId, array $data): void
    {
        $pdo = $this->database->getConnection();
        $pdo->beginTransaction();

        try {
            $target = $data['target'];
            
            // 1. Create Target Entity (Domain or IP)
            $type = ($data['type'] === 'DOMAIN') ? 'domain' : 'ip';
            
            $existingTarget = $this->database->fetch(
                "SELECT id FROM entities WHERE type = ? AND value = ?",
                [$type, $target]
            );

            if ($existingTarget) {
                $targetId = $existingTarget['id'];
                // Update payload
                $this->database->run(
                    "UPDATE entities SET payload = ? WHERE id = ?",
                    [json_encode($data), $targetId]
                );
            } else {
                $this->database->insert('entities', [
                    'type' => $type,
                    'value' => $target,
                    'risk_level' => 'informational',
                    'description' => "Analyzovaná cílová infrastruktura: {$target}.",
                    'payload' => json_encode($data)
                ]);
                $targetId = $this->database->lastInsertId();
            }

            // Link to report
            $this->database->run(
                "INSERT IGNORE INTO report_entities (report_id, entity_id) VALUES (?, ?)",
                [$reportId, $targetId]
            );

            // 2. Link IPs from DNS A/AAAA records
            if (isset($data['dns']['A'])) {
                foreach ($data['dns']['A'] as $aRecord) {
                    $ipVal = $aRecord['ip'] ?? '';
                    if (!$ipVal) continue;

                    $existingIp = $this->database->fetch(
                        "SELECT id FROM entities WHERE type = 'ip' AND value = ?",
                        [$ipVal]
                    );

                    if ($existingIp) {
                        $ipId = $existingIp['id'];
                    } else {
                        $this->database->insert('entities', [
                            'type' => 'ip',
                            'value' => $ipVal,
                            'risk_level' => 'informational',
                            'description' => "IP adresa vyřešená z DNS A záznamu pro {$target}.",
                            'payload' => json_encode($aRecord)
                        ]);
                        $ipId = $this->database->lastInsertId();
                    }

                    // Link to report
                    $this->database->run(
                        "INSERT IGNORE INTO report_entities (report_id, entity_id) VALUES (?, ?)",
                        [$reportId, $ipId]
                    );

                    // Add relationship
                    $existingRel = $this->database->fetch(
                        "SELECT id FROM relations WHERE entity_from_id = ? AND entity_to_id = ? AND relation_type = ?",
                        [$targetId, $ipId, 'dns_a_record']
                    );

                    if (!$existingRel) {
                        $this->database->insert('relations', [
                            'entity_from_id' => $targetId,
                            'entity_to_id' => $ipId,
                            'relation_type' => 'dns_a_record',
                            'details' => json_encode($aRecord)
                        ]);
                    }
                }
            }

            // 3. Save SSL Certificate Entity
            if (!empty($data['ssl']) && !isset($data['ssl']['error'])) {
                $ssl = $data['ssl'];
                $sslVal = "SSL: " . ($ssl['subject'] ?? $target);

                $existingSsl = $this->database->fetch(
                    "SELECT id FROM entities WHERE type = 'certificate' AND value = ?",
                    [$sslVal]
                );

                if ($existingSsl) {
                    $sslId = $existingSsl['id'];
                } else {
                    $this->database->insert('entities', [
                        'type' => 'certificate',
                        'value' => $sslVal,
                        'risk_level' => $ssl['expired'] ? 'critical' : ($ssl['expiring_soon'] ? 'medium' : 'informational'),
                        'description' => "SSL certifikát vystavený od {$ssl['issuer']}.",
                        'payload' => json_encode($ssl)
                    ]);
                    $sslId = $this->database->lastInsertId();
                }

                // Link to report
                $this->database->run(
                    "INSERT IGNORE INTO report_entities (report_id, entity_id) VALUES (?, ?)",
                    [$reportId, $sslId]
                );

                // Add relationship
                $existingRel = $this->database->fetch(
                    "SELECT id FROM relations WHERE entity_from_id = ? AND entity_to_id = ? AND relation_type = ?",
                    [$targetId, $sslId, 'ssl_certificate']
                );

                if (!$existingRel) {
                    $this->database->insert('relations', [
                        'entity_from_id' => $targetId,
                        'entity_to_id' => $sslId,
                        'relation_type' => 'ssl_certificate',
                        'details' => null
                    ]);
                }
            }

            // 4. Save Risks as Entities
            foreach ($data['risks'] as $risk) {
                $riskVal = $risk['description'];
                
                $existingRisk = $this->database->fetch(
                    "SELECT id FROM entities WHERE type = 'domain' AND value = ? AND risk_level = ?",
                    [$target, $risk['risk_level']] // update target's risk status if needed, or create a unique risk entity
                );

                // We can register a custom risk finding entity to display in the risk engine
                $this->database->insert('entities', [
                    'type' => 'domain', // attach finding to target type
                    'value' => "Nález: {$risk['description']}",
                    'risk_level' => $risk['risk_level'],
                    'description' => $risk['details'],
                    'payload' => json_encode($risk)
                ]);
                $riskId = $this->database->lastInsertId();

                // Link to report
                $this->database->run(
                    "INSERT IGNORE INTO report_entities (report_id, entity_id) VALUES (?, ?)",
                    [$reportId, $riskId]
                );

                // Link relationship from target to risk finding
                $this->database->insert('relations', [
                    'entity_from_id' => $targetId,
                    'entity_to_id' => $riskId,
                    'relation_type' => 'security_finding',
                    'details' => null
                ]);
            }

            $pdo->commit();
        } catch (Exception $e) {
            $pdo->rollBack();
            error_log("Transaction failed in InfrastructureAnalyzer::saveReportData: " . $e->getMessage());
            throw $e;
        }
    }
}