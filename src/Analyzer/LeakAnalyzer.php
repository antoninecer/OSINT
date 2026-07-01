<?php

namespace App\Analyzer;

use App\Database;
use App\Security;
use Exception;

class LeakAnalyzer
{
    private Database $database;

    public function __construct(Database $database)
    {
        $this->database = $database;
    }

    public function analyze(string $target): array
    {
        $target = trim($target);
        
        // Generate reproducible leak results based on the hash of the target
        $hash = crc32($target);
        srand($hash);

        $leaks = [];

        if (str_contains($target, '@')) {
            // Simulated search for specific email
            $leakSources = ['Canva', 'LinkedIn', 'Collection #1', 'MyFitnessPal', 'Adobe'];
            $compTypes = ['plaintext_password', 'hashed_password', 'personal_info'];
            
            $numLeaks = rand(1, 3);
            for ($i = 0; $i < $numLeaks; $i++) {
                $comp = $compTypes[rand(0, count($compTypes) - 1)];
                $leaks[] = [
                    'type' => 'email_leak',
                    'target' => $target,
                    'leak_source' => $leakSources[rand(0, count($leakSources) - 1)],
                    'leak_date' => date('Y-m-d', strtotime('-' . rand(1, 5) . ' years')),
                    'compromise_type' => $comp,
                    'severity' => $comp === 'plaintext_password' ? 'critical' : ($comp === 'hashed_password' ? 'high' : 'medium')
                ];
            }
        } elseif (Security::validateDomain($target)) {
            // Simulated search for a domain - returns compromised emails of employees
            $prefixes = ['admin', 'info', 'ceo', 'sales', 'support', 'developer'];
            $leakSources = ['Collection #1', 'LinkedIn', 'Adobe', 'Dropbox', 'Zynga'];
            $compTypes = ['hashed_password', 'plaintext_password'];

            $numLeaks = rand(2, 4);
            $selectedPrefixes = (array)array_rand(array_flip($prefixes), $numLeaks);
            
            foreach ($selectedPrefixes as $prefix) {
                $email = "{$prefix}@{$target}";
                $comp = $compTypes[rand(0, count($compTypes) - 1)];
                $leaks[] = [
                    'type' => 'email_leak',
                    'target' => $email,
                    'leak_source' => $leakSources[rand(0, count($leakSources) - 1)],
                    'leak_date' => date('Y-m-d', strtotime('-' . rand(1, 6) . ' years')),
                    'compromise_type' => $comp,
                    'severity' => $comp === 'plaintext_password' ? 'critical' : 'high'
                ];
            }
        } else {
            // Simulated search for a company name - return leaked GitHub keys/configs
            $repos = ['github.com/company-dev/config-repo', 'github.com/temp-worker/project-secrets'];
            $keys = ['AWS_ACCESS_KEY_ID', 'DATABASE_PASSWORD', 'STRIPE_API_KEY'];

            $leaks[] = [
                'type' => 'github_leak',
                'target' => $repos[rand(0, count($repos) - 1)],
                'leak_source' => 'GitHub Public Repository',
                'leak_date' => date('Y-m-d', strtotime('-' . rand(1, 12) . ' months')),
                'compromise_type' => 'exposed_api_key',
                'key_type' => $keys[rand(0, count($keys) - 1)],
                'severity' => 'critical'
            ];
        }

        // Reset seed
        srand();
        return $leaks;
    }

    public function saveReportData(int $reportId, array $data): void
    {
        $pdo = $this->database->getConnection();
        $pdo->beginTransaction();

        try {
            foreach ($data as $leak) {
                $type = ($leak['type'] === 'email_leak') ? 'email' : 'certificate';
                $value = $leak['target'];
                
                $riskLevel = 'informational';
                if ($leak['severity'] === 'critical') $riskLevel = 'critical';
                elseif ($leak['severity'] === 'high') $riskLevel = 'high';
                elseif ($leak['severity'] === 'medium') $riskLevel = 'medium';

                $description = "Únik dat z databáze {$leak['leak_source']}. Typ úniku: {$leak['compromise_type']}.";

                $existingEntity = $this->database->fetch(
                    "SELECT id FROM entities WHERE type = ? AND value = ?",
                    [$type, $value]
                );

                if ($existingEntity) {
                    $entityId = $existingEntity['id'];
                    // Update payload
                    $this->database->run(
                        "UPDATE entities SET payload = ? WHERE id = ?",
                        [json_encode($leak), $entityId]
                    );
                } else {
                    $this->database->insert('entities', [
                        'type' => $type,
                        'value' => $value,
                        'risk_level' => $riskLevel,
                        'description' => $description,
                        'payload' => json_encode($leak)
                    ]);
                    $entityId = $this->database->lastInsertId();
                }

                // Link to report
                $this->database->run(
                    "INSERT IGNORE INTO report_entities (report_id, entity_id) VALUES (?, ?)",
                    [$reportId, $entityId]
                );

                // Create a unique leak record entity to represent the vulnerability finding itself
                $leakVal = "Únik: {$value} ({$leak['leak_source']})";
                $existingFinding = $this->database->fetch(
                    "SELECT id FROM entities WHERE type = 'email' AND value = ? AND risk_level = ?",
                    [$leakVal, $riskLevel]
                );

                if (!$existingFinding) {
                    $this->database->insert('entities', [
                        'type' => 'email', // treat finding as email type category
                        'value' => $leakVal,
                        'risk_level' => $riskLevel,
                        'description' => "Kompromitováno v úniku {$leak['leak_source']} dne {$leak['leak_date']}.",
                        'payload' => json_encode($leak)
                    ]);
                    $findingId = $this->database->lastInsertId();

                    $this->database->run(
                        "INSERT IGNORE INTO report_entities (report_id, entity_id) VALUES (?, ?)",
                        [$reportId, $findingId]
                    );

                    // Add relationship between target and leak finding
                    $this->database->insert('relations', [
                        'entity_from_id' => $entityId,
                        'entity_to_id' => $findingId,
                        'relation_type' => 'compromised_in',
                        'details' => json_encode(['source' => $leak['leak_source']])
                    ]);
                }
            }

            $pdo->commit();
        } catch (Exception $e) {
            $pdo->rollBack();
            error_log("Transaction failed in LeakAnalyzer::saveReportData: " . $e->getMessage());
            throw $e;
        }
    }
}