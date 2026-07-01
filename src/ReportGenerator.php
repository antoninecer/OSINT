<?php

namespace App;

use App\Database;
use App\Security;
use App\Analyzer\CompanyAnalyzer;
use App\Analyzer\InfrastructureAnalyzer;
use App\Analyzer\LeakAnalyzer;
use Exception;

class ReportGenerator
{
    private Database $db;

    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    public function createReport(string $target, string $pricingLevel): int
    {
        $target = Security::sanitizeInput($target);
        $targetType = $this->detectTargetType($target);

        if ($target === '') {
            throw new Exception('Vyhledávaný cíl nesmí být prázdný.');
        }

        $sessionId = SessionManager::get('session_id') ?: session_id();
        if (!$sessionId) {
            $sessionId = 'anonymous_session';
        }

        // 1. Create report metadata entry
        $this->db->insert('reports', [
            'session_id' => $sessionId,
            'pricing_level' => $pricingLevel,
            'target_type' => $targetType,
            'target_value' => $target
        ]);
        $reportId = (int)$this->db->lastInsertId();

        // Log search action to audit logs
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $this->db->insert('audit_logs', [
            'session_id' => $sessionId,
            'action' => 'create_report',
            'target_type' => $targetType,
            'target_value' => $target,
            'ip_address' => $ip,
            'user_agent' => $ua
        ]);

        // 2. Instantiate and run analyzers based on target type
        $analyzers = $this->getAnalyzersForType($targetType);
        
        foreach ($analyzers as $analyzer) {
            try {
                $data = $analyzer->analyze($target);
                $analyzer->saveReportData($reportId, $data);
            } catch (Exception $e) {
                error_log("Analyzer execution failed for target {$target}: " . $e->getMessage());
                // Continue execution so that report is created even if one analyzer fails
            }
        }

        return $reportId;
    }

    public function getReport(int $reportId, string $pricingLevel): array
    {
        $report = $this->db->fetch("SELECT * FROM reports WHERE id = ?", [$reportId]);
        if (!$report) {
            throw new Exception('Report nebyl nalezen.');
        }

        // Fetch entities linked to this report
        $entities = $this->db->fetchAll(
            "SELECT e.* FROM entities e 
             JOIN report_entities re ON e.id = re.entity_id 
             WHERE re.report_id = ?",
            [$reportId]
        );

        // Fetch relationships between entities in this report
        $relations = $this->db->fetchAll(
            "SELECT r.* FROM relations r 
             JOIN report_entities re1 ON r.entity_from_id = re1.entity_id 
             JOIN report_entities re2 ON r.entity_to_id = re2.entity_id 
             WHERE re1.report_id = ? AND re2.report_id = ?",
            [$reportId, $reportId]
        );

        // Decode JSON payloads
        foreach ($entities as &$entity) {
            $entity['payload'] = json_decode($entity['payload'] ?? '{}', true);
        }
        foreach ($relations as &$relation) {
            $relation['details'] = json_decode($relation['details'] ?? '{}', true);
        }

        // Apply pricing level filtering
        $cleaned = $this->applyPricingLevelLimits($report, $entities, $relations, $pricingLevel);
        
        // Calculate consolidated Risk Score (0-100)
        $riskScore = $this->computeRiskScore($cleaned['entities']);

        // Generate dynamic Executive Summary
        $executiveSummary = $this->generateExecutiveSummary($report, $cleaned['entities'], $riskScore);

        return [
            'report' => $report,
            'entities' => $cleaned['entities'],
            'relations' => $cleaned['relations'],
            'risk_score' => $riskScore,
            'executive_summary' => $executiveSummary,
            'stats' => $cleaned['stats']
        ];
    }

    private function detectTargetType(string $target): string
    {
        if (Security::validateIco($target)) {
            return 'ico';
        } elseif (Security::validateIp($target)) {
            return 'ip';
        } elseif (Security::validateDomain($target)) {
            return 'domain';
        } else {
            // Check if it's a domain name that was typed without prefix, or treat as company name
            return 'company';
        }
    }

    private function getAnalyzersForType(string $targetType): array
    {
        switch ($targetType) {
            case 'ico':
                return [new CompanyAnalyzer($this->db)];
            case 'domain':
                return [
                    new InfrastructureAnalyzer($this->db),
                    new LeakAnalyzer($this->db)
                ];
            case 'ip':
                return [new InfrastructureAnalyzer($this->db)];
            case 'company':
            default:
                return [new LeakAnalyzer($this->db)];
        }
    }

    private function applyPricingLevelLimits(array $report, array $entities, array $relations, string $pricingLevel): array
    {
        $filteredEntities = [];
        $filteredRelations = [];

        // Count stats *before* filtering to display "what was found" for sales conversion
        $stats = [
            'total_entities' => count($entities),
            'total_relations' => count($relations),
            'total_risks' => 0,
            'total_documents' => rand(3, 10), // Simulated counts of public records
            'total_technologies' => 0
        ];

        foreach ($entities as $e) {
            if ($e['risk_level'] !== 'informational') {
                $stats['total_risks']++;
            }
            if ($e['type'] === 'certificate' || ($e['type'] === 'domain' && str_starts_with($e['value'], 'Nález:'))) {
                // count techs / finding issues
                $stats['total_technologies']++;
            }
        }

        foreach ($entities as $e) {
            $keep = false;

            if ($pricingLevel === 'free') {
                // Free features: Basic ARES data (company, address), Target domain/IP (dns_basic)
                if (in_array($e['type'], ['company', 'address'])) {
                    $keep = true;
                }
                if ($e['type'] === $report['target_type'] && $e['value'] === $report['target_value']) {
                    $keep = true;
                }
            } elseif ($pricingLevel === 'surcharge1') {
                // Surcharge 1: Free + DNS full, WHOIS, Web Tech, Leaks summary stats
                if (in_array($e['type'], ['company', 'address', 'domain', 'ip', 'certificate'])) {
                    // Filter out detailed Leak finding entities (e.g. specific compromised emails)
                    if (str_starts_with($e['value'], 'Únik:')) {
                        $keep = false;
                    } else {
                        $keep = true;
                    }
                }
            } else {
                // Surcharge 2: Everything unlocked
                $keep = true;
            }

            if ($keep) {
                // Strip detailed payloads for lower tiers
                if ($pricingLevel === 'free') {
                    // Strip specific IP info and address details
                    if ($e['type'] === 'address') {
                        $e['payload'] = ['city' => $e['payload']['city'] ?? '', 'country' => $e['payload']['country'] ?? ''];
                        $e['value'] = "Sídlo společnosti (Detail skryt)";
                    }
                }
                $filteredEntities[] = $e;
            }
        }

        // Filter relations based on remaining entities
        $entityIds = array_column($filteredEntities, 'id');
        foreach ($relations as $r) {
            if (in_array($r['entity_from_id'], $entityIds) && in_array($r['entity_to_id'], $entityIds)) {
                $filteredRelations[] = $r;
            }
        }

        return [
            'entities' => $filteredEntities,
            'relations' => $filteredRelations,
            'stats' => $stats
        ];
    }

    private function computeRiskScore(array $entities): int
    {
        $score = 0;
        foreach ($entities as $e) {
            switch ($e['risk_level']) {
                case 'low':
                    $score += 5;
                    break;
                case 'medium':
                    $score += 15;
                    break;
                case 'high':
                    $score += 35;
                    break;
                case 'critical':
                    $score += 65;
                    break;
            }
        }
        return min(100, $score);
    }

    private function generateExecutiveSummary(array $report, array $entities, int $riskScore): string
    {
        $target = $report['target_value'];
        $type = strtoupper($report['target_type']);

        $riskText = 'NÍZKÉ RIZIKO';
        if ($riskScore > 60) $riskText = 'KRITICKÉ RIZIKO';
        elseif ($riskScore > 35) $riskText = 'VYSOKÉ RIZIKO';
        elseif ($riskScore > 15) $riskText = 'STŘEDNÍ RIZIKO';

        return "Analýza subjektu {$target} (typ: {$type}) byla dokončena s výsledným rizikovým skóre {$riskScore}/100, což odpovídá kategorii: {$riskText}. " .
               "Během analýzy bylo identifikováno celkem " . count($entities) . " souvisejících objektů v infrastruktuře a rejstřících.";
    }
}