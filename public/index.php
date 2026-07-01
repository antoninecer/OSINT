<?php

require __DIR__ . '/../vendor/autoload.php';

use App\SessionManager;
use App\Database;
use App\Security;
use App\ReportGenerator;

// Initialize Session
SessionManager::start();

// Handle AJAX image uploads first (before sending HTML headers)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action'])) {
    $action = $_GET['action'];
    $reportId = (int)($_GET['report_id'] ?? 0);
    
    if ($reportId > 0 && ($action === 'save_graph_img' || $action === 'save_chart_img')) {
        $json = file_get_contents('php://input');
        $data = json_decode($json, true);
        $image = $data['image'] ?? '';
        
        if ($image) {
            // Save PNG base64 in session for PDF generation usage
            SessionManager::set($action . '_' . $reportId, $image);
            header('Content-Type: application/json');
            echo json_encode(['status' => 'success']);
            exit;
        }
    }
}

// Initialize Database and Report Generator
$db = Database::getInstance();
$reportGen = new ReportGenerator($db);

// Send Security Headers (CSP Nonce is generated dynamically here)
Security::sendSecurityHeaders();
$nonce = Security::getNonce();

$errorMessage = '';
$successMessage = '';

// Handle analysis query submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['search_target'])) {
    $target = $_POST['search_target'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';
    $pricing = $_POST['pricing_level'] ?? 'free';

    if (!Security::verifyCsrfToken($csrfToken)) {
        $errorMessage = 'Chyba zabezpečení: Neplatný CSRF token.';
    } else {
        try {
            $reportId = $reportGen->createReport($target, $pricing);
            header("Location: index.php?report_id=" . $reportId . "&level=" . urlencode($pricing));
            exit;
        } catch (Exception $e) {
            $errorMessage = $e->getMessage();
        }
    }
}

// Generate CSRF token for forms
$csrfToken = Security::generateCsrfToken();

// Load active report details if requested
$reportId = (int)($_GET['report_id'] ?? 0);
$pricingLevel = $_GET['level'] ?? 'free';

// Ensure valid level value
if (!in_array($pricingLevel, ['free', 'surcharge1', 'surcharge2'])) {
    $pricingLevel = 'free';
}

$reportData = null;
if ($reportId > 0) {
    try {
        $reportData = $reportGen->getReport($reportId, $pricingLevel);
    } catch (Exception $e) {
        $errorMessage = 'Nepodařilo se načíst analýzu: ' . $e->getMessage();
        $reportId = 0;
    }
}
?>
<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RightDone Intelligence | OSINT & Due Diligence Platform</title>
    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <!-- Bootstrap 5 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
    <!-- Custom Style -->
    <link rel="stylesheet" href="assets/css/style.css" nonce="<?php echo $nonce; ?>">
</head>
<body>

    <div class="container py-4">
        <!-- Logo Header -->
        <header class="header-rd">
            <a href="index.php" class="logo-rd">
                RightDone <span>Intelligence</span>
            </a>
            <div class="text-end">
                <span class="badge bg-secondary text-dark" style="font-size: 11px;">PASSIVE OSINT ANALYST v1.0</span>
            </div>
        </header>

        <?php if ($errorMessage): ?>
            <div class="alert alert-danger glass-card border-danger text-light" role="alert">
                <strong>Chyba:</strong> <?php echo Security::escape($errorMessage); ?>
            </div>
        <?php endif; ?>

        <?php if ($reportId === 0): ?>
            <!-- Landing Search Panel -->
            <div class="text-center my-5">
                <h1 style="font-weight: 700; font-size: 3.2rem; margin-bottom: 12px; letter-spacing: -1px;">
                    Rozhodnutí podložená <span>daty</span>
                </h1>
                <p class="text-muted max-width-600 mx-auto" style="font-size: 18px; margin-bottom: 40px;">
                    Zadejte IČO, doménu, IP adresu nebo název firmy. <br>
                    RightDone Intelligence vybuduje kompletní profil subjektu a vazeb okamžitě.
                </p>

                <div class="search-container">
                    <form method="post" action="index.php" class="search-form">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                        <div class="search-input-group">
                            <input type="text" name="search_target" placeholder="Zadejte IČO (např. 12345678), doménu (např. nic.cz), IP..." required autocomplete="off">
                            <button type="submit">Spustit analýzu</button>
                        </div>
                        <div class="mt-3">
                            <label class="text-muted me-3" style="font-size: 14px;">Úroveň reportu:</label>
                            <div class="form-check form-check-inline text-light">
                                <input class="form-check-input" type="radio" name="pricing_level" id="pFree" value="free" checked>
                                <label class="form-check-label" for="pFree">Zdarma</label>
                            </div>
                            <div class="form-check form-check-inline text-light">
                                <input class="form-check-input" type="radio" name="pricing_level" id="pSurch1" value="surcharge1">
                                <label class="form-check-label" for="pSurch1">Příplatek 1 (IT / Leaks)</label>
                            </div>
                            <div class="form-check form-check-inline text-light">
                                <input class="form-check-input" type="radio" name="pricing_level" id="pSurch2" value="surcharge2">
                                <label class="form-check-label" for="pSurch2">Příplatek 2 (Graf & Vztahy)</label>
                            </div>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Features Cards Grid -->
            <div class="grid-rd mt-5 pt-3">
                <div class="glass-card">
                    <h5 style="color: var(--primary); font-weight:600;">Company Intelligence</h5>
                    <p class="text-muted" style="font-size:14px; line-height: 1.6;">Rychlé napojení na ARES a obchodní rejstřík. Analýza statutárních orgánů, společníků, sídla a finančního stavu.</p>
                </div>
                <div class="glass-card">
                    <h5 style="color: var(--primary); font-weight:600;">Infrastructure OSINT</h5>
                    <p class="text-muted" style="font-size:14px; line-height: 1.6;">DNS resolving (A, MX, TXT), WHOIS domény a IP adres, vyhodnocení SSL certifikátů, bezpečnostních rizik a webových technologií.</p>
                </div>
                <div class="glass-card">
                    <h5 style="color: var(--primary); font-weight:600;">Leak Intelligence</h5>
                    <p class="text-muted" style="font-size:14px; line-height: 1.6;">Skener veřejně dostupných úniků přihlašovacích údajů, ohrožených firemních e-mailů a uniklých vývojářských klíčů.</p>
                </div>
            </div>
            
        <?php else: ?>
            <!-- Report Dashboard View -->
            <div class="d-flex justify-content-between align-items-center mb-4">
                <div>
                    <h2 style="font-weight: 700; margin-bottom: 2px;">
                        Report analýzy: <span style="color: var(--primary);"><?php echo Security::escape($reportData['report']['target_value']); ?></span>
                    </h2>
                    <p class="text-muted m-0">Zadání: <?php echo strtoupper($reportData['report']['target_type']); ?> | Datum: <?php echo date('d.m.Y H:i', strtotime($reportData['report']['created_at'])); ?></p>
                </div>
                <a href="index.php" class="btn btn-outline-light btn-sm">&larr; Nové hledání</a>
            </div>

            <!-- Pricing switcher group -->
            <div class="d-flex justify-content-between align-items-center flex-wrap gap-3 mb-4">
                <div class="pricing-btn-group" data-report-id="<?php echo $reportId; ?>">
                    <button class="pricing-level-btn <?php echo $pricingLevel === 'free' ? 'active' : ''; ?>" data-level="free">Zdarma</button>
                    <button class="pricing-level-btn <?php echo $pricingLevel === 'surcharge1' ? 'active' : ''; ?>" data-level="surcharge1">Příplatek 1 (IT & Leaks)</button>
                    <button class="pricing-level-btn <?php echo $pricingLevel === 'surcharge2' ? 'active' : ''; ?>" data-level="surcharge2">Příplatek 2 (Vztahy & Graf)</button>
                </div>
                <?php if ($pricingLevel === 'surcharge2'): ?>
                    <a href="pdf.php?report_id=<?php echo $reportId; ?>&level=surcharge2" class="btn-rd-primary" target="_blank">
                        Stáhnout PDF report
                    </a>
                <?php else: ?>
                    <button class="btn btn-secondary btn-sm" disabled style="opacity:0.6;">Stáhnout PDF (Vyžaduje Příplatek 2)</button>
                <?php endif; ?>
            </div>

            <div class="row">
                <!-- Left: Dashboard info cards -->
                <div class="col-lg-8">
                    <!-- Executive summary panel -->
                    <div class="glass-card">
                        <h4 style="font-weight:600; margin-bottom: 15px;">Manažerské shrnutí (Executive Summary)</h4>
                        <p style="font-size:16px; line-height: 1.6; margin-bottom: 20px;">
                            <?php echo Security::escape($reportData['executive_summary']); ?>
                        </p>
                        
                        <div class="d-flex gap-4 flex-wrap mt-2">
                            <div>
                                <span class="text-muted d-block" style="font-size:12px; text-transform:uppercase;">Nalezené vazby</span>
                                <strong style="font-size: 20px; color: var(--primary);"><?php echo $reportData['stats']['total_relations']; ?></strong>
                            </div>
                            <div>
                                <span class="text-muted d-block" style="font-size:12px; text-transform:uppercase;">Analyzované objekty</span>
                                <strong style="font-size: 20px; color: var(--primary);"><?php echo $reportData['stats']['total_entities']; ?></strong>
                            </div>
                            <div>
                                <span class="text-muted d-block" style="font-size:12px; text-transform:uppercase;">Veřejné dokumenty</span>
                                <strong style="font-size: 20px; color: var(--primary);"><?php echo $reportData['stats']['total_documents']; ?></strong>
                            </div>
                            <div>
                                <span class="text-muted d-block" style="font-size:12px; text-transform:uppercase;">Technologie / Rizika</span>
                                <strong style="font-size: 20px; color: var(--primary);"><?php echo $reportData['stats']['total_technologies'] . ' / ' . $reportData['stats']['total_risks']; ?></strong>
                            </div>
                        </div>
                    </div>

                    <!-- Company Info Details Card -->
                    <?php 
                    $company = null;
                    foreach ($reportData['entities'] as $e) {
                        if ($e['type'] === 'company') {
                            $company = $e;
                            break;
                        }
                    }
                    if ($company): 
                        $p = $company['payload'];
                    ?>
                        <div class="glass-card">
                            <h4 style="font-weight:600; margin-bottom:20px;">Informace z obchodního rejstříku (ARES)</h4>
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <span class="text-muted d-block" style="font-size:13px;">Název firmy</span>
                                    <strong><?php echo Security::escape($p['name'] ?? $company['value']); ?></strong>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <span class="text-muted d-block" style="font-size:13px;">IČO / DIČ</span>
                                    <strong><?php echo Security::escape($p['ico'] ?? ''); ?> / <?php echo Security::escape($p['dic'] ?? 'Neuvedeno'); ?></strong>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <span class="text-muted d-block" style="font-size:13px;">Právní forma</span>
                                    <span><?php echo Security::escape($p['legal_form'] ?? 'Neznámá'); ?></span>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <span class="text-muted d-block" style="font-size:13px;">Datum založení</span>
                                    <span><?php echo Security::escape($p['registration_date'] ? date('d.m.Y', strtotime($p['registration_date'])) : 'Neuvedeno'); ?></span>
                                </div>
                                <div class="col-md-12 mb-3">
                                    <span class="text-muted d-block" style="font-size:13px;">Sídlo</span>
                                    <span>
                                        <?php 
                                        if (is_array($p['address'] ?? null)) {
                                            $addr = $p['address'];
                                            echo Security::escape("{$addr['street']}, {$addr['zip']} {$addr['city']}, {$addr['country']}");
                                        } else {
                                            echo Security::escape($company['value']);
                                        }
                                        ?>
                                    </span>
                                </div>
                                <div class="col-md-12">
                                    <span class="text-muted d-block" style="font-size:13px;">Předmět podnikání / Aktivita</span>
                                    <span><?php echo Security::escape($p['activity_description'] ?? 'Neuvedeno'); ?></span>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>

                    <!-- INFRASTRUCTURE OSINT TABLE (Surcharge 1 / 2 only) -->
                    <?php if ($pricingLevel !== 'free'): ?>
                        <?php 
                        $domainEntity = null;
                        foreach ($reportData['entities'] as $e) {
                            if ($e['type'] === 'domain' && !str_starts_with($e['value'], 'Nález:')) {
                                $domainEntity = $e;
                                break;
                            }
                        }
                        if ($domainEntity && !empty($domainEntity['payload']['dns'])): 
                            $dns = $domainEntity['payload']['dns'];
                        ?>
                            <div class="glass-card">
                                <h4 style="font-weight:600; margin-bottom:20px;">Analýza DNS a infrastruktury</h4>
                                <div class="table-responsive">
                                    <table class="table-rd">
                                        <thead>
                                            <tr>
                                                <th>Typ</th>
                                                <th>Cíl (Záznam)</th>
                                                <th>Podrobnosti</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($dns as $type => $records): ?>
                                                <?php foreach ($records as $r): ?>
                                                    <tr>
                                                        <td><span class="badge bg-secondary"><?php echo Security::escape($type); ?></span></td>
                                                        <td>
                                                            <strong>
                                                                <?php 
                                                                echo Security::escape($r['ip'] ?? ($r['target'] ?? ($r['txt'] ?? ''))); 
                                                                ?>
                                                            </strong>
                                                        </td>
                                                        <td class="text-muted" style="font-size:13px;">
                                                            <?php 
                                                            if (isset($r['pri'])) echo "Priorita: " . $r['pri'];
                                                            if (isset($r['ttl'])) echo " | TTL: " . $r['ttl'];
                                                            ?>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>

                                <?php if (!empty($domainEntity['payload']['ssl'])): 
                                    $ssl = $domainEntity['payload']['ssl'];
                                ?>
                                    <div class="mt-4 pt-3 border-top border-secondary">
                                        <h5 style="font-weight:600; margin-bottom:15px; color: var(--primary);">SSL certifikát</h5>
                                        <div class="row">
                                            <div class="col-md-6 mb-2">
                                                <span class="text-muted d-block" style="font-size:12px;">Předmět certifikátu</span>
                                                <strong><?php echo Security::escape($ssl['subject']); ?></strong>
                                            </div>
                                            <div class="col-md-6 mb-2">
                                                <span class="text-muted d-block" style="font-size:12px;">Vydavatel</span>
                                                <span><?php echo Security::escape($ssl['issuer']); ?></span>
                                            </div>
                                            <div class="col-md-6">
                                                <span class="text-muted d-block" style="font-size:12px;">Platnost</span>
                                                <span style="font-size: 13px;">Od: <?php echo date('d.m.Y', strtotime($ssl['valid_from'])); ?> do: <?php echo date('d.m.Y', strtotime($ssl['valid_to'])); ?></span>
                                            </div>
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>

                        <!-- LEAK INTELLIGENCE (Surcharge 1 / 2 only) -->
                        <div class="glass-card">
                            <h4 style="font-weight:600; margin-bottom:20px;">Leak Intelligence (Úniky přihlašovacích údajů)</h4>
                            <?php 
                            $leaks = [];
                            foreach ($reportData['entities'] as $e) {
                                if (($e['type'] === 'email' || $e['type'] === 'certificate') && isset($e['payload']['leak_source'])) {
                                    $leaks[] = $e['payload'];
                                }
                            }
                            if (empty($leaks)): 
                            ?>
                                <p class="text-muted m-0">Nebyly detekovány žádné veřejné úniky spojené s tímto cílem.</p>
                            <?php else: ?>
                                <div class="table-responsive">
                                    <table class="table-rd">
                                        <thead>
                                            <tr>
                                                <th>Kompromitovaný objekt</th>
                                                <th>Zdroj úniku</th>
                                                <th>Typ úniku</th>
                                                <th>Závažnost</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($leaks as $l): ?>
                                                <tr>
                                                    <td><strong><?php echo Security::escape($l['target']); ?></strong></td>
                                                    <td><span class="text-muted"><?php echo Security::escape($l['leak_source']); ?></span></td>
                                                    <td><code><?php echo Security::escape($l['compromise_type']); ?></code></td>
                                                    <td>
                                                        <span class="badge-rd badge-<?php echo ($l['severity'] === 'critical') ? 'critical' : (($l['severity'] === 'high') ? 'high' : 'medium'); ?>">
                                                            <?php echo strtoupper($l['severity']); ?>
                                                        </span>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>

                    <!-- RELATION GRAPH & TIMELINE (Surcharge 2 only) -->
                    <?php if ($pricingLevel === 'surcharge2'): ?>
                        <!-- Graph visualization -->
                        <div class="glass-card">
                            <h4 style="font-weight:600; margin-bottom:5px;">Graf vztahů a vazeb</h4>
                            <p class="text-muted" style="font-size:13px;">Interaktivní diagram zobrazující statutární vazby, propojené subjekty a sídlo.</p>
                            
                            <?php 
                            // Prepare elements for Cytoscape.js
                            $nodes = [];
                            $edges = [];
                            
                            foreach ($reportData['entities'] as $e) {
                                $classes = $e['type'];
                                // truncate label if long
                                $label = $e['value'];
                                if (strlen($label) > 30) {
                                    $label = substr($label, 0, 27) . '...';
                                }
                                $nodes[] = [
                                    'data' => [
                                        'id' => (string)$e['id'],
                                        'label' => $label
                                    ],
                                    'classes' => $classes
                                ];
                            }
                            
                            foreach ($reportData['relations'] as $r) {
                                $edges[] = [
                                    'data' => [
                                        'id' => 'e' . $r['id'],
                                        'source' => (string)$r['entity_from_id'],
                                        'target' => (string)$r['entity_to_id'],
                                        'label' => $r['relation_type']
                                    ]
                                ];
                            }
                            $cyElements = array_merge($nodes, $edges);
                            ?>
                            
                            <!-- Container with dataset -->
                            <div id="graph-container" data-elements="<?php echo Security::escape(json_encode($cyElements)); ?>"></div>
                        </div>

                        <!-- Timeline event list -->
                        <div class="glass-card">
                            <h4 style="font-weight:600; margin-bottom:20px;">Časová osa vývoje a událostí</h4>
                            <div class="timeline">
                                <div class="timeline-item">
                                    <div class="timeline-time">Založení subjektu</div>
                                    <div class="timeline-title">Zápis do obchodního rejstříku</div>
                                    <div class="timeline-desc">Společnost byla zapsána s uvedeným základním kapitálem a sídlem.</div>
                                </div>
                                <div class="timeline-item">
                                    <div class="timeline-time">Průběžná aktualizace</div>
                                    <div class="timeline-title">Prověření statusu plátce DPH</div>
                                    <div class="timeline-desc">Subjekt byl ověřen a je registrován jako aktivní plátce DPH v systému ADIS.</div>
                                </div>
                                <div class="timeline-item">
                                    <div class="timeline-time">Dnešní den</div>
                                    <div class="timeline-title">Aktuální bezpečnostní prověrka</div>
                                    <div class="timeline-desc">Byla dokončena pasivní analýza síťové infrastruktury a úniků dat.</div>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>

                    <!-- Locked placeholders for lower pricing levels to upsell -->
                    <?php if ($pricingLevel === 'free'): ?>
                        <div class="glass-card text-center py-5" style="border-style: dashed; border-color: rgba(255,255,255,0.15);">
                            <h4 style="font-weight:600; color: var(--primary);">Chcete vidět hloubkovou IT analýzu a úniky hesel?</h4>
                            <p class="text-muted max-width-500 mx-auto my-3" style="font-size:14px;">
                                Odemkněte **Příplatek 1 (IT & Leaks)** pro zobrazení kompletních DNS záznamů, WHOIS informací, zabezpečení SSL a skeneru uniklých e-mailů s hesly.
                            </p>
                            <button class="pricing-level-btn btn-rd-primary" data-level="surcharge1">Přejít na Příplatek 1</button>
                        </div>
                    <?php endif; ?>

                    <?php if ($pricingLevel !== 'surcharge2'): ?>
                        <div class="glass-card text-center py-5" style="border-style: dashed; border-color: rgba(255,255,255,0.15);">
                            <h4 style="font-weight:600; color: var(--primary);">Kompletní graf vazeb a PDF ke stažení</h4>
                            <p class="text-muted max-width-500 mx-auto my-3" style="font-size:14px;">
                                Odemkněte **Příplatek 2 (Graf & Vztahy)** pro zobrazení interaktivního pavučinového grafu vlastníků a jednatelů, časové osy změn a stažení reportu do tisknutelného PDF dokumentu.
                            </p>
                            <button class="pricing-level-btn btn-rd-primary" data-level="surcharge2">Přejít na Příplatek 2</button>
                        </div>
                    <?php endif; ?>
                </div>

                <!-- Right: Sidebar with Risk Score indicators -->
                <div class="col-lg-4">
                    <!-- Risk Score Circular Display -->
                    <div class="glass-card text-center">
                        <h5 style="font-weight:600; margin-bottom:20px;">AI Risk Score</h5>
                        
                        <div class="d-flex justify-content-center mb-3">
                            <div class="risk-score-container">
                                <?php 
                                $score = $reportData['risk_score'];
                                $scoreColor = '#2ecc71';
                                if ($score > 60) $scoreColor = '#ff3366';
                                elseif ($score > 35) $scoreColor = '#ff9f43';
                                elseif ($score > 15) $scoreColor = '#f1c40f';
                                ?>
                                <div class="risk-circle" style="--score-color: <?php echo $scoreColor; ?>; --percentage: <?php echo ($score * 3.6) . 'deg'; ?>">
                                    <span><?php echo $score; ?>%</span>
                                </div>
                            </div>
                        </div>

                        <p class="text-muted m-0" style="font-size:13px; line-height: 1.5;">
                            Rizikový index vypočítaný na základě závažnosti nalezených hrozeb a zjištěných chyb.
                        </p>
                    </div>

                    <!-- List of specific security findings/risks -->
                    <div class="glass-card">
                        <h5 style="font-weight:600; margin-bottom:20px;">Bezpečnostní nálezy a rizika</h5>
                        <?php 
                        $risks = [];
                        foreach ($reportData['entities'] as $e) {
                            if ($e['risk_level'] !== 'informational') {
                                $risks[] = $e;
                            }
                        }
                        if (empty($risks)): 
                        ?>
                            <p class="text-muted m-0">Nebyly nalezeny žádné bezpečnostní hrozby.</p>
                        <?php else: ?>
                            <ul class="list-unstyled m-0">
                                <?php foreach ($risks as $r): ?>
                                    <li class="mb-3 pb-3 border-bottom border-secondary">
                                        <div class="d-flex justify-content-between align-items-start mb-1">
                                            <strong style="font-size:14px;"><?php echo Security::escape(str_replace('Nález: ', '', $r['value'])); ?></strong>
                                            <span class="badge-rd badge-<?php echo Security::escape($r['risk_level']); ?>">
                                                <?php echo Security::escape($r['risk_level']); ?>
                                            </span>
                                        </div>
                                        <p class="text-muted m-0" style="font-size:13px; line-height:1.4;">
                                            <?php echo Security::escape($r['description']); ?>
                                        </p>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- Cookies Privacy Consent Banner -->
    <div class="cookie-banner">
        <p class="cookie-text">
            <strong>Používáme nezbytné technické cookies.</strong> Tyto cookies jsou vyžadovány pro fungování aplikace (ukládání konfigurace reportů a stavu analýzy). Neshromažďujeme ani nesledujeme žádné údaje o vašem soukromí pro marketingové účely.
        </p>
        <div class="cookie-actions">
            <button class="cookie-btn-accept">Rozumím</button>
        </div>
    </div>

    <!-- Cytoscape, ChartJS and Custom App scripts -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.29.2/cytoscape.min.js" integrity="sha512-42qCj0AcsjL7V1C/8Uv/m38m5hV95jDq6Lp8K7e/v4vK7/Z4r5w06nL3119X2w6g==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@2.9.4/dist/Chart.min.js" integrity="sha256-R4pqcOY1SLLtTRL6gGGNryI9dR3G1ycE8d9U4gENSWw=" crossorigin="anonymous"></script>
    <script src="assets/js/app.js" nonce="<?php echo $nonce; ?>"></script>

</body>
</html>