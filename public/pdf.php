<?php

require __DIR__ . '/../vendor/autoload.php';

use App\SessionManager;
use App\Database;
use App\Security;
use App\ReportGenerator;
use Dompdf\Dompdf;
use Dompdf\Options;

// Initialize Session
SessionManager::start();

$reportId = (int)($_GET['report_id'] ?? 0);
$level = $_GET['level'] ?? 'free';

if ($reportId <= 0 || $level !== 'surcharge2') {
    http_response_code(403);
    echo "<h1>403 Forbidden</h1><p>Stažení PDF reportu je dostupné pouze pro úroveň Příplatek 2.</p>";
    exit;
}

try {
    $db = Database::getInstance();
    $reportGen = new ReportGenerator($db);
    
    // Verify report existence and session owner (optional security binding, using session comparison)
    $report = $db->fetch("SELECT * FROM reports WHERE id = ?", [$reportId]);
    if (!$report) {
        http_response_code(404);
        echo "<h1>404 Not Found</h1><p>Report nebyl nalezen.</p>";
        exit;
    }
    
    $currentSessionId = SessionManager::get('session_id') ?: session_id();
    if ($report['session_id'] !== $currentSessionId) {
        // Access control: only the creator of the report can download it in this session
        http_response_code(403);
        echo "<h1>403 Forbidden</h1><p>Nemáte oprávnění ke stažení tohoto reportu.</p>";
        exit;
    }

    // Retrieve full report details (level Surcharge 2)
    $reportData = $reportGen->getReport($reportId, 'surcharge2');

    // Retrieve base64 graph and chart images stored in session by client-side renderers
    $graphImg = SessionManager::get('save_graph_img_' . $reportId, '');
    $chartImg = SessionManager::get('save_chart_img_' . $reportId, '');

    // Format HTML for PDF rendering using Dompdf (A4 printable styling, flex/grid not supported)
    $html = '
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Report: ' . htmlspecialchars($reportData['report']['target_value']) . '</title>
        <style>
            @page {
                margin: 20mm;
            }
            body {
                background-color: #0b0f19;
                color: #f1f3f9;
                font-family: DejaVu Sans, Helvetica, sans-serif;
                font-size: 13px;
                line-height: 1.5;
            }
            .header {
                border-bottom: 2px solid #00d2ff;
                padding-bottom: 10px;
                margin-bottom: 30px;
            }
            .logo {
                font-size: 20px;
                font-weight: bold;
                color: #f1f3f9;
            }
            .logo span {
                color: #00d2ff;
            }
            h1, h2, h3, h4 {
                color: #00d2ff;
                margin-top: 25px;
                margin-bottom: 15px;
                font-weight: normal;
            }
            h1 {
                font-size: 24px;
            }
            h2 {
                font-size: 18px;
                border-bottom: 1px solid rgba(255,255,255,0.1);
                padding-bottom: 5px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 25px;
            }
            table th, table td {
                padding: 10px;
                text-align: left;
                border-bottom: 1px solid rgba(255,255,255,0.08);
            }
            table th {
                color: #8b9bb4;
                font-weight: bold;
                width: 30%;
            }
            .executive-box {
                background-color: #101626;
                border-left: 4px solid #00d2ff;
                padding: 15px;
                margin-bottom: 25px;
            }
            .badge {
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                text-transform: uppercase;
                font-weight: bold;
            }
            .badge-critical { background-color: #ff3366; color: #fff; }
            .badge-high { background-color: #ff9f43; color: #fff; }
            .badge-medium { background-color: #f1c40f; color: #000; }
            .badge-low { background-color: #2ecc71; color: #fff; }
            .badge-info { background-color: #3498db; color: #fff; }
            
            .image-container {
                text-align: center;
                margin: 30px 0;
                background-color: #101626;
                padding: 15px;
                border-radius: 8px;
            }
            .image-container img {
                max-width: 100%;
                max-height: 350px;
            }
            .page-break {
                page-break-before: always;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <span class="logo">RightDone <span>Intelligence</span></span>
            <div style="float: right; color: #8b9bb4; font-size: 11px; margin-top: 5px;">
                DUE-DILIGENCE & OSINT REPORT
            </div>
            <div style="clear: both;"></div>
        </div>

        <h1>Bezpečnostní prověrka subjektu</h1>
        
        <table>
            <tr>
                <th>Analyzovaný cíl:</th>
                <td style="font-weight: bold; color: #00d2ff;">' . htmlspecialchars($reportData['report']['target_value']) . '</td>
            </tr>
            <tr>
                <th>Typ subjektu:</th>
                <td>' . htmlspecialchars(strtoupper($reportData['report']['target_type'])) . '</td>
            </tr>
            <tr>
                <th>Datum vygenerování:</th>
                <td>' . htmlspecialchars(date('d.m.Y H:i', strtotime($reportData['report']['created_at']))) . '</td>
            </tr>
            <tr>
                <th>AI Risk Score:</th>
                <td style="font-weight: bold; color: ' . ($reportData['risk_score'] > 60 ? '#ff3366' : ($reportData['risk_score'] > 35 ? '#ff9f43' : '#2ecc71')) . ';">' . $reportData['risk_score'] . '%</td>
            </tr>
        </table>

        <h2>Manažerské shrnutí (Executive Summary)</h2>
        <div class="executive-box">
            ' . htmlspecialchars($reportData['executive_summary']) . '
        </div>';

        // Embed Risk Doughnut chart image if available
        if ($chartImg) {
            $html .= '
            <div class="image-container">
                <h3>Vizuální rizikové skóre</h3>
                <img src="' . $chartImg . '" alt="Risk Chart">
            </div>';
        }

        // Add page break for technical details
        $html .= '
        <div class="page-break"></div>
        <h2>Přehled detekovaných rizik</h2>';

        $risks = [];
        foreach ($reportData['entities'] as $e) {
            if ($e['risk_level'] !== 'informational') {
                $risks[] = $e;
            }
        }

        if (empty($risks)) {
            $html .= '<p>Nebyly detekovány žádné bezpečnostní hrozby.</p>';
        } else {
            $html .= '<table>
                <thead>
                    <tr style="background-color: rgba(255,255,255,0.02);">
                        <th style="width: 60%; color: #f1f3f9;">Nález / Riziko</th>
                        <th style="width: 20%; color: #f1f3f9;">Závažnost</th>
                    </tr>
                </thead>
                <tbody>';
            foreach ($risks as $r) {
                $badgeClass = 'badge-' . htmlspecialchars($r['risk_level']);
                $html .= '<tr>
                    <td>
                        <strong>' . htmlspecialchars(str_replace('Nález: ', '', $r['value'])) . '</strong><br>
                        <span style="color: #8b9bb4; font-size: 11px;">' . htmlspecialchars($r['description']) . '</span>
                    </td>
                    <td><span class="badge ' . $badgeClass . '">' . htmlspecialchars($r['risk_level']) . '</span></td>
                </tr>';
            }
            $html .= '</tbody>
            </table>';
        }

        // Add ARES info if company analyzer was used
        $company = null;
        foreach ($reportData['entities'] as $e) {
            if ($e['type'] === 'company') {
                $company = $e;
                break;
            }
        }
        if ($company) {
            $p = $company['payload'];
            $html .= '
            <h2>Údaje z obchodního rejstříku (ARES)</h2>
            <table>
                <tr>
                    <th>Název firmy:</th>
                    <td><strong>' . htmlspecialchars($p['name'] ?? $company['value']) . '</strong></td>
                </tr>
                <tr>
                    <th>IČO / DIČ:</th>
                    <td>' . htmlspecialchars($p['ico'] ?? '') . ' / ' . htmlspecialchars($p['dic'] ?: 'Neuvedeno') . '</td>
                </tr>
                <tr>
                    <th>Právní forma:</th>
                    <td>' . htmlspecialchars($p['legal_form'] ?? '') . '</td>
                </tr>
                <tr>
                    <th>Založeno dne:</th>
                    <td>' . htmlspecialchars($p['registration_date'] ? date('d.m.Y', strtotime($p['registration_date'])) : 'Neuvedeno') . '</td>
                </tr>
                <tr>
                    <th>Předmět činnosti:</th>
                    <td>' . htmlspecialchars($p['activity_description'] ?? '') . '</td>
                </tr>
            </table>';
        }

        // Add Graph section if graph image exists
        if ($graphImg) {
            $html .= '
            <div class="page-break"></div>
            <h2>Diagram vztahů a vazeb</h2>
            <div class="image-container">
                <img src="' . $graphImg . '" alt="Vztahový graf">
            </div>';
        }

        $html .= '
    </body>
    </html>';

    // Dompdf execution
    $options = new Options();
    $options->set('isHtml5ParserEnabled', true);
    $options->set('isRemoteEnabled', true);
    
    $dompdf = new Dompdf($options);
    $dompdf->loadHtml($html);
    $dompdf->setPaper('A4', 'portrait');
    $dompdf->render();
    
    // Stream PDF with filename
    $filename = "RightDone_Intelligence_Report_" . $reportId . ".pdf";
    $dompdf->stream($filename, ["Attachment" => false]);
    exit;

} catch (Exception $e) {
    http_response_code(500);
    echo "<h1>Chyba generování PDF</h1><p>" . htmlspecialchars($e->getMessage()) . "</p>";
    exit;
}