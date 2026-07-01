document.addEventListener('DOMContentLoaded', function() {
    // 1. Cookie Consent Banner
    const cookieBanner = document.querySelector('.cookie-banner');
    const cookieAcceptBtn = document.querySelector('.cookie-btn-accept');

    if (cookieBanner && cookieAcceptBtn) {
        if (!localStorage.getItem('cookies_accepted')) {
            setTimeout(() => {
                cookieBanner.classList.add('show');
            }, 600);

            cookieAcceptBtn.addEventListener('click', () => {
                localStorage.setItem('cookies_accepted', '1');
                cookieBanner.classList.remove('show');
            });
        }
    }

    // 2. Pricing Level Switching
    const pricingButtons = document.querySelectorAll('.pricing-level-btn');
    pricingButtons.forEach(button => {
        button.addEventListener('click', () => {
            const level = button.getAttribute('data-level');
            const currentUrl = new URL(window.location.href);
            currentUrl.searchParams.set('level', level);
            window.location.href = currentUrl.toString();
        });
    });

    // Extract Report ID if available
    const reportMeta = document.querySelector('[data-report-id]');
    const reportId = reportMeta ? reportMeta.getAttribute('data-report-id') : null;

    // 3. Cytoscape.js Relationship Graph Rendering
    const graphContainer = document.querySelector('#graph-container');
    if (graphContainer && graphContainer.getAttribute('data-elements') && typeof cytoscape !== 'undefined') {
        try {
            const graphData = JSON.parse(graphContainer.getAttribute('data-elements'));
            
            const cy = cytoscape({
                container: graphContainer,
                elements: graphData,
                boxSelectionEnabled: false,
                autounselectify: true,
                style: [
                    {
                        selector: 'node',
                        style: {
                            'label': 'data(label)',
                            'width': '50px',
                            'height': '50px',
                            'color': '#f1f3f9',
                            'font-family': 'Outfit, sans-serif',
                            'font-size': '11px',
                            'text-valign': 'bottom',
                            'text-margin-y': '8px',
                            'background-color': '#3498db',
                            'border-width': '2px',
                            'border-color': '#1b2a47',
                            'overlay-opacity': 0,
                            'transition-property': 'background-color, line-color',
                            'transition-duration': '0.3s'
                        }
                    },
                    {
                        selector: 'node.company',
                        style: {
                            'background-color': '#00d2ff',
                            'width': '65px',
                            'height': '65px',
                            'font-size': '13px',
                            'font-weight': 'bold',
                            'border-color': '#0099bc',
                            'border-width': '3px'
                        }
                    },
                    {
                        selector: 'node.person',
                        style: {
                            'background-color': '#9b59b6',
                            'border-color': '#8e44ad'
                        }
                    },
                    {
                        selector: 'node.address',
                        style: {
                            'background-color': '#95a5a6',
                            'border-color': '#7f8c8d'
                        }
                    },
                    {
                        selector: 'node.domain',
                        style: {
                            'background-color': '#f1c40f',
                            'border-color': '#f39c12'
                        }
                    },
                    {
                        selector: 'node.ip',
                        style: {
                            'background-color': '#e67e22',
                            'border-color': '#d35400'
                        }
                    },
                    {
                        selector: 'edge',
                        style: {
                            'width': 2,
                            'line-color': 'rgba(255,255,255,0.15)',
                            'target-arrow-color': 'rgba(255,255,255,0.15)',
                            'target-arrow-shape': 'triangle',
                            'curve-style': 'bezier',
                            'label': 'data(label)',
                            'color': '#8b9bb4',
                            'font-size': '9px',
                            'font-family': 'Outfit, sans-serif',
                            'text-rotation': 'autorotate',
                            'text-margin-y': '-10px'
                        }
                    }
                ],
                layout: {
                    name: 'cose',
                    animate: false,
                    padding: 30
                }
            });

            // After layout is complete and rendered, send PNG representation to server
            if (reportId) {
                cy.ready(function() {
                    setTimeout(() => {
                        const base64Image = cy.png({ bg: '#080c14', scale: 1.5, full: true });
                        fetch('index.php?action=save_graph_img&report_id=' + encodeURIComponent(reportId), {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ image: base64Image })
                        }).catch(err => console.error("Failed to save graph image:", err));
                    }, 500);
                });
            }
        } catch (e) {
            console.error("Error drawing graph:", e);
        }
    }

    // 4. Chart.js Risk Score Rendering
    const riskChartCanvas = document.querySelector('#risk-chart');
    if (riskChartCanvas && typeof Chart !== 'undefined') {
        const score = parseInt(riskChartCanvas.getAttribute('data-score') || '0', 10);
        
        let scoreColor = '#2ecc71'; // low
        if (score > 60) scoreColor = '#ff3366'; // critical
        elseif (score > 35) scoreColor = '#ff9f43'; // high
        elseif (score > 15) scoreColor = '#f1c40f'; // medium

        const chart = new Chart(riskChartCanvas, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [scoreColor, 'rgba(255, 255, 255, 0.05)'],
                    borderWidth: 0
                }]
            },
            options: {
                cutoutPercentage: 80,
                responsive: true,
                maintainAspectRatio: false,
                legend: { display: false },
                tooltips: { enabled: false },
                animation: {
                    onComplete: function() {
                        if (reportId) {
                            const chartImage = chart.toBase64Image();
                            fetch('index.php?action=save_chart_img&report_id=' + encodeURIComponent(reportId), {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ image: chartImage })
                            }).catch(err => console.error("Failed to save chart image:", err));
                        }
                    }
                }
            }
        });
    }
});