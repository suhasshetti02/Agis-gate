/* ═══════════════════════════════════════════════════════════
   AEGIS-GATE · admin_charts.js
   Renders login activity + risk distribution charts
   on the admin dashboard using Chart.js.
   ═══════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', async () => {
    let stats;
    try {
        const res = await fetch('/admin/api/stats');
        stats = await res.json();
    } catch (e) {
        console.error('Failed to load chart data:', e);
        return;
    }

    const COLORS = {
        cyan:   '#00e5ff',
        green:  '#00ff88',
        red:    '#ff3355',
        amber:  '#ffb300',
        dim:    '#1e2d3d',
        text:   '#6a8a9f',
        grid:   '#1e2d3d',
    };

    Chart.defaults.color = COLORS.text;
    Chart.defaults.borderColor = COLORS.grid;

    // ── Activity Bar Chart ──────────────────────────────────

    const activityCtx = document.getElementById('activityChart');
    if (activityCtx && stats.daily) {
        // Aggregate by day
        const dayMap = {};
        stats.daily.forEach(r => {
            if (!dayMap[r.day]) dayMap[r.day] = { success: 0, fail: 0, blocked: 0 };
            const key = r.status.startsWith('fail') ? 'fail' :
                        r.status.startsWith('block') ? 'blocked' : 'success';
            dayMap[r.day][key] += r.cnt;
        });

        const labels = Object.keys(dayMap).sort();
        const successData = labels.map(d => dayMap[d].success || 0);
        const failData    = labels.map(d => dayMap[d].fail    || 0);
        const blockData   = labels.map(d => dayMap[d].blocked || 0);

        new Chart(activityCtx, {
            type: 'bar',
            data: {
                labels,
                datasets: [
                    {
                        label: 'Allowed',
                        data: successData,
                        backgroundColor: 'rgba(0,255,136,0.5)',
                        borderColor: COLORS.green,
                        borderWidth: 1,
                        borderRadius: 3,
                    },
                    {
                        label: 'Failed',
                        data: failData,
                        backgroundColor: 'rgba(255,179,0,0.4)',
                        borderColor: COLORS.amber,
                        borderWidth: 1,
                        borderRadius: 3,
                    },
                    {
                        label: 'Blocked',
                        data: blockData,
                        backgroundColor: 'rgba(255,51,85,0.4)',
                        borderColor: COLORS.red,
                        borderWidth: 1,
                        borderRadius: 3,
                    },
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { boxWidth: 12, padding: 16 } }
                },
                scales: {
                    x: { grid: { color: COLORS.grid }, ticks: { font: { family: 'Share Tech Mono', size: 10 } } },
                    y: { grid: { color: COLORS.grid }, beginAtZero: true, ticks: { font: { family: 'Share Tech Mono', size: 10 } } }
                }
            }
        });
    }

    // ── Risk Doughnut Chart ─────────────────────────────────

    const riskCtx = document.getElementById('riskChart');
    if (riskCtx && stats.risk_dist) {
        const riskLabels = stats.risk_dist.map(r => r.category);
        const riskData   = stats.risk_dist.map(r => r.cnt);
        const colorMap   = { 'Low': COLORS.green, 'Medium': COLORS.amber, 'High': COLORS.red };
        const bgColors   = riskLabels.map(l => colorMap[l] || COLORS.cyan);

        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: riskLabels,
                datasets: [{
                    data: riskData,
                    backgroundColor: bgColors.map(c => c + '55'),
                    borderColor: bgColors,
                    borderWidth: 2,
                    hoverOffset: 8,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: { position: 'bottom', labels: { boxWidth: 12, padding: 16, font: { family: 'Share Tech Mono', size: 11 } } }
                }
            }
        });
    }
});
