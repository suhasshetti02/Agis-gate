/* ═══════════════════════════════════════════════════════════
   AEGIS-GATE · main.js
   General UI interactions and flash auto-dismiss
   ═══════════════════════════════════════════════════════════ */

// Auto-dismiss flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', () => {
    const flashes = document.querySelectorAll('.flash-alert');
    flashes.forEach((el, i) => {
        setTimeout(() => {
            el.style.transition = 'opacity 0.5s, transform 0.5s';
            el.style.opacity = '0';
            el.style.transform = 'translateX(20px)';
            setTimeout(() => el.remove(), 500);
        }, 4000 + i * 500);
    });

    // Animate stat values on dashboard
    document.querySelectorAll('.stat-value').forEach(el => {
        const target = parseInt(el.textContent);
        if (!isNaN(target) && target > 0) {
            animateCount(el, target);
        }
    });

    // Animate risk badge ring
    document.querySelectorAll('.risk-badge[data-score]').forEach(el => {
        const score = parseFloat(el.dataset.score) || 0;
        const ring = el.querySelector('.risk-ring');
        if (ring) {
            const pct = (score * 100).toFixed(1);
            const color = score >= 0.75 ? '#ff3355' : score >= 0.45 ? '#ffb300' : '#00ff88';
            setTimeout(() => {
                ring.style.background = `conic-gradient(${color} ${pct}%, var(--border) ${pct}%)`;
                ring.style.borderRadius = '50%';
            }, 300);
        }
    });
});

function animateCount(el, target) {
    let current = 0;
    const step = Math.ceil(target / 30);
    const timer = setInterval(() => {
        current = Math.min(current + step, target);
        el.textContent = current;
        if (current >= target) clearInterval(timer);
    }, 30);
}
