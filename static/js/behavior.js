// static/js/behavior.js
/**
 * Captures non-sensitive behavioral biometrics (typing dynamics).
 * Records speed, dwell time, and flight time averages without logging actual keys.
 */
document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.querySelector('input[name="password"]');
    const hiddenInput = document.getElementById('behavioralData');
    if (!passwordInput || !hiddenInput) return;

    let keydownTimes = [];
    let keyupTimes = [];
    
    passwordInput.addEventListener('keydown', (e) => {
        // Ignore control keys to focus on character typing rhythm
        if (e.key.length === 1) {
            keydownTimes.push(Date.now());
        }
    });

    passwordInput.addEventListener('keyup', (e) => {
        if (e.key.length === 1) {
            keyupTimes.push(Date.now());
            updateBehavioralData();
        }
    });

    function updateBehavioralData() {
        if (keydownTimes.length < 3 || keyupTimes.length < 3) return;
        
        let dwellTimes = [];
        let flightTimes = [];
        
        // Calculate Dwell time (down to up for same key)
        for (let i = 0; i < Math.min(keydownTimes.length, keyupTimes.length); i++) {
            dwellTimes.push(keyupTimes[i] - keydownTimes[i]);
        }
        
        // Calculate Flight time (up of prev key to down of next key)
        for (let i = 1; i < keydownTimes.length; i++) {
            flightTimes.push(keydownTimes[i] - keyupTimes[i-1]);
        }

        const avgDwell = dwellTimes.reduce((a, b) => a + b, 0) / dwellTimes.length;
        const avgFlight = flightTimes.reduce((a, b) => a + b, 0) / flightTimes.length;
        const typingSpeed = keydownTimes.length / ((keydownTimes[keydownTimes.length - 1] - keydownTimes[0]) / 1000); // keys per second

        const data = {
            avg_dwell_ms: Math.round(avgDwell),
            avg_flight_ms: Math.round(avgFlight),
            typing_speed_kps: parseFloat(typingSpeed.toFixed(2)),
            samples: keydownTimes.length
        };
        
        hiddenInput.value = JSON.stringify(data);
    }
});
