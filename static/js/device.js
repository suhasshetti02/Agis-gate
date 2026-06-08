/* ═══════════════════════════════════════════════════════════
   AEGIS-GATE · device.js
   Browser-side device fingerprinting & Cryptography.
   Computes a stable fingerprint from browser signals and handles
   WebCrypto RSA generation and IndexedDB storage.
   ═══════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    /**
     * Collect browser signals and return a fingerprint string.
     */
    async function collectFingerprint() {
        const userAgent = navigator.userAgent;
        const platform = navigator.platform || '';
        const screenResolution = String(screen.width) + 'x' + String(screen.height);
        const language = navigator.language || '';
        const timezone = String(new Date().getTimezoneOffset());

        const raw = userAgent + platform + screenResolution + language + timezone;
        const fp = await sha256(raw);
        return fp;
    }

    /**
     * SHA-256 using WebCrypto API (if available) with a pure JS fallback.
     */
    async function sha256(str) {
        if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
            try {
                const buf = new TextEncoder().encode(str);
                const hashBuf = await crypto.subtle.digest('SHA-256', buf);
                return Array.from(new Uint8Array(hashBuf))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            } catch (e) {
                console.warn("WebCrypto SHA-256 failed, using fallback:", e);
            }
        }
        return sha256_fallback(utf8Encode(str));
    }

    function utf8Encode(str) {
        return unescape(encodeURIComponent(str));
    }

    function sha256_fallback(ascii) {
        function rightRotate(value, amount) {
            return (value >>> amount) | (value << (32 - amount));
        }
        
        var mathPow = Math.pow;
        var maxWord = mathPow(2, 32);
        var lengthProperty = 'length';
        var i, j;
        var result = '';
        var words = [];
        var asciiLength = ascii[lengthProperty];
        var hash = sha256_fallback.h = sha256_fallback.h || [];
        var k = sha256_fallback.k = sha256_fallback.k || [];
        var primeCounter = k[lengthProperty];

        var isPrime = {};
        for (var candidate = 2; primeCounter < 64; candidate++) {
            if (!isPrime[candidate]) {
                for (i = 0; i < 313; i += candidate) {
                    isPrime[i] = 1;
                }
                hash[primeCounter] = (mathPow(candidate, .5)*maxWord)|0;
                k[primeCounter++] = (mathPow(candidate, 1/3)*maxWord)|0;
            }
        }
        
        ascii += '\x80';
        while (ascii[lengthProperty] % 64 - 56) ascii += '\x00';
        for (i = 0; i < ascii[lengthProperty]; i++) {
            j = ascii.charCodeAt(i);
            if (j >> 8) return; // ASCII only check
            words[i >> 2] |= j << ((3 - i % 4) * 8);
        }
        words[words[lengthProperty]] = ((asciiLength * 8) / maxWord) | 0;
        words[words[lengthProperty]] = (asciiLength * 8);
        
        for (j = 0; j < words[lengthProperty];) {
            var w = words.slice(j, j += 16);
            var oldHash = hash.slice(0);
            hash = hash.slice(0, 8);
            
            for (i = 0; i < 64; i++) {
                var wItem = w[i];
                if (i >= 16) {
                    var s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
                    var s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
                    wItem = w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
                }
                
                var ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
                var maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
                var sigma0 = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
                var sigma1 = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);
                
                var temp1 = (hash[7] + sigma1 + ch + k[i] + (wItem || 0)) | 0;
                var temp2 = (sigma0 + maj) | 0;
                
                hash = [(temp1 + temp2) | 0].concat(hash);
                hash[4] = (hash[4] + temp1) | 0;
            }
            
            for (i = 0; i < 8; i++) {
                hash[i] = (hash[i] + oldHash[i]) | 0;
            }
        }
        
        for (i = 0; i < 8; i++) {
            var hex = (hash[i] >>> 0).toString(16);
            result += hex.padStart(8, '0');
        }
        return result;
    }

    /**
     * Get a human-readable device name from UA.
     */
    function getDeviceName() {
        const ua = navigator.userAgent;
        if (/Windows NT 10/.test(ua)) return 'Windows 10 PC';
        if (/Windows NT 11/.test(ua)) return 'Windows 11 PC';
        if (/Windows/.test(ua))       return 'Windows PC';
        if (/Macintosh/.test(ua))     return 'Mac';
        if (/Android/.test(ua))       return 'Android Device';
        if (/iPhone/.test(ua))        return 'iPhone';
        if (/Linux/.test(ua))         return 'Linux PC';
        return 'Unknown Device';
    }

    /**
     * Check device status with server and update status bar.
     */
    async function checkDeviceStatus(fp) {
        try {
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
            const res = await fetch('/api/device-status', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ device_fingerprint: fp })
            });
            return await res.json();
        } catch (_) {
            return null;
        }
    }

    /**
     * Update the device status bar in the login form.
     */
    function updateStatusBar(status, fp) {
        const bar   = document.getElementById('deviceStatus');
        const dot   = bar?.querySelector('.ds-dot');
        const label = bar?.querySelector('.ds-label');
        if (!bar || !dot || !label) return;

        if (!status) {
            dot.className   = 'ds-dot ds-unknown';
            label.textContent = 'Device scan failed';
            return;
        }

        if (status.blocked) {
            dot.className   = 'ds-dot ds-unknown';
            label.textContent = '⛔ This device is blocked';
        } else if (status.registered && status.trusted) {
            dot.className   = 'ds-dot ds-ready';
            label.textContent = `✓ Trusted device · Trust ${Math.round(status.trust_score * 100)}%`;
        } else if (status.registered) {
            dot.className   = 'ds-dot ds-ready';
            label.textContent = `Device recognized · Trust ${Math.round(status.trust_score * 100)}%`;
        } else {
            dot.className   = 'ds-dot ds-unknown';
            label.textContent = '⚠ New device — OTP registration required';
        }
    }

    // ── Cryptographic operations ────────────────────────────────

    const DB_NAME = 'AegisGateCryptoDB';
    const DB_VERSION = 1;
    const STORE_NAME = 'keys';

    function openCryptoDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME);
                }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }

    async function storePrivateKey(fp, key) {
        const db = await openCryptoDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            const req = store.put(key, fp);
            req.onsuccess = () => resolve();
            req.onerror = () => reject(req.error);
        });
    }

    async function getPrivateKey(fp) {
        const db = await openCryptoDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readonly');
            const store = tx.objectStore(STORE_NAME);
            const req = store.get(fp);
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }

    async function generateDeviceKeyPair() {
        if (!window.crypto || !window.crypto.subtle || !window.crypto.subtle.generateKey) {
            console.warn("Insecure context: using mock RSA key generation fallback.");
            return {
                privateKey: "mock_private_key",
                publicKeyPem: "mock_public_key"
            };
        }

        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-PSS",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            false, // non-extractable private key
            ["sign", "verify"]
        );
        
        // Export public key to SPKI format
        const spki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
        const spkiArray = new Uint8Array(spki);
        let binaryString = '';
        for (let i = 0; i < spkiArray.byteLength; i++) {
            binaryString += String.fromCharCode(spkiArray[i]);
        }
        const spkiB64 = btoa(binaryString);
        
        // Format as PEM for the Python backend
        const pubPem = `-----BEGIN PUBLIC KEY-----\n${spkiB64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
        
        return {
            privateKey: keyPair.privateKey,
            publicKeyPem: pubPem
        };
    }

    async function signChallenge(privateKey, challengeStr) {
        if (privateKey === "mock_private_key") {
            console.warn("Insecure context: signing challenge using mock signature fallback.");
            return btoa("mock_signature_for:" + challengeStr);
        }

        const enc = new TextEncoder();
        const data = enc.encode(challengeStr);
        const signature = await window.crypto.subtle.sign(
            {
                name: "RSA-PSS",
                saltLength: 32
            },
            privateKey,
            data
        );
        const sigArray = new Uint8Array(signature);
        let binaryString = '';
        for (let i = 0; i < sigArray.byteLength; i++) {
            binaryString += String.fromCharCode(sigArray[i]);
        }
        return btoa(binaryString);
    }

    window.AegisCrypto = {
        generateDeviceKeyPair,
        storePrivateKey,
        getPrivateKey,
        signChallenge
    };

    // ── Main init ──────────────────────────────────────────────

    document.addEventListener('DOMContentLoaded', async () => {
        const fpField   = document.getElementById('deviceFingerprint');
        const nameField = document.getElementById('deviceName');

        if (!fpField) return;   // Not a login/register form

        const fp   = await collectFingerprint();
        const name = getDeviceName();

        fpField.value   = fp;
        if (nameField) nameField.value = name;

        // Persist for challenge page
        localStorage.setItem('aegis_device_fp', fp);

        // Warn if in insecure context
        const isInsecure = !window.crypto || !window.crypto.subtle || !window.crypto.subtle.generateKey;
        if (isInsecure) {
            console.warn("AEGIS-GATE: Operating in insecure context. Mock Cryptography Fallback is active.");
            const logFn = window.logToTerminal || (typeof logToTerminal !== 'undefined' ? logToTerminal : null);
            if (logFn) {
                logFn("⚠️ Insecure Context: WebCrypto disabled. Using mock cryptography fallback.", "warn");
            }
        }

        // Ask server about this device
        const status = await checkDeviceStatus(fp);
        updateStatusBar(status, fp);
    });

})();
