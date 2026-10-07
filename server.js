const express = require('express');
const path = require('path');
const https = require('node:https');
const http = require('node:http');
const tls = require('node:tls');
const dns = require('node:dns');
const dnsPromises = dns.promises;
const net = require('node:net');
const { URL } = require('node:url');

// Configure reliable public DNS resolvers
try {
  dns.setServers(['1.1.1.1', '8.8.8.8', '1.0.0.1']);
} catch (e) {
  // ignore if system limits prevent custom dns
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// SSRF & Target Validation Helper
// ==========================================
function isPrivateIP(ip) {
  if (!ip) return false;
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts[0] === 127) return true; // Loopback
    if (parts[0] === 10) return true;  // Class A
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // Class B
    if (parts[0] === 192 && parts[1] === 168) return true; // Class C
    if (parts[0] === 169 && parts[1] === 254) return true; // Link-local / Cloud metadata
    if (parts[0] === 0) return true;
  } else if (net.isIPv6(ip)) {
    if (ip === '::1' || ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip.startsWith('fd00:')) {
      return true;
    }
  }
  return false;
}

// Clean and normalize target URL
function normalizeTarget(rawInput) {
  let target = rawInput.trim();
  if (!/^https?:\/\//i.test(target)) {
    target = 'https://' + target;
  }
  const parsed = new URL(target);
  return {
    fullUrl: parsed.href,
    protocol: parsed.protocol,
    hostname: parsed.hostname.toLowerCase(),
    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
    pathname: parsed.pathname || '/'
  };
}

// Helper to extract apex/organizational domain (e.g. www.google.com -> google.com, sub.domain.co.id -> domain.co.id)
function getApexDomain(hostname) {
  if (!hostname) return '';
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return hostname;

  const multiPartTlds = [
    'co.id', 'go.id', 'ac.id', 'mil.id', 'sch.id', 'or.id', 'net.id', 'biz.id', 'my.id',
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.jp', 'ne.jp', 'ac.jp', 'go.jp',
    'com.br', 'gov.br', 'org.br',
    'com.sg', 'edu.sg', 'gov.sg'
  ];

  const lastTwo = parts.slice(-2).join('.');
  if (multiPartTlds.includes(lastTwo)) {
    if (parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return hostname;
  }

  return parts.slice(-2).join('.');
}

// ==========================================
// 1. SSL/TLS Certificate & Cipher Inspector
// ==========================================
function inspectTLS(hostname, port = 443, timeout = 7500) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    let isResolved = false;

    const socket = tls.connect(
      {
        host: hostname,
        port: port,
        servername: hostname, // SNI support
        rejectUnauthorized: false, // We inspect even self-signed / expired certs
        timeout: timeout
      },
      () => {
        if (isResolved) return;
        isResolved = true;

        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const authorized = socket.authorized;
        const authError = socket.authorizationError;

        socket.end();

        if (!cert || Object.keys(cert).length === 0) {
          return resolve({
            supported: true,
            hasCert: false,
            error: 'Tidak ada sertifikat SSL/TLS yang dikembalikan oleh host target.'
          });
        }

        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        const isExpired = now > validTo;
        const isNotYetValid = now < validFrom;

        // Protocol strength evaluation
        let protocolRating = 'STRONG';
        if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
          protocolRating = 'DEPRECATED_VULNERABLE';
        } else if (protocol === 'TLSv1.2') {
          protocolRating = 'ACCEPTABLE';
        } else if (protocol === 'TLSv1.3') {
          protocolRating = 'MODERN_STRONG';
        }

        resolve({
          supported: true,
          protocol,
          protocolRating,
          cipher: cipher ? cipher.name : 'Unknown',
          cipherVersion: cipher ? cipher.version : 'Unknown',
          authorized,
          authError: authError || null,
          subject: cert.subject ? cert.subject.CN || cert.subject.O || hostname : hostname,
          issuer: cert.issuer ? cert.issuer.O || cert.issuer.CN || 'Unknown CA' : 'Unknown',
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysRemaining,
          isExpired,
          isNotYetValid,
          altNames: cert.subjectaltname || 'None',
          fingerprint256: cert.fingerprint256 || cert.fingerprint || null,
          bits: cert.bits || null,
          responseTimeMs: Date.now() - startTime
        });
      }
    );

    socket.on('timeout', () => {
      if (!isResolved) {
        isResolved = true;
        socket.destroy();
        resolve({
          supported: false,
          error: `TLS handshake connection timed out (port ${port} tidak merespons)`
        });
      }
    });

    socket.on('error', (err) => {
      if (!isResolved) {
        isResolved = true;
        socket.destroy();
        resolve({
          supported: false,
          error: err.message
        });
      }
    });
  });
}

// ==========================================
// 2. HTTP to HTTPS Redirection Inspector
// ==========================================
function inspectHttpRedirect(hostname, timeout = 6000) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: hostname,
        port: 80,
        path: '/',
        method: 'GET',
        headers: {
          'User-Agent': 'CyberTrack-SecurityAudit/1.0 (+https://cybertrack.local)',
          'Accept': '*/*'
        },
        timeout: timeout
      },
      (res) => {
        const statusCode = res.statusCode;
        const location = res.headers['location'] || null;
        let redirectsToHttps = false;
        let isPermanent = statusCode === 301 || statusCode === 308;

        if (location && /^https:\/\//i.test(location)) {
          redirectsToHttps = true;
        }

        res.resume(); // consume stream
        resolve({
          httpAvailable: true,
          statusCode,
          location,
          redirectsToHttps,
          isPermanent
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ httpAvailable: false, reason: 'Port 80 timeout' });
    });

    req.on('error', (err) => {
      resolve({ httpAvailable: false, reason: err.message });
    });

    req.end();
  });
}

// ==========================================
// 3. HTTP Headers, Cookies & Redirect Follower
// ==========================================
function fetchUrlHeadersWithRedirects(targetUrl, maxRedirects = 5, timeout = 7500, accumulatedCookies = [], redirectChain = []) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch (e) {
      return resolve({ error: 'Invalid URL: ' + targetUrl });
    }

    const client = parsed.protocol === 'https:' ? https : http;
    redirectChain.push({ url: targetUrl, protocol: parsed.protocol });

    const req = client.request(
      parsed,
      {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberTrack-Security-Scanner/1.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Cache-Control': 'no-cache'
        },
        rejectUnauthorized: false,
        timeout: timeout
      },
      (res) => {
        const rawHeaders = res.headers;

        // Parse cookies from this hop
        const setCookie = rawHeaders['set-cookie'];
        if (setCookie) {
          const cookieStrings = Array.isArray(setCookie) ? setCookie : [setCookie];
          cookieStrings.forEach((c) => {
            const parts = c.split(';').map((p) => p.trim());
            const nameValue = parts[0].split('=');
            const name = nameValue[0];
            const lowerParts = parts.map((p) => p.toLowerCase());

            const isSecure = lowerParts.includes('secure');
            const isHttpOnly = lowerParts.includes('httponly');
            let sameSite = 'None/Not Specified';
            const sameSitePart = lowerParts.find((p) => p.startsWith('samesite='));
            if (sameSitePart) {
              sameSite = sameSitePart.split('=')[1] || 'Unknown';
            }

            accumulatedCookies.push({
              name,
              secure: isSecure,
              httpOnly: isHttpOnly,
              sameSite: sameSite,
              raw: c
            });
          });
        }

        // Check if redirect
        const statusCode = res.statusCode;
        const location = rawHeaders['location'];

        if ([301, 302, 303, 307, 308].includes(statusCode) && location && maxRedirects > 0) {
          res.resume();
          try {
            const nextUrl = new URL(location, targetUrl).href;
            return resolve(fetchUrlHeadersWithRedirects(nextUrl, maxRedirects - 1, timeout, accumulatedCookies, redirectChain));
          } catch (err) {
            // fallback to current if invalid location
          }
        }

        // Drain response
        res.on('data', () => {});
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            finalUrl: targetUrl,
            headers: rawHeaders,
            cookies: accumulatedCookies,
            redirectChain
          });
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ error: 'Request timeout waiting for target server response.' });
    });

    req.on('error', (err) => {
      resolve({ error: err.message });
    });

    req.end();
  });
}

// Check RFC 9116 security.txt
function checkSecurityTxt(hostname, timeout = 4000) {
  return new Promise((resolve) => {
    const req = https.request(
      `https://${hostname}/.well-known/security.txt`,
      {
        method: 'HEAD',
        headers: { 'User-Agent': 'CyberTrack-SecurityAudit/1.0' },
        rejectUnauthorized: false,
        timeout
      },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      }
    );
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.end();
  });
}

// ==========================================
// 4. DNS, SPF & DMARC Inspector with Apex Fallback
// ==========================================
async function inspectDNS(hostname) {
  const apexDomain = getApexDomain(hostname);
  const result = {
    hostname,
    apexDomain,
    ipAddresses: [],
    spf: { present: false, record: null, status: 'MISSING', checkedDomain: hostname },
    dmarc: { present: false, record: null, policy: 'MISSING', status: 'MISSING', checkedDomain: hostname },
    mxRecords: []
  };

  // 1. IP Lookup
  try {
    const lookupResults = await dnsPromises.lookup(hostname, { all: true }).catch(() => []);
    result.ipAddresses = lookupResults.map((r) => r.address);
  } catch (e) {
    // ignore
  }

  // 2. MX Records (query hostname, fallback to apex)
  try {
    let mx = await dnsPromises.resolveMx(hostname).catch(() => []);
    if (mx.length === 0 && apexDomain !== hostname) {
      mx = await dnsPromises.resolveMx(apexDomain).catch(() => []);
    }
    result.mxRecords = mx;
  } catch (e) {
    // ignore
  }

  // 3. SPF Records (query hostname, fallback to apex if not found)
  try {
    let spfRecord = null;
    let checkedDomain = hostname;

    const txtHost = await dnsPromises.resolveTxt(hostname).catch(() => []);
    const flatHost = txtHost.map((c) => c.join(''));
    spfRecord = flatHost.find((r) => r.startsWith('v=spf1'));

    if (!spfRecord && apexDomain !== hostname) {
      const txtApex = await dnsPromises.resolveTxt(apexDomain).catch(() => []);
      const flatApex = txtApex.map((c) => c.join(''));
      spfRecord = flatApex.find((r) => r.startsWith('v=spf1'));
      if (spfRecord) checkedDomain = apexDomain;
    }

    if (spfRecord) {
      result.spf.present = true;
      result.spf.record = spfRecord;
      result.spf.checkedDomain = checkedDomain;

      if (spfRecord.includes('-all')) {
        result.spf.status = 'STRICT_HARDFAIL'; // Recommended
      } else if (spfRecord.includes('~all')) {
        result.spf.status = 'SOFTFAIL'; // Acceptable
      } else if (spfRecord.includes('+all') || spfRecord.includes('?all')) {
        result.spf.status = 'PERMISSIVE_VULNERABLE'; // Ineffective
      } else {
        result.spf.status = 'NEUTRAL';
      }
    }
  } catch (e) {
    // ignore
  }

  // 4. DMARC Records (RFC 7489: query _dmarc.hostname, fallback to _dmarc.apexDomain)
  try {
    let dmarcRecord = null;
    let checkedDomain = hostname;

    const dmarcHost = await dnsPromises.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
    const flatDmarcHost = dmarcHost.map((c) => c.join(''));
    dmarcRecord = flatDmarcHost.find((r) => r.startsWith('v=DMARC1'));

    if (!dmarcRecord && apexDomain !== hostname) {
      const dmarcApex = await dnsPromises.resolveTxt(`_dmarc.${apexDomain}`).catch(() => []);
      const flatDmarcApex = dmarcApex.map((c) => c.join(''));
      dmarcRecord = flatDmarcApex.find((r) => r.startsWith('v=DMARC1'));
      if (dmarcRecord) checkedDomain = apexDomain;
    }

    if (dmarcRecord) {
      result.dmarc.present = true;
      result.dmarc.record = dmarcRecord;
      result.dmarc.checkedDomain = checkedDomain;

      const pMatch = dmarcRecord.match(/p=([a-zA-Z]+)/i);
      const policy = pMatch ? pMatch[1].toLowerCase() : 'unknown';
      result.dmarc.policy = policy;

      if (policy === 'reject') {
        result.dmarc.status = 'REJECT_STRONG';
      } else if (policy === 'quarantine') {
        result.dmarc.status = 'QUARANTINE_MODERATE';
      } else if (policy === 'none') {
        result.dmarc.status = 'MONITOR_ONLY_NONE';
      }
    }
  } catch (e) {
    // ignore
  }

  return result;
}

// ==========================================
// 5. Complete Audit & Scoring Engine
// ==========================================
function evaluateSecurityPosture({ targetInfo, tlsResult, redirectResult, headersResult, dnsResult, hasSecurityTxt }) {
  const findings = [];
  let score = 100;
  const headers = headersResult.headers || {};

  function addFinding({ id, category, title, severity, penalty, passed, details, recommendation, owasp, snippets }) {
    if (!passed) {
      score = Math.max(0, score - penalty);
    }
    findings.push({
      id,
      category,
      title,
      severity,
      penalty: passed ? 0 : penalty,
      passed,
      details,
      recommendation,
      owasp,
      snippets: snippets || {}
    });
  }

  // --- A. Transport Layer & HTTPS ---
  if (!tlsResult.supported) {
    addFinding({
      id: 'tls-supported',
      category: 'Transport Security',
      title: 'HTTPS & TLS Support Tidak Aktif',
      severity: 'CRITICAL',
      penalty: 35,
      passed: false,
      details: `Website tidak merespons pada port HTTPS (443) atau jabat tangan TLS gagal: ${tlsResult.error || 'Connection Refused'}.`,
      recommendation: 'Pasang sertifikat SSL/TLS valid (misal: Let\'s Encrypt / Cloudflare) dan aktifkan protokol HTTPS pada port 443.',
      owasp: 'A02:2021 - Cryptographic Failures',
      snippets: {
        nginx: '# Install Certbot & configure Nginx for SSL:\nsudo certbot --nginx -d example.com'
      }
    });
  } else {
    // 1. Certificate Authenticity / Authorization check
    if (!tlsResult.authorized) {
      addFinding({
        id: 'tls-untrusted',
        category: 'Transport Security',
        title: 'Sertifikat SSL/TLS Tidak Tepercaya / Invalid CA',
        severity: 'CRITICAL',
        penalty: 30,
        passed: false,
        details: `Sertifikat ditolak oleh verifikasi trust store: ${tlsResult.authError || 'Self-Signed / Untrusted CA'}. Browser pengunjung akan memblokir akses ke situs dengan layar merah.`,
        recommendation: 'Ganti dengan sertifikat SSL/TLS resmi yang diterbitkan oleh Certificate Authority (CA) tepercaya.',
        owasp: 'A02:2021 - Cryptographic Failures'
      });
    }

    // 2. Expiration check
    if (tlsResult.isExpired) {
      addFinding({
        id: 'tls-expired',
        category: 'Transport Security',
        title: 'Sertifikat SSL/TLS Kedaluwarsa (Expired)',
        severity: 'CRITICAL',
        penalty: 30,
        passed: false,
        details: `Sertifikat kedaluwarsa pada ${tlsResult.validTo}. Pengunjung akan disambut peringatan bahaya keamanan dari browser.`,
        recommendation: 'Segera perbarui sertifikat SSL/TLS domain Anda.',
        owasp: 'A02:2021 - Cryptographic Failures'
      });
    } else if (tlsResult.daysRemaining <= 14) {
      addFinding({
        id: 'tls-expiring-soon',
        category: 'Transport Security',
        title: 'Sertifikat SSL/TLS Segera Kedaluwarsa',
        severity: 'MEDIUM',
        penalty: 8,
        passed: false,
        details: `Sertifikat akan kedaluwarsa dalam ${tlsResult.daysRemaining} hari (${tlsResult.validTo}).`,
        recommendation: 'Jalankan auto-renew sertifikat (misal: certbot renew) sebelum kedaluwarsa.',
        owasp: 'A02:2021 - Cryptographic Failures'
      });
    } else if (tlsResult.authorized) {
      addFinding({
        id: 'tls-valid',
        category: 'Transport Security',
        title: 'Sertifikat SSL/TLS Aktif & Tepercaya',
        severity: 'PASS',
        penalty: 0,
        passed: true,
        details: `Sertifikat diterbitkan oleh ${tlsResult.issuer}, berlaku hingga ${tlsResult.validTo} (${tlsResult.daysRemaining} hari tersisa).`,
        recommendation: 'Sertifikat dalam kondisi prima dan valid.',
        owasp: 'A02:2021 - Cryptographic Failures'
      });
    }

    // 3. Protocol strength check
    if (tlsResult.protocolRating === 'DEPRECATED_VULNERABLE') {
      addFinding({
        id: 'tls-protocol',
        category: 'Transport Security',
        title: `Protokol TLS Usang & Rentan (${tlsResult.protocol})`,
        severity: 'HIGH',
        penalty: 15,
        passed: false,
        details: `Server menggunakan versi TLS usang (${tlsResult.protocol}) yang rentan terhadap serangan downgrade (seperti POODLE/BEAST).`,
        recommendation: 'Nonaktifkan TLSv1.0 dan TLSv1.1 pada web server. Gunakan minimal TLSv1.2 atau TLSv1.3.',
        owasp: 'A02:2021 - Cryptographic Failures',
        snippets: {
          nginx: 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;'
        }
      });
    } else {
      addFinding({
        id: 'tls-protocol-modern',
        category: 'Transport Security',
        title: `Protokol Enkripsi Modern (${tlsResult.protocol})`,
        severity: 'PASS',
        penalty: 0,
        passed: true,
        details: `Server menegosiasikan protokol modern ${tlsResult.protocol} dengan cipher ${tlsResult.cipher}.`,
        recommendation: 'Pertahankan konfigurasi enkripsi kuat.',
        owasp: 'A02:2021 - Cryptographic Failures'
      });
    }
  }

  // --- B. HTTP to HTTPS Redirection ---
  if (redirectResult.httpAvailable) {
    if (redirectResult.redirectsToHttps) {
      addFinding({
        id: 'http-redirect',
        category: 'Transport Security',
        title: 'Redirect Otomatis HTTP ke HTTPS',
        severity: 'PASS',
        penalty: 0,
        passed: true,
        details: `Permintaan port 80 (HTTP) dialihkan secara aman ke HTTPS (Status ${redirectResult.statusCode} -> ${redirectResult.location}).`,
        recommendation: 'Sangat baik, mencegah transmisi data plaintext.',
        owasp: 'A02:2021 - Cryptographic Failures'
      });
    } else {
      addFinding({
        id: 'http-redirect-missing',
        category: 'Transport Security',
        title: 'Tidak Ada Enforce Redirect HTTP ke HTTPS',
        severity: 'HIGH',
        penalty: 15,
        passed: false,
        details: `Permintaan ke http://${targetInfo.hostname} tidak otomatis diarahkan ke https:// (Status ${redirectResult.statusCode}). Data pengguna rentan disadap (Man-in-the-Middle) di jaringan publik.`,
        recommendation: 'Tambahkan aturan redirect permanen (301) dari HTTP ke HTTPS.',
        owasp: 'A02:2021 - Cryptographic Failures',
        snippets: {
          nginx: 'server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}',
          apache: 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]'
        }
      });
    }
  }

  // --- C. HTTP Security Headers Audit ---

  // 1. Strict-Transport-Security (HSTS)
  const hsts = headers['strict-transport-security'];
  if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    const hasSubDomains = /includesubdomains/i.test(hsts);
    const hasPreload = /preload/i.test(hsts);

    if (maxAge >= 15552000) {
      addFinding({
        id: 'header-hsts',
        category: 'HTTP Security Headers',
        title: 'Strict-Transport-Security (HSTS) Diterapkan Kuat',
        severity: 'PASS',
        penalty: 0,
        passed: true,
        details: `Header HSTS aktif dengan max-age=${maxAge}s (${Math.round(maxAge / 86400)} hari). Subdomains: ${hasSubDomains}, Preload: ${hasPreload}.`,
        recommendation: 'Konfigurasi HSTS prima untuk mencegah SSL Stripping.',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    } else {
      addFinding({
        id: 'header-hsts-weak',
        category: 'HTTP Security Headers',
        title: 'HSTS Max-Age Terlalu Pendek',
        severity: 'LOW',
        penalty: 5,
        passed: false,
        details: `HSTS aktif namun durasi max-age (${maxAge} detik) disarankan minimal 1 tahun (31536000 detik).`,
        recommendation: 'Tingkatkan nilai max-age HSTS menjadi setidaknya 31536000.',
        owasp: 'A05:2021 - Security Misconfiguration',
        snippets: {
          nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;'
        }
      });
    }
  } else {
    addFinding({
      id: 'header-hsts-missing',
      category: 'HTTP Security Headers',
      title: 'Header HSTS (Strict-Transport-Security) Tidak Ada',
      severity: 'HIGH',
      penalty: 15,
      passed: false,
      details: 'Browser tidak dipaksa untuk selalu terhubung via HTTPS. Penyerang di jaringan yang sama dapat melakukan serangan SSL Stripping.',
      recommendation: 'Aktifkan header HSTS pada konfigurasi server Anda.',
      owasp: 'A05:2021 - Security Misconfiguration',
      snippets: {
        nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
        express: 'const helmet = require("helmet");\napp.use(helmet.hsts({ maxAge: 31536000 }));'
      }
    });
  }

  // 2. Content-Security-Policy (CSP)
  const csp = headers['content-security-policy'];
  if (csp) {
    const hasUnsafeInline = /'unsafe-inline'/i.test(csp);
    const hasUnsafeEval = /'unsafe-eval'/i.test(csp);

    if (hasUnsafeInline || hasUnsafeEval) {
      addFinding({
        id: 'header-csp-loose',
        category: 'HTTP Security Headers',
        title: 'CSP Menggunakan Aturan Permisif (unsafe-inline / unsafe-eval)',
        severity: 'MEDIUM',
        penalty: 7,
        passed: false,
        details: `Content-Security-Policy terdeteksi, namun mengandung ${hasUnsafeInline ? "'unsafe-inline'" : ''} ${hasUnsafeEval ? "'unsafe-eval'" : ''} yang dapat menurunkan efektivitas proteksi injeksi skrip.`,
        recommendation: 'Gunakan Nonce atau SHA hash untuk script inline daripada izin wildcard unsafe-inline.',
        owasp: 'A03:2021 - Injection'
      });
    } else {
      addFinding({
        id: 'header-csp',
        category: 'HTTP Security Headers',
        title: 'Content-Security-Policy (CSP) Aktif & Ketat',
        severity: 'PASS',
        penalty: 0,
        passed: true,
        details: 'CSP dikonfigurasi dengan baik untuk mencegah serangan Cross-Site Scripting (XSS) dan injeksi data.',
        recommendation: 'Pertahankan kebijakan CSP.',
        owasp: 'A03:2021 - Injection'
      });
    }
  } else {
    addFinding({
      id: 'header-csp-missing',
      category: 'HTTP Security Headers',
      title: 'Content-Security-Policy (CSP) Belum Dikonfigurasi',
      severity: 'HIGH',
      penalty: 14,
      passed: false,
      details: 'Tidak ada CSP yang membatasi asal resource (script, styles, images). Membuka celah bagi serangan Cross-Site Scripting (XSS) dan Data Injection.',
      recommendation: 'Definisikan kebijakan CSP untuk membatasi eksekusi skrip pihak ketiga yang tidak tepercaya.',
      owasp: 'A03:2021 - Injection',
      snippets: {
        nginx: 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';" always;',
        apache: 'Header set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';"',
        express: 'const helmet = require("helmet");\napp.use(helmet.contentSecurityPolicy());'
      }
    });
  }

  // 3. X-Frame-Options (Clickjacking)
  const xfo = headers['x-frame-options'];
  if (xfo && (xfo.toUpperCase() === 'DENY' || xfo.toUpperCase() === 'SAMEORIGIN')) {
    addFinding({
      id: 'header-xfo',
      category: 'HTTP Security Headers',
      title: `X-Frame-Options Aktif (${xfo.toUpperCase()})`,
      severity: 'PASS',
      penalty: 0,
      passed: true,
      details: `Website terlindungi dari teknik pembajakan klik (Clickjacking / UI Redressing) dengan nilai "${xfo}".`,
      recommendation: 'Proteksi Clickjacking aktif.',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  } else {
    addFinding({
      id: 'header-xfo-missing',
      category: 'HTTP Security Headers',
      title: 'Proteksi Clickjacking (X-Frame-Options) Tidak Ditemukan',
      severity: 'MEDIUM',
      penalty: 10,
      passed: false,
      details: 'Halaman web dapat di-embed ke dalam iframe situs asing milik penyerang untuk memanipulasi klik pengguna (Clickjacking).',
      recommendation: 'Tambahkan header X-Frame-Options: DENY atau SAMEORIGIN.',
      owasp: 'A05:2021 - Security Misconfiguration',
      snippets: {
        nginx: 'add_header X-Frame-Options "SAMEORIGIN" always;',
        apache: 'Header always set X-Frame-Options "SAMEORIGIN"',
        express: 'app.use((req, res, next) => { res.setHeader("X-Frame-Options", "SAMEORIGIN"); next(); });'
      }
    });
  }

  // 4. X-Content-Type-Options (MIME Sniffing)
  const xcto = headers['x-content-type-options'];
  if (xcto && xcto.toLowerCase() === 'nosniff') {
    addFinding({
      id: 'header-xcto',
      category: 'HTTP Security Headers',
      title: 'X-Content-Type-Options: nosniff Aktif',
      severity: 'PASS',
      penalty: 0,
      passed: true,
      details: 'Browser dilarang melakukan MIME-type sniffing, mencegah eksekusi file berbahaya yang disamarkan sebagai gambar atau teks.',
      recommendation: 'Proteksi MIME sniffing aktif.',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  } else {
    addFinding({
      id: 'header-xcto-missing',
      category: 'HTTP Security Headers',
      title: 'X-Content-Type-Options Tidak Ditemukan',
      severity: 'MEDIUM',
      penalty: 7,
      passed: false,
      details: 'Tanpa nosniff, browser dapat mencoba menebak tipe konten secara mandiri dan berpotensi mengeksekusi file berbahaya sebagai skrip.',
      recommendation: 'Tambahkan header X-Content-Type-Options: nosniff.',
      owasp: 'A05:2021 - Security Misconfiguration',
      snippets: {
        nginx: 'add_header X-Content-Type-Options "nosniff" always;',
        apache: 'Header always set X-Content-Type-Options "nosniff"'
      }
    });
  }

  // 5. Referrer-Policy
  const refPol = headers['referrer-policy'];
  if (refPol) {
    addFinding({
      id: 'header-referrer-policy',
      category: 'HTTP Security Headers',
      title: `Referrer-Policy Dikonfigurasi (${refPol})`,
      severity: 'PASS',
      penalty: 0,
      passed: true,
      details: `Kebijakan perujuk ditentukan (${refPol}) untuk membatasi kebocoran parameter query atau token rahasia URL ke pihak ketiga.`,
      recommendation: 'Privasi referer terlindungi.',
      owasp: 'A01:2021 - Broken Access Control'
    });
  } else {
    addFinding({
      id: 'header-referrer-policy-missing',
      category: 'HTTP Security Headers',
      title: 'Referrer-Policy Tidak Ditemukan',
      severity: 'LOW',
      penalty: 4,
      passed: false,
      details: 'URL lengkap termasuk parameter query sensitif dapat bocor ke server pihak ketiga saat pengguna mengeklik tautan keluar.',
      recommendation: 'Tambahkan header Referrer-Policy: strict-origin-when-cross-origin atau no-referrer.',
      owasp: 'A01:2021 - Broken Access Control',
      snippets: {
        nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
      }
    });
  }

  // 6. Permissions-Policy
  const permPol = headers['permissions-policy'] || headers['feature-policy'];
  if (permPol) {
    addFinding({
      id: 'header-permissions-policy',
      category: 'HTTP Security Headers',
      title: 'Permissions-Policy Dikonfigurasi',
      severity: 'PASS',
      penalty: 0,
      passed: true,
      details: 'Membatasi akses browser API seperti kamera, mikrofon, dan geolokasi pada dokumen dan iframe.',
      recommendation: 'Kontrol fitur hardware aktif.',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  } else {
    addFinding({
      id: 'header-permissions-policy-missing',
      category: 'HTTP Security Headers',
      title: 'Permissions-Policy Belum Diterapkan',
      severity: 'LOW',
      penalty: 3,
      passed: false,
      details: 'Disarankan untuk secara eksplisit menolak akses ke fitur perangkat seperti kamera, mikrofon, atau USB jika tidak diperlukan.',
      recommendation: 'Tambahkan header Permissions-Policy: camera=(), microphone=(), geolocation=().',
      owasp: 'A05:2021 - Security Misconfiguration',
      snippets: {
        nginx: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;'
      }
    });
  }

  // 7. Cross-Origin-Opener-Policy (COOP)
  const coop = headers['cross-origin-opener-policy'];
  if (coop) {
    addFinding({
      id: 'header-coop',
      category: 'HTTP Security Headers',
      title: `Cross-Origin-Opener-Policy (COOP) Aktif (${coop})`,
      severity: 'PASS',
      penalty: 0,
      passed: true,
      details: `Mengisolasi konteks browsing tingkat atas untuk mencegah serangan side-channel seperti Spectre.`,
      recommendation: 'Isolasi origin aktif.',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  }

  // --- D. Information Leakage & Fingerprinting ---
  const serverHeader = headers['server'];
  const xPoweredBy = headers['x-powered-by'];

  if (xPoweredBy) {
    addFinding({
      id: 'leak-powered-by',
      category: 'Information Disclosure',
      title: 'Bocoran Teknologi Backend (X-Powered-By)',
      severity: 'MEDIUM',
      penalty: 8,
      passed: false,
      details: `Header mengekspos tumpukan framework backend: "${xPoweredBy}". Mempermudah penyerang menargetkan exploit CVE spesifik.`,
      recommendation: 'Hapus header X-Powered-By dari response aplikasi.',
      owasp: 'A05:2021 - Security Misconfiguration',
      snippets: {
        express: 'app.disable("x-powered-by");',
        php: 'expose_php = Off // di file php.ini',
        nginx: 'proxy_hide_header X-Powered-By;'
      }
    });
  } else {
    addFinding({
      id: 'leak-powered-by-hidden',
      category: 'Information Disclosure',
      title: 'X-Powered-By Disembunyikan',
      severity: 'PASS',
      penalty: 0,
      passed: true,
      details: 'Framework backend tidak membocorkan identitas melalui header X-Powered-By.',
      recommendation: 'Pencegahan fingerprinting berhasil.',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  }

  if (serverHeader && /\d+\.\d+/i.test(serverHeader)) {
    addFinding({
      id: 'leak-server-version',
      category: 'Information Disclosure',
      title: `Versi Web Server Terbuka (${serverHeader})`,
      severity: 'LOW',
      penalty: 5,
      passed: false,
      details: `Header Server secara gamblang mencantumkan nomor versi detail: "${serverHeader}".`,
      recommendation: 'Sembunyikan nomor versi di konfigurasi web server.',
      owasp: 'A05:2021 - Security Misconfiguration',
      snippets: {
        nginx: 'server_tokens off; // di file nginx.conf',
        apache: 'ServerTokens Prod\nServerSignature Off'
      }
    });
  } else {
    addFinding({
      id: 'leak-server-safe',
      category: 'Information Disclosure',
      title: 'Header Server Minimalis / Tersembunyi',
      severity: 'PASS',
      penalty: 0,
      passed: true,
      details: serverHeader ? `Header Server generik ("${serverHeader}") tanpa nomor versi rinci.` : 'Header Server tidak dikirimkan.',
      recommendation: 'Fingerprinting web server diminimalkan.',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  }

  // RFC 9116 security.txt
  if (hasSecurityTxt) {
    addFinding({
      id: 'security-txt-present',
      category: 'Information Disclosure',
      title: 'RFC 9116 security.txt Ditemukan',
      severity: 'PASS',
      penalty: 0,
      passed: true,
      details: 'Situs menyediakan file /.well-known/security.txt untuk saluran pelaporan kerentanan keamanan yang bertanggung jawab.',
      recommendation: 'Sangat baik, memenuhi standar pengungkapan kerentanan internasional.',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  }

  // --- E. Cookie Security Audit ---
  const cookies = headersResult.cookies || [];
  if (cookies.length > 0) {
    let insecureCookies = 0;
    let nonHttpOnly = 0;
    let missingSameSite = 0;

    cookies.forEach((c) => {
      if (!c.secure) insecureCookies++;
      if (!c.httpOnly) nonHttpOnly++;
      if (c.sameSite === 'None/Not Specified') missingSameSite++;
    });

    if (insecureCookies > 0) {
      addFinding({
        id: 'cookie-secure-missing',
        category: 'Cookie Security',
        title: `${insecureCookies} Cookie Tanpa Atribut "Secure"`,
        severity: 'HIGH',
        penalty: 12,
        passed: false,
        details: 'Cookie dikirim tanpa flag "Secure", sehingga dapat ditransmisikan dalam format plaintext via koneksi HTTP tidak terenkripsi.',
        recommendation: 'Wajibkan atribut Secure pada seluruh cookie yang diset oleh aplikasi.',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    }

    if (nonHttpOnly > 0) {
      addFinding({
        id: 'cookie-httponly-missing',
        category: 'Cookie Security',
        title: `${nonHttpOnly} Cookie Tanpa Atribut "HttpOnly"`,
        severity: 'MEDIUM',
        penalty: 8,
        passed: false,
        details: 'Cookie dapat diakses oleh JavaScript (document.cookie), berisiko dicuri penyerang saat terjadi serangan XSS (Session Hijacking).',
        recommendation: 'Tambahkan flag HttpOnly untuk cookie sesi otentikasi.',
        owasp: 'A07:2021 - Identification and Authentication Failures'
      });
    }

    if (missingSameSite > 0) {
      addFinding({
        id: 'cookie-samesite-missing',
        category: 'Cookie Security',
        title: `${missingSameSite} Cookie Tanpa Atribut "SameSite"`,
        severity: 'MEDIUM',
        penalty: 6,
        passed: false,
        details: 'Atribut SameSite tidak didefinisikan (Lax atau Strict), meningkatkan risiko serangan Cross-Site Request Forgery (CSRF).',
        recommendation: 'Tentukan atribut SameSite=Lax atau SameSite=Strict pada semua cookie.',
        owasp: 'A01:2021 - Broken Access Control'
      });
    }

    if (insecureCookies === 0 && nonHttpOnly === 0 && missingSameSite === 0) {
      addFinding({
        id: 'cookie-perfect',
        category: 'Cookie Security',
        title: 'Seluruh Cookie Terproteksi Penuh (Secure, HttpOnly, SameSite)',
        severity: 'PASS',
        penalty: 0,
        passed: true,
        details: `Semua ${cookies.length} cookie yang terdeteksi memiliki flag keamanan lengkap.`,
        recommendation: 'Pengaturan cookie sesuai standar keamanan tertinggi.',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    }
  }

  // --- F. DNS, SPF & DMARC Security ---
  if (dnsResult.spf.present) {
    if (dnsResult.spf.status === 'PERMISSIVE_VULNERABLE') {
      addFinding({
        id: 'dns-spf-loose',
        category: 'DNS & Email Posture',
        title: 'SPF Record Terlalu Permisif (+all / ?all)',
        severity: 'MEDIUM',
        penalty: 8,
        passed: false,
        details: `SPF ditemukan pada ${dnsResult.spf.checkedDomain} ("${dnsResult.spf.record}") namun menggunakan mekanisme netral/izinkan semua, sehingga domain masih mudah dipalsukan untuk phising.`,
        recommendation: 'Ganti aturan penutup SPF dengan ~all (SoftFail) atau -all (HardFail).',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    } else {
      addFinding({
        id: 'dns-spf-good',
        category: 'DNS & Email Posture',
        title: `SPF Record Dikonfigurasi (${dnsResult.spf.status})`,
        severity: 'PASS',
        penalty: 0,
        passed: true,
        details: `SPF aktif pada ${dnsResult.spf.checkedDomain}: "${dnsResult.spf.record}". Memverifikasi server pengirim email resmi.`,
        recommendation: 'Proteksi SPF aktif.',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    }
  } else if (dnsResult.mxRecords.length > 0) {
    addFinding({
      id: 'dns-spf-missing',
      category: 'DNS & Email Posture',
      title: 'Domain Memiliki Mail Server (MX) Namun Tanpa SPF Record',
      severity: 'HIGH',
      penalty: 10,
      passed: false,
      details: `Domain (${dnsResult.apexDomain}) aktif memiliki catatan MX tetapi tidak memiliki record TXT SPF. Penipu dapat memalsukan alamat email domain Anda dengan mudah (Email Spoofing).`,
      recommendation: 'Tambahkan TXT record SPF pada DNS manajemen domain Anda.',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  }

  if (dnsResult.dmarc.present) {
    if (dnsResult.dmarc.policy === 'none') {
      addFinding({
        id: 'dns-dmarc-none',
        category: 'DNS & Email Posture',
        title: 'DMARC Mode Pantau Saja (p=none)',
        severity: 'LOW',
        penalty: 4,
        passed: false,
        details: `DMARC aktif pada ${dnsResult.dmarc.checkedDomain} dengan p=none ("${dnsResult.dmarc.record}"). Email palsu yang gagal lolos tidak ditolak, hanya dipantau.`,
        recommendation: 'Tingkatkan kebijakan DMARC ke p=quarantine atau p=reject setelah selesai verifikasi pengirim sah.',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    } else {
      addFinding({
        id: 'dns-dmarc-good',
        category: 'DNS & Email Posture',
        title: `DMARC Enforcement Aktif (p=${dnsResult.dmarc.policy})`,
        severity: 'PASS',
        penalty: 0,
        passed: true,
        details: `DMARC diterapkan secara tegas pada ${dnsResult.dmarc.checkedDomain}: "${dnsResult.dmarc.record}". Melindungi reputasi domain dari phising massal.`,
        recommendation: 'Proteksi anti-spoofing DMARC sangat baik.',
        owasp: 'A05:2021 - Security Misconfiguration'
      });
    }
  } else if (dnsResult.mxRecords.length > 0) {
    addFinding({
      id: 'dns-dmarc-missing',
      category: 'DNS & Email Posture',
      title: 'DMARC Record Tidak Ditemukan',
      severity: 'MEDIUM',
      penalty: 8,
      passed: false,
      details: `Tidak ada proteksi DMARC pada _dmarc.${dnsResult.apexDomain}. Server penerima email tidak memiliki panduan tindakan ketika menerima email palsu dari domain ini.`,
      recommendation: 'Tambahkan TXT record DMARC dengan kebijakan p=quarantine atau p=reject.',
      owasp: 'A05:2021 - Security Misconfiguration'
    });
  }

  // Calculate Grade
  let grade = 'F';
  if (score >= 95) grade = 'A+';
  else if (score >= 85) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 45) grade = 'D';
  else grade = 'F';

  // Count severity stats
  const stats = {
    critical: findings.filter((f) => f.severity === 'CRITICAL' && !f.passed).length,
    high: findings.filter((f) => f.severity === 'HIGH' && !f.passed).length,
    medium: findings.filter((f) => f.severity === 'MEDIUM' && !f.passed).length,
    low: findings.filter((f) => f.severity === 'LOW' && !f.passed).length,
    passed: findings.filter((f) => f.passed).length,
    totalChecks: findings.length
  };

  return {
    score,
    grade,
    stats,
    findings
  };
}

// ==========================================
// API Endpoints
// ==========================================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'CyberTrack Security Engine', timestamp: new Date() });
});

// Main Scan Endpoint
app.post('/api/scan', async (req, res) => {
  const { url: rawUrl, allowLocal = false } = req.body;

  if (!rawUrl || typeof rawUrl !== 'string') {
    return res.status(400).json({ error: 'Parameter URL diperlukan.' });
  }

  let targetInfo;
  try {
    targetInfo = normalizeTarget(rawUrl);
  } catch (err) {
    return res.status(400).json({ error: 'Format URL / domain tidak valid.' });
  }

  // Prevent SSRF to internal networks unless specifically allowed
  try {
    const ipLookups = await dnsPromises.lookup(targetInfo.hostname, { all: true }).catch(() => []);
    if (!allowLocal) {
      if (
        targetInfo.hostname === 'localhost' ||
        targetInfo.hostname === '127.0.0.1' ||
        targetInfo.hostname === '::1' ||
        ipLookups.some((r) => isPrivateIP(r.address))
      ) {
        return res.status(403).json({
          error: 'Pemindaian terhadap alamat jaringan internal / private IP dibatasi untuk alasan keamanan SSRF. Gunakan domain publik tepercaya.'
        });
      }
    }
  } catch (e) {
    // dns lookup may fail if host does not exist
  }

  const startTime = Date.now();

  try {
    // Run all live non-intrusive network scans in parallel
    const [tlsResult, redirectResult, headersResult, dnsResult, hasSecurityTxt] = await Promise.all([
      inspectTLS(targetInfo.hostname, 443),
      inspectHttpRedirect(targetInfo.hostname),
      fetchUrlHeadersWithRedirects(targetInfo.fullUrl),
      inspectDNS(targetInfo.hostname),
      checkSecurityTxt(targetInfo.hostname)
    ]);

    if (!tlsResult.supported && !redirectResult.httpAvailable && headersResult.error) {
      return res.status(502).json({
        error: `Gagal menghubungi host target (${targetInfo.hostname}): Server mungkin offline, domain tidak terdaftar, atau memblokir koneksi.`,
        details: headersResult.error || tlsResult.error
      });
    }

    const evaluation = evaluateSecurityPosture({
      targetInfo,
      tlsResult,
      redirectResult,
      headersResult,
      dnsResult,
      hasSecurityTxt
    });

    const executionTimeMs = Date.now() - startTime;

    res.json({
      success: true,
      target: {
        raw: rawUrl,
        normalized: targetInfo.fullUrl,
        finalLandingUrl: headersResult.finalUrl || targetInfo.fullUrl,
        hostname: targetInfo.hostname,
        apexDomain: dnsResult.apexDomain,
        port: targetInfo.port,
        protocol: targetInfo.protocol,
        scanTimestamp: new Date().toISOString(),
        executionTimeMs
      },
      evaluation,
      rawScanData: {
        tls: tlsResult,
        redirect: redirectResult,
        headers: headersResult.headers || {},
        cookies: headersResult.cookies || [],
        dns: dnsResult,
        redirectChain: headersResult.redirectChain || [],
        hasSecurityTxt
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'Terjadi kesalahan sistem saat memproses pemindaian: ' + error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`[CyberTrack] Security Scanner Server running at http://localhost:${PORT}`);
});
