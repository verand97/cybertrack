/**
 * CyberTrack - Cyber Security Posture & Vulnerability Scanner
 * Frontend Client Application
 */

document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const scanForm = document.getElementById('scanForm');
  const targetInput = document.getElementById('targetUrlInput');
  const startScanBtn = document.getElementById('startScanBtn');
  const presetChips = document.querySelectorAll('.preset-chip');

  const scanningState = document.getElementById('scanningState');
  const scanPhaseText = document.getElementById('scanPhaseText');
  const scanDomainDisplay = document.getElementById('scanDomainDisplay');

  const errorBanner = document.getElementById('errorBanner');
  const errorMessage = document.getElementById('errorMessage');

  const resultsSection = document.getElementById('resultsSection');
  const meterFill = document.getElementById('meterFill');
  const meterScoreNum = document.getElementById('meterScoreNum');
  const gradeBadge = document.getElementById('gradeBadge');
  const targetDomainDisplay = document.getElementById('targetDomainDisplay');
  const ipAddressDisplay = document.getElementById('ipAddressDisplay');
  const tlsVersionDisplay = document.getElementById('tlsVersionDisplay');
  const scanTimeDisplay = document.getElementById('scanTimeDisplay');

  // Severity counts
  const critCountEl = document.getElementById('critCount');
  const highCountEl = document.getElementById('highCount');
  const medCountEl = document.getElementById('medCount');
  const lowCountEl = document.getElementById('lowCount');
  const passCountEl = document.getElementById('passCount');

  // Findings list and filters
  const findingsContainer = document.getElementById('findingsContainer');
  const categoryTabs = document.querySelectorAll('.tab-btn');
  const severityFilter = document.getElementById('severityFilter');

  // Action buttons
  const printReportBtn = document.getElementById('printReportBtn');
  const downloadJsonBtn = document.getElementById('downloadJsonBtn');
  const copySummaryBtn = document.getElementById('copySummaryBtn');

  // Tech details
  const sslCertIssuer = document.getElementById('sslCertIssuer');
  const sslCertValidity = document.getElementById('sslCertValidity');
  const sslCertDays = document.getElementById('sslCertDays');
  const sslCipherSuite = document.getElementById('sslCipherSuite');
  const dnsSpfVal = document.getElementById('dnsSpfVal');
  const dnsDmarcVal = document.getElementById('dnsDmarcVal');
  const httpRedirectVal = document.getElementById('httpRedirectVal');
  const serverHeaderVal = document.getElementById('serverHeaderVal');

  // History container
  const historyChipsContainer = document.getElementById('historyChipsContainer');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');
  const toastMsg = document.getElementById('toastMsg');

  // State
  let currentScanData = null;
  let activeCategory = 'all';
  let activeSeverityFilter = 'all';

  // Scanning phases messages
  const phaseMessages = [
    'Menghubungi DNS & memverifikasi IP publik...',
    'Menjalankan TLS handshake & verifikasi sertifikat X.509...',
    'Memeriksa pemaksaan redirect HTTP -> HTTPS...',
    'Menganalisis HTTP Security Headers (CSP, HSTS, XFO, XCTO)...',
    'Menguji atribut keamanan cookie (Secure, HttpOnly, SameSite)...',
    'Memeriksa catatan reputasi domain DNS (SPF & DMARC)...',
    'Menghitung skor postur keamanan & memetakan OWASP Top 10...'
  ];
  let phaseInterval = null;

  // Initialize History
  loadHistory();

  // Preset click
  presetChips.forEach((chip) => {
    chip.addEventListener('click', () => {
      const domain = chip.getAttribute('data-domain');
      if (domain) {
        targetInput.value = domain;
        performScan(domain);
      }
    });
  });

  // Form submit
  scanForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const domain = targetInput.value.trim();
    if (domain) {
      performScan(domain);
    }
  });

  // Category filter tabs
  categoryTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      categoryTabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      activeCategory = tab.getAttribute('data-category');
      renderFindings();
    });
  });

  // Severity dropdown filter
  if (severityFilter) {
    severityFilter.addEventListener('change', (e) => {
      activeSeverityFilter = e.target.value;
      renderFindings();
    });
  }

  // Export & Action Handlers
  if (printReportBtn) {
    printReportBtn.addEventListener('click', () => {
      window.print();
    });
  }

  if (downloadJsonBtn) {
    downloadJsonBtn.addEventListener('click', () => {
      if (!currentScanData) return;
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(currentScanData, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', `cybertrack-report-${currentScanData.target.hostname}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      showToast('Laporan JSON berhasil diunduh!');
    });
  }

  if (copySummaryBtn) {
    copySummaryBtn.addEventListener('click', () => {
      if (!currentScanData) return;
      const t = currentScanData.target;
      const e = currentScanData.evaluation;
      const summaryText = `[CyberTrack Security Audit Report]
Target: ${t.hostname} (${t.normalized})
Skor: ${e.score}/100 (Grade: ${e.grade})
Status Masalah:
- Critical: ${e.stats.critical}
- High: ${e.stats.high}
- Medium: ${e.stats.medium}
- Low: ${e.stats.low}
- Checks Passed: ${e.stats.passed}
Waktu Audit: ${new Date(t.scanTimestamp).toLocaleString()}
Dianalisis menggunakan CyberTrack Passive Security Scanner.`;

      navigator.clipboard.writeText(summaryText).then(() => {
        showToast('Ringkasan berhasil disalin ke clipboard!');
      });
    });
  }

  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', () => {
      localStorage.removeItem('cybertrack_history');
      loadHistory();
      showToast('Riwayat pemindaian dibersihkan.');
    });
  }

  // ==========================================
  // Perform Security Scan
  // ==========================================
  async function performScan(target) {
    // Reset states
    hideError();
    resultsSection.style.display = 'none';
    scanningState.style.display = 'block';
    startScanBtn.disabled = true;

    scanDomainDisplay.textContent = target;

    // Start animated status text
    let phaseIdx = 0;
    scanPhaseText.textContent = phaseMessages[phaseIdx];
    clearInterval(phaseInterval);
    phaseInterval = setInterval(() => {
      phaseIdx = (phaseIdx + 1) % phaseMessages.length;
      scanPhaseText.textContent = phaseMessages[phaseIdx];
    }, 900);

    // Scroll to loading area
    scanningState.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target })
      });

      const data = await response.json();
      clearInterval(phaseInterval);

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Gagal melakukan pemindaian keamanan target.');
      }

      currentScanData = data;
      saveToHistory(data);
      renderResults(data);

      scanningState.style.display = 'none';
      resultsSection.style.display = 'block';
      resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (err) {
      clearInterval(phaseInterval);
      scanningState.style.display = 'none';
      showError(err.message);
    } finally {
      startScanBtn.disabled = false;
    }
  }

  // ==========================================
  // Render Scan Results
  // ==========================================
  function renderResults(data) {
    const { target, evaluation, rawScanData } = data;

    // 1. Target Details
    targetDomainDisplay.textContent = target.hostname;
    ipAddressDisplay.textContent = rawScanData.dns.ipAddresses[0] || 'Tidak terdeteksi';
    tlsVersionDisplay.textContent = rawScanData.tls.protocol || 'None';
    scanTimeDisplay.textContent = `${target.executionTimeMs} ms`;

    // 2. Score Gauge & Grade
    animateScoreMeter(evaluation.score);
    renderGradeBadge(evaluation.grade);

    // 3. Severity stats
    critCountEl.textContent = `${evaluation.stats.critical} Critical`;
    highCountEl.textContent = `${evaluation.stats.high} High`;
    medCountEl.textContent = `${evaluation.stats.medium} Medium`;
    lowCountEl.textContent = `${evaluation.stats.low} Low`;
    passCountEl.textContent = `${evaluation.stats.passed} Passed`;

    // 4. Diagnostic Technical Drawer
    renderTechnicalDiagnostics(rawScanData);

    // 5. Findings List
    renderFindings();
  }

  // Gauge Meter Animation
  function animateScoreMeter(score) {
    const circumference = 440; // 2 * pi * r (r=70)
    meterScoreNum.textContent = '0';

    let strokeColor = 'var(--cyan)';
    if (score >= 85) strokeColor = 'var(--green)';
    else if (score >= 70) strokeColor = 'var(--cyan)';
    else if (score >= 50) strokeColor = 'var(--yellow)';
    else if (score >= 35) strokeColor = 'var(--orange)';
    else strokeColor = 'var(--red)';

    meterFill.style.stroke = strokeColor;

    const offset = circumference - (score / 100) * circumference;
    meterFill.style.strokeDashoffset = offset;

    // Count up animation
    let current = 0;
    const duration = 1200;
    const increment = Math.ceil(score / (duration / 25)) || 1;
    const counterInterval = setInterval(() => {
      current += increment;
      if (current >= score) {
        current = score;
        clearInterval(counterInterval);
      }
      meterScoreNum.textContent = current;
    }, 25);
  }

  // Grade Badge
  function renderGradeBadge(grade) {
    gradeBadge.textContent = `Grade ${grade}`;
    gradeBadge.className = 'grade-badge';
    if (grade === 'A+' || grade === 'A') gradeBadge.classList.add('grade-A');
    else if (grade === 'B') gradeBadge.classList.add('grade-B');
    else if (grade === 'C') gradeBadge.classList.add('grade-C');
    else if (grade === 'D') gradeBadge.classList.add('grade-D');
    else gradeBadge.classList.add('grade-F');
  }

  // Diagnostic Technical Drawer Values
  function renderTechnicalDiagnostics(raw) {
    const tls = raw.tls;
    if (tls.supported) {
      sslCertIssuer.textContent = tls.issuer;
      sslCertValidity.textContent = `${new Date(tls.validFrom).toLocaleDateString()} s/d ${new Date(tls.validTo).toLocaleDateString()}`;
      sslCertDays.textContent = tls.isExpired ? 'Kedaluwarsa!' : `${tls.daysRemaining} hari`;
      sslCipherSuite.textContent = `${tls.protocol} (${tls.cipher})`;
    } else {
      sslCertIssuer.textContent = 'Tidak Ada SSL/TLS';
      sslCertValidity.textContent = 'N/A';
      sslCertDays.textContent = 'N/A';
      sslCipherSuite.textContent = 'N/A';
    }

    // DNS & SPF/DMARC
    dnsSpfVal.textContent = raw.dns.spf.present ? raw.dns.spf.status : 'Tidak Ditemukan';
    dnsDmarcVal.textContent = raw.dns.dmarc.present ? `p=${raw.dns.dmarc.policy}` : 'Tidak Ditemukan';

    // HTTP Redirect
    if (raw.redirect.httpAvailable) {
      httpRedirectVal.textContent = raw.redirect.redirectsToHttps ? `Otomatis (Status ${raw.redirect.statusCode})` : 'Tidak Redirect';
    } else {
      httpRedirectVal.textContent = 'Port 80 Tertutup';
    }

    // Server Leak
    const srv = raw.headers['server'] || 'Disembunyikan (Bagus)';
    const pow = raw.headers['x-powered-by'] ? ` / Powered: ${raw.headers['x-powered-by']}` : '';
    serverHeaderVal.textContent = srv + pow;
  }

  // Findings List Rendering
  function renderFindings() {
    if (!currentScanData) return;
    const { findings } = currentScanData.evaluation;
    findingsContainer.innerHTML = '';

    const filtered = findings.filter((f) => {
      // Category filter
      if (activeCategory === 'headers' && f.category !== 'HTTP Security Headers') return false;
      if (activeCategory === 'transport' && f.category !== 'Transport Security') return false;
      if (activeCategory === 'cookies' && f.category !== 'Cookie Security') return false;
      if (activeCategory === 'dns' && f.category !== 'DNS & Email Posture') return false;
      if (activeCategory === 'disclosure' && f.category !== 'Information Disclosure') return false;

      // Severity filter
      if (activeSeverityFilter === 'issues' && f.passed) return false;
      if (activeSeverityFilter === 'critical_high' && (f.passed || (f.severity !== 'CRITICAL' && f.severity !== 'HIGH'))) return false;
      if (activeSeverityFilter === 'passed' && !f.passed) return false;

      return true;
    });

    if (filtered.length === 0) {
      findingsContainer.innerHTML = `
        <div style="text-align: center; padding: 3rem; background: var(--bg-card); border-radius: var(--radius-lg); border: 1px dashed var(--border-subtle); color: var(--text-dim);">
          <svg style="width: 48px; height: 48px; fill: var(--green); margin-bottom: 0.5rem;" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
          <p style="font-weight: 700; font-size: 1.1rem; color: var(--text-main);">Tidak ada temuan yang cocok dengan filter ini</p>
          <p style="font-size: 0.9rem;">Semua kriteria pada kategori ini dalam kondisi prima atau filter disetel terlalu ketat.</p>
        </div>
      `;
      return;
    }

    filtered.forEach((finding) => {
      const card = createFindingCard(finding);
      findingsContainer.appendChild(card);
    });
  }

  function createFindingCard(f) {
    const card = document.createElement('div');
    card.className = `finding-card status-${f.severity.toLowerCase()}`;

    // Severity status badge styling
    let sevBadgeColor = 'var(--text-muted)';
    let sevBadgeBg = 'rgba(255, 255, 255, 0.05)';
    if (f.severity === 'CRITICAL') { sevBadgeColor = 'var(--red)'; sevBadgeBg = 'var(--red-dim)'; }
    else if (f.severity === 'HIGH') { sevBadgeColor = 'var(--orange)'; sevBadgeBg = 'var(--orange-dim)'; }
    else if (f.severity === 'MEDIUM') { sevBadgeColor = 'var(--yellow)'; sevBadgeBg = 'var(--yellow-dim)'; }
    else if (f.severity === 'LOW') { sevBadgeColor = 'var(--cyan)'; sevBadgeBg = 'var(--cyan-dim)'; }
    else if (f.severity === 'PASS') { sevBadgeColor = 'var(--green)'; sevBadgeBg = 'var(--green-dim)'; }

    let snippetsHtml = '';
    if (f.snippets && Object.keys(f.snippets).length > 0) {
      const firstKey = Object.keys(f.snippets)[0];
      const snippetContent = escapeHtml(f.snippets[firstKey]);
      snippetsHtml = `
        <div class="snippet-box">
          <div class="snippet-top">
            <span>Contoh Konfigurasi Solusi (${firstKey.toUpperCase()})</span>
            <button type="button" class="btn-copy-snippet" data-code="${encodeURIComponent(f.snippets[firstKey])}">
              <svg style="width: 13px; height: 13px;" viewBox="0 0 24 24"><path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
              Salin Konfigurasi
            </button>
          </div>
          <div class="snippet-code">${snippetContent}</div>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="finding-header">
        <div class="finding-title-group">
          <span class="badge-tag" style="background: ${sevBadgeBg}; color: ${sevBadgeColor}; border: 1px solid ${sevBadgeColor}40;">
            ${f.severity}
          </span>
          <span class="badge-tag badge-category">${f.category}</span>
          ${f.owasp ? `<span class="badge-tag badge-owasp">${f.owasp}</span>` : ''}
          <h3 class="finding-title">${f.title}</h3>
        </div>
        ${f.penalty > 0 ? `<span style="font-size: 0.8rem; font-weight: 700; color: var(--red); font-family: var(--font-mono);">-${f.penalty} Poin</span>` : ''}
      </div>

      <p class="finding-desc">${f.details}</p>

      ${!f.passed ? `
        <div class="finding-remediation-box">
          <div class="remediation-header">
            <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
            <span>Rekomendasi Perbaikan:</span>
          </div>
          <p class="remediation-text">${f.recommendation}</p>
          ${snippetsHtml}
        </div>
      ` : `
        <div style="font-size: 0.85rem; color: var(--green); display: flex; align-items: center; gap: 0.4rem;">
          <svg style="width: 16px; height: 16px; fill: currentColor;" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
          ${f.recommendation}
        </div>
      `}
    `;

    // Bind snippet copy buttons
    const copyBtns = card.querySelectorAll('.btn-copy-snippet');
    copyBtns.forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const rawCode = decodeURIComponent(btn.getAttribute('data-code'));
        navigator.clipboard.writeText(rawCode).then(() => {
          showToast('Kode konfigurasi berhasil disalin!');
        });
      });
    });

    return card;
  }

  // ==========================================
  // Local History Management
  // ==========================================
  function saveToHistory(scanData) {
    const item = {
      hostname: scanData.target.hostname,
      score: scanData.evaluation.score,
      grade: scanData.evaluation.grade,
      timestamp: Date.now()
    };

    let history = JSON.parse(localStorage.getItem('cybertrack_history') || '[]');
    // Filter duplicates
    history = history.filter((h) => h.hostname !== item.hostname);
    history.unshift(item);
    if (history.length > 8) history.pop();

    localStorage.setItem('cybertrack_history', JSON.stringify(history));
    loadHistory();
  }

  function loadHistory() {
    if (!historyChipsContainer) return;
    const history = JSON.parse(localStorage.getItem('cybertrack_history') || '[]');
    historyChipsContainer.innerHTML = '';

    if (history.length === 0) {
      historyChipsContainer.innerHTML = `<span style="font-size: 0.82rem; color: var(--text-dim);">Belum ada riwayat pemindaian sebelumnya.</span>`;
      return;
    }

    history.forEach((h) => {
      const chip = document.createElement('div');
      chip.className = 'history-item';
      chip.innerHTML = `
        <span>${h.hostname}</span>
        <span class="history-grade-tag grade-${h.grade.replace('+', '-plus')}">${h.grade} (${h.score})</span>
      `;
      chip.addEventListener('click', () => {
        targetInput.value = h.hostname;
        performScan(h.hostname);
      });
      historyChipsContainer.appendChild(chip);
    });
  }

  // ==========================================
  // Helper Utilities
  // ==========================================
  function showError(msg) {
    errorMessage.textContent = msg;
    errorBanner.style.display = 'flex';
    errorBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function hideError() {
    errorBanner.style.display = 'none';
  }

  function showToast(msg) {
    if (!toastMsg) return;
    toastMsg.textContent = msg;
    toastMsg.classList.add('show');
    setTimeout(() => {
      toastMsg.classList.remove('show');
    }, 3000);
  }

  function escapeHtml(text) {
    if (!text) return '';
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
