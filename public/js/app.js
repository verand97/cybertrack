/**
 * CyberTrack - Enterprise Cyber Security Posture & Vulnerability Scanner
 * Security Command Center Client Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const scanForm = document.getElementById('scanForm');
  const targetInput = document.getElementById('targetUrlInput');
  const startScanBtn = document.getElementById('startScanBtn');
  const presetChips = document.querySelectorAll('.preset-chip');

  const scanningState = document.getElementById('scanningState');
  const terminalLogs = document.getElementById('terminalLogs');

  const errorBanner = document.getElementById('errorBanner');
  const errorMessage = document.getElementById('errorMessage');

  const resultsSection = document.getElementById('resultsSection');
  const meterScoreNum = document.getElementById('meterScoreNum');
  const hudScoreBar = document.getElementById('hudScoreBar');
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

  // Findings list & filters
  const findingsContainer = document.getElementById('findingsContainer');
  const categoryChips = document.querySelectorAll('.cat-chip');
  const severityFilter = document.getElementById('severityFilter');

  // Actions
  const printReportBtn = document.getElementById('printReportBtn');
  const downloadJsonBtn = document.getElementById('downloadJsonBtn');
  const copySummaryBtn = document.getElementById('copySummaryBtn');

  // Diagnostic sidebar
  const sslCertIssuer = document.getElementById('sslCertIssuer');
  const sslCertValidity = document.getElementById('sslCertValidity');
  const sslCertDays = document.getElementById('sslCertDays');
  const sslCipherSuite = document.getElementById('sslCipherSuite');
  const dnsSpfVal = document.getElementById('dnsSpfVal');
  const dnsDmarcVal = document.getElementById('dnsDmarcVal');
  const httpRedirectVal = document.getElementById('httpRedirectVal');
  const serverHeaderVal = document.getElementById('serverHeaderVal');

  // History & Toast
  const historyChipsContainer = document.getElementById('historyChipsContainer');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');
  const toastMsg = document.getElementById('toastMsg');

  // State
  let currentScanData = null;
  let activeCategory = 'all';
  let activeSeverityFilter = 'all';
  let terminalTimeouts = [];

  // Initialize
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

  // Category filter chips
  categoryChips.forEach((chip) => {
    chip.addEventListener('click', () => {
      categoryChips.forEach((c) => c.classList.remove('active'));
      chip.classList.add('active');
      activeCategory = chip.getAttribute('data-category');
      renderFindings();
    });
  });

  // Severity dropdown
  if (severityFilter) {
    severityFilter.addEventListener('change', (e) => {
      activeSeverityFilter = e.target.value;
      renderFindings();
    });
  }

  // Export handlers
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
      downloadAnchor.setAttribute('download', `cybertrack-audit-${currentScanData.target.hostname}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      showToast('Raw telemetry JSON exported');
    });
  }

  if (copySummaryBtn) {
    copySummaryBtn.addEventListener('click', () => {
      if (!currentScanData) return;
      const t = currentScanData.target;
      const e = currentScanData.evaluation;
      const summaryText = `[CYBERTRACK SECURITY AUDIT REPORT]
TARGET: ${t.hostname} (${t.normalized})
POSTURE SCORE: ${e.score}/100 (GRADE: ${e.grade})
RISK DISTRIBUTION:
  [!] CRITICAL: ${e.stats.critical}
  [!] HIGH:     ${e.stats.high}
  [-] MEDIUM:   ${e.stats.medium}
  [-] LOW:      ${e.stats.low}
  [+] PASSED:   ${e.stats.passed}
AUDIT TIME: ${new Date(t.scanTimestamp).toISOString()}
ENGINE: CyberTrack RFC-Compliant Security Posture Auditor`;

      navigator.clipboard.writeText(summaryText).then(() => {
        showToast('Summary copied to clipboard');
      });
    });
  }

  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', () => {
      localStorage.removeItem('cybertrack_history');
      loadHistory();
      showToast('Audit history cleared');
    });
  }

  // ==========================================
  // Scan progress: list the checks being run.
  // The server answers in a single response, so we don't fake per-step timing.
  // ==========================================
  const SCAN_CHECKS = [
    'Resolusi DNS (A/AAAA)',
    'Koneksi TLS port 443 & sertifikat',
    'Redirect HTTP → HTTPS (port 80)',
    'Header keamanan HTTP (CSP, HSTS, XFO, dll.)',
    'Atribut cookie (Secure, HttpOnly, SameSite)',
    'Rekaman SPF & DMARC',
    'security.txt (RFC 9116)',
    'Kebocoran informasi server'
  ];

  function streamTerminalLogs(target) {
    const label = document.getElementById('scanTargetLabel');
    if (label) label.textContent = target;
    terminalLogs.innerHTML = SCAN_CHECKS.map((c) => `<li>${escapeHtml(c)}</li>`).join('');
  }

  // ==========================================
  // Execute Security Scan
  // ==========================================
  async function performScan(target) {
    hideError();
    resultsSection.style.display = 'none';
    scanningState.style.display = 'block';
    startScanBtn.disabled = true;

    streamTerminalLogs(target);
    scanningState.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Failed to establish connection to target.');
      }

      currentScanData = data;
      saveToHistory(data);
      renderResults(data);

      setTimeout(() => {
        scanningState.style.display = 'none';
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 350);
    } catch (err) {
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

    // 1. Target Metadata
    targetDomainDisplay.textContent = target.hostname;
    ipAddressDisplay.textContent = rawScanData.dns.ipAddresses[0] || 'Unresolved';
    tlsVersionDisplay.textContent = rawScanData.tls.protocol || 'None';
    scanTimeDisplay.textContent = `${target.executionTimeMs} ms`;

    // 2. Score & Grade
    animateScoreDisplay(evaluation.score);
    renderGradeBadge(evaluation.grade);

    // 3. Severity Distribution
    critCountEl.textContent = evaluation.stats.critical;
    highCountEl.textContent = evaluation.stats.high;
    medCountEl.textContent = evaluation.stats.medium;
    lowCountEl.textContent = evaluation.stats.low;
    passCountEl.textContent = evaluation.stats.passed;

    // 4. Diagnostic Sidebar
    renderDiagnosticsSidebar(rawScanData);

    // 5. Findings
    renderFindings();
  }

  function animateScoreDisplay(score) {
    meterScoreNum.textContent = '0';
    let barColor;
    if (score >= 85) barColor = 'var(--sev-pass)';
    else if (score >= 70) barColor = 'var(--sev-low)';
    else if (score >= 50) barColor = 'var(--sev-medium)';
    else if (score >= 35) barColor = 'var(--sev-high)';
    else barColor = 'var(--sev-critical)';

    hudScoreBar.style.background = barColor;
    hudScoreBar.style.width = `${score}%`;

    let current = 0;
    const duration = 900;
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

  function renderGradeBadge(grade) {
    gradeBadge.textContent = grade;
    gradeBadge.title = `Grade ${grade}`;
    gradeBadge.className = 'grade';
    if (grade === 'A+' || grade === 'A') gradeBadge.classList.add('grade-A');
    else if (grade === 'B') gradeBadge.classList.add('grade-B');
    else if (grade === 'C') gradeBadge.classList.add('grade-C');
    else if (grade === 'D') gradeBadge.classList.add('grade-D');
    else gradeBadge.classList.add('grade-F');
  }

  function renderDiagnosticsSidebar(raw) {
    const tls = raw.tls;
    if (tls.supported) {
      sslCertIssuer.textContent = tls.issuer;
      sslCertValidity.textContent = `${new Date(tls.validFrom).toLocaleDateString()} - ${new Date(tls.validTo).toLocaleDateString()}`;
      sslCertDays.textContent = tls.isExpired ? 'Kedaluwarsa' : `${tls.daysRemaining} hari`;
      sslCipherSuite.textContent = `${tls.protocol} (${tls.cipher})`;
    } else {
      sslCertIssuer.textContent = 'Tidak ada TLS / port 443 tertutup';
      sslCertValidity.textContent = 'N/A';
      sslCertDays.textContent = 'N/A';
      sslCipherSuite.textContent = 'N/A';
    }

    // DNS & SPF/DMARC
    if (raw.dns.spf.present) {
      dnsSpfVal.textContent = `${raw.dns.spf.status} (${raw.dns.spf.checkedDomain})`;
    } else {
      dnsSpfVal.textContent = 'Tidak dikonfigurasi';
    }

    if (raw.dns.dmarc.present) {
      dnsDmarcVal.textContent = `p=${raw.dns.dmarc.policy} (${raw.dns.dmarc.checkedDomain})`;
    } else {
      dnsDmarcVal.textContent = 'Tidak dikonfigurasi';
    }

    // HTTP Redirect
    if (raw.redirect.httpAvailable) {
      httpRedirectVal.textContent = raw.redirect.redirectsToHttps ? 'Ya, ke HTTPS' : 'Tidak (tidak aman)';
    } else {
      httpRedirectVal.textContent = 'Port 80 menolak koneksi';
    }

    // Server Leak
    const srv = raw.headers['server'] || 'Disembunyikan';
    const pow = raw.headers['x-powered-by'] ? ` / X-Powered-By: ${raw.headers['x-powered-by']}` : '';
    serverHeaderVal.textContent = srv + pow;
  }

  // Findings List
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
      findingsContainer.innerHTML = `<div class="empty-state">Tidak ada temuan untuk filter ini.</div>`;
      return;
    }

    const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, PASS: 5 };
    filtered.sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4));

    filtered.forEach((f) => {
      const card = createFindingRow(f);
      findingsContainer.appendChild(card);
    });
  }

  function createFindingRow(f) {
    const SEV_LABELS = {
      CRITICAL: 'Kritis',
      HIGH: 'Tinggi',
      MEDIUM: 'Sedang',
      LOW: 'Rendah',
      PASS: 'Lolos'
    };
    const sevKey = (f.severity || 'INFO').toUpperCase();
    const sevClass = SEV_LABELS[sevKey] ? sevKey.toLowerCase() : 'info';
    const sevText = SEV_LABELS[sevKey] || 'Info';

    const row = document.createElement('article');
    row.className = `finding sev-${sevClass}`;

    let snippetsHtml = '';
    if (f.snippets && Object.keys(f.snippets).length > 0) {
      const firstKey = Object.keys(f.snippets)[0];
      const code = escapeHtml(f.snippets[firstKey]);
      snippetsHtml = `
        <div class="code-box">
          <div class="code-box-header">
            <span>${escapeHtml(firstKey)}</span>
            <button type="button" class="btn-copy-code" data-code="${encodeURIComponent(f.snippets[firstKey])}">Salin</button>
          </div>
          <pre>${code}</pre>
        </div>
      `;
    }

    const meta = [f.category, f.owasp].filter(Boolean).join(' · ');

    row.innerHTML = `
      <div><span class="sev-label">${sevText}</span></div>
      <div>
        <div class="finding-head">
          <h3 class="finding-title">${f.title}</h3>
          ${f.penalty > 0 ? `<span class="finding-penalty">−${f.penalty} poin</span>` : ''}
        </div>
        <div class="finding-meta">${meta}</div>
        <p class="finding-desc">${f.details}</p>
        ${!f.passed ? `
          <div class="fix">
            <div class="fix-label">Perbaikan</div>
            <p class="fix-text">${f.recommendation}</p>
            ${snippetsHtml}
          </div>
        ` : `
          <p class="passed-note">${f.recommendation}</p>
        `}
      </div>
    `;

    // Bind snippet copy buttons
    const copyBtns = row.querySelectorAll('.btn-copy-code');
    copyBtns.forEach((btn) => {
      btn.addEventListener('click', () => {
        const rawCode = decodeURIComponent(btn.getAttribute('data-code'));
        navigator.clipboard.writeText(rawCode).then(() => {
          showToast('Config snippet copied');
        });
      });
    });

    return row;
  }

  // ==========================================
  // Local History
  // ==========================================
  function saveToHistory(scanData) {
    const item = {
      hostname: scanData.target.hostname,
      score: scanData.evaluation.score,
      grade: scanData.evaluation.grade,
      timestamp: Date.now()
    };

    let history = JSON.parse(localStorage.getItem('cybertrack_history') || '[]');
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
      historyChipsContainer.innerHTML = `<span class="history-empty">Belum ada</span>`;
      return;
    }

    history.forEach((h) => {
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'history-item';
      chip.innerHTML = `
        <span>${escapeHtml(h.hostname)}</span>
        <span class="history-grade">${escapeHtml(h.grade)}</span>
      `;
      chip.addEventListener('click', () => {
        targetInput.value = h.hostname;
        performScan(h.hostname);
      });
      historyChipsContainer.appendChild(chip);
    });
  }

  // ==========================================
  // Helpers
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
    }, 2800);
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
