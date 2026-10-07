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
  // Terminal Log Streaming Helper
  // ==========================================
  function streamTerminalLogs(target) {
    terminalLogs.innerHTML = '';
    terminalTimeouts.forEach(clearTimeout);
    terminalTimeouts = [];

    const startTime = Date.now();
    const steps = [
      { tag: 'RESOLVER', msg: `Querying A/AAAA records for ${target} via 1.1.1.1 / 8.8.8.8...` },
      { tag: 'SOCKET',   msg: `Initializing raw TLS connection on port 443 with SNI hostname...` },
      { tag: 'X509',     msg: `Inspecting certificate chain, CA authority, cipher suite and expiry...` },
      { tag: 'ROUTING',  msg: `Testing Port 80 HTTP enforcement and checking 301/308 redirect chain...` },
      { tag: 'HEADERS',  msg: `Auditing HTTP Security Headers (CSP, HSTS, XFO, XCTO, Referrer, COOP)...` },
      { tag: 'COOKIES',  msg: `Evaluating Set-Cookie flag matrix (Secure, HttpOnly, SameSite)...` },
      { tag: 'DNS-SEC',  msg: `Validating SPF (v=spf1) & DMARC (_dmarc) email anti-spoofing policies...` },
      { tag: 'RFC-9116', msg: `Querying /.well-known/security.txt vulnerability disclosure policy...` },
      { tag: 'EVALUATE', msg: `Synthesizing OWASP Top 10 telemetry and computing security score...` }
    ];

    steps.forEach((step, idx) => {
      const delay = idx * 110;
      const t = setTimeout(() => {
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(3);
        const line = document.createElement('div');
        line.className = 'log-line';
        line.innerHTML = `
          <span class="log-ts">[+${elapsed}s]</span>
          <span class="log-tag">[${step.tag}]</span>
          <span class="log-msg">${step.msg}</span>
        `;
        terminalLogs.appendChild(line);
        terminalLogs.scrollTop = terminalLogs.scrollHeight;
      }, delay);
      terminalTimeouts.push(t);
    });
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
    critCountEl.textContent = `${evaluation.stats.critical} CRIT`;
    highCountEl.textContent = `${evaluation.stats.high} HIGH`;
    medCountEl.textContent = `${evaluation.stats.medium} MED`;
    lowCountEl.textContent = `${evaluation.stats.low} LOW`;
    passCountEl.textContent = `${evaluation.stats.passed} PASS`;

    // 4. Diagnostic Sidebar
    renderDiagnosticsSidebar(rawScanData);

    // 5. Findings
    renderFindings();
  }

  function animateScoreDisplay(score) {
    meterScoreNum.textContent = '0';
    let barColor = 'var(--cyan)';
    if (score >= 85) barColor = 'var(--green)';
    else if (score >= 70) barColor = 'var(--cyan)';
    else if (score >= 50) barColor = 'var(--amber)';
    else if (score >= 35) barColor = 'var(--orange)';
    else barColor = 'var(--red)';

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
    gradeBadge.textContent = `GRADE ${grade}`;
    gradeBadge.className = 'grade-stamp';
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
      sslCertDays.textContent = tls.isExpired ? 'EXPIRED' : `${tls.daysRemaining} days`;
      sslCipherSuite.textContent = `${tls.protocol} (${tls.cipher})`;
    } else {
      sslCertIssuer.textContent = 'NO TLS / PORT 443 CLOSED';
      sslCertValidity.textContent = 'N/A';
      sslCertDays.textContent = 'N/A';
      sslCipherSuite.textContent = 'N/A';
    }

    // DNS & SPF/DMARC
    if (raw.dns.spf.present) {
      dnsSpfVal.textContent = `${raw.dns.spf.status} (${raw.dns.spf.checkedDomain})`;
    } else {
      dnsSpfVal.textContent = 'NOT CONFIGURED';
    }

    if (raw.dns.dmarc.present) {
      dnsDmarcVal.textContent = `p=${raw.dns.dmarc.policy} (${raw.dns.dmarc.checkedDomain})`;
    } else {
      dnsDmarcVal.textContent = 'NOT CONFIGURED';
    }

    // HTTP Redirect
    if (raw.redirect.httpAvailable) {
      httpRedirectVal.textContent = raw.redirect.redirectsToHttps ? `301 ENFORCED` : `NO REDIRECT (INSECURE)`;
    } else {
      httpRedirectVal.textContent = 'PORT 80 REFUSED';
    }

    // Server Leak
    const srv = raw.headers['server'] || 'SUPPRESSED (SECURE)';
    const pow = raw.headers['x-powered-by'] ? ` / Powered: ${raw.headers['x-powered-by']}` : '';
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
      findingsContainer.innerHTML = `
        <div style="padding: 2.5rem; text-align: center; background: var(--bg-surface); border: 1px dashed var(--border-hairline); border-radius: var(--radius-sm); color: var(--text-tertiary); font-family: var(--font-mono); font-size: 0.85rem;">
          [NO AUDIT FINDINGS MATCH CURRENT FILTER CRITERIA]
        </div>
      `;
      return;
    }

    filtered.forEach((f) => {
      const card = createFindingRow(f);
      findingsContainer.appendChild(card);
    });
  }

  function createFindingRow(f) {
    const row = document.createElement('div');
    row.className = `finding-row sev-${f.severity.toLowerCase()}`;

    let sevColor = 'var(--text-tertiary)';
    if (f.severity === 'CRITICAL') sevColor = 'var(--red)';
    else if (f.severity === 'HIGH') sevColor = 'var(--orange)';
    else if (f.severity === 'MEDIUM') sevColor = 'var(--amber)';
    else if (f.severity === 'LOW') sevColor = 'var(--cyan)';
    else if (f.severity === 'PASS') sevColor = 'var(--green)';

    let snippetsHtml = '';
    if (f.snippets && Object.keys(f.snippets).length > 0) {
      const firstKey = Object.keys(f.snippets)[0];
      const code = escapeHtml(f.snippets[firstKey]);
      snippetsHtml = `
        <div class="code-box">
          <div class="code-box-header">
            <span>CONFIG PLAYBOOK // ${firstKey.toUpperCase()}</span>
            <button type="button" class="btn-copy-code" data-code="${encodeURIComponent(f.snippets[firstKey])}">
              <svg style="width: 12px; height: 12px;" viewBox="0 0 24 24"><path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
              COPY
            </button>
          </div>
          <pre>${code}</pre>
        </div>
      `;
    }

    row.innerHTML = `
      <div class="finding-meta-top">
        <span class="badge-tag" style="background: ${sevColor}15; color: ${sevColor}; border: 1px solid ${sevColor}40;">
          [${f.severity}]
        </span>
        <span class="badge-tag badge-cat">${f.category}</span>
        ${f.owasp ? `<span class="badge-tag badge-owasp">${f.owasp}</span>` : ''}
        ${f.penalty > 0 ? `<span class="penalty-tag">-${f.penalty} PTS</span>` : ''}
      </div>

      <div class="finding-title">${f.title}</div>
      <div class="finding-desc">${f.details}</div>

      ${!f.passed ? `
        <div class="remediation-panel">
          <div class="remediation-label">
            <svg style="width: 12px; height: 12px;" viewBox="0 0 24 24"><path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
            <span>REMEDIATION PROTOCOL:</span>
          </div>
          <div class="remediation-text">${f.recommendation}</div>
          ${snippetsHtml}
        </div>
      ` : `
        <div class="passed-line">
          <svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
          <span>${f.recommendation}</span>
        </div>
      `}
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
      historyChipsContainer.innerHTML = `<span style="font-size: 0.75rem; color: var(--text-dimmed); font-family: var(--font-mono);">No audit history</span>`;
      return;
    }

    history.forEach((h) => {
      const chip = document.createElement('div');
      chip.className = 'history-item';
      chip.innerHTML = `
        <span>${h.hostname}</span>
        <span class="history-grade grade-${h.grade.replace('+', '-plus')}">[${h.grade}]</span>
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
