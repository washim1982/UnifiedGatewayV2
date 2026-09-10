// Universal AI Gateway - Web Dashboard Frontend
document.addEventListener('DOMContentLoaded', () => {
  let allApps = [];
  let availableModels = { bedrock: [], local: [] };
  let activeLang = 'curl';
  let activeAuthMode = 'sts'; // 'sts' or 'key'
  let appStsCache = {}; // appId -> { token, expiresAt }
  let selectedAppForStsModal = null;

  // DOM Elements
  const navButtons = document.querySelectorAll('.nav-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const pageHeading = document.getElementById('page-heading');
  const pageSubheading = document.getElementById('page-subheading');

  // STS status
  const stsIndicator = document.getElementById('sts-indicator');
  const stsDetail = document.getElementById('sts-detail-text');

  // Modals
  const createModal = document.getElementById('create-modal');
  const keyModal = document.getElementById('key-modal');
  const stsModal = document.getElementById('sts-modal');
  const btnOpenCreateModal = document.getElementById('btn-open-create-modal');
  const btnCloseCreateModal = document.getElementById('btn-close-create-modal');
  const btnCancelCreate = document.getElementById('btn-cancel-create');
  const btnCloseKeyModal = document.getElementById('btn-close-key-modal');
  const btnDoneKey = document.getElementById('btn-done-key');
  const btnCloseStsModal = document.getElementById('btn-close-sts-modal');
  const btnCloseStsModalBottom = document.getElementById('btn-close-sts-modal-bottom');
  const btnMintStsModal = document.getElementById('btn-mint-sts-modal');
  const btnCopyStsModalToken = document.getElementById('btn-copy-sts-modal-token');
  const createAppForm = document.getElementById('create-app-form');
  const btnRefreshStatus = document.getElementById('btn-refresh-status');

  // Guardrails Elements
  const guardrailsForm = document.getElementById('guardrails-form');
  const btnRunGrTest = document.getElementById('btn-run-gr-test');

  // Generator & Tester
  const genAppSelect = document.getElementById('gen-app-select');
  const genAppDetails = document.getElementById('gen-app-details');
  const genEndpointUrl = document.getElementById('gen-endpoint-url');
  const genCodeSnippet = document.getElementById('gen-code-snippet');
  const codeTabBtns = document.querySelectorAll('.code-tab-btn');
  const btnRunAppTest = document.getElementById('btn-run-app-test');
  const btnModeSts = document.getElementById('btn-mode-sts');
  const btnModeKey = document.getElementById('btn-mode-key');
  const genAuthBadge = document.getElementById('gen-auth-badge');
  const genStsControlsPanel = document.getElementById('gen-sts-controls-panel');
  const btnMintGenSts = document.getElementById('btn-mint-gen-sts');
  const genStsTtlSelect = document.getElementById('gen-sts-ttl-select');
  const genCurrentStsInput = document.getElementById('gen-current-sts-input');
  const btnCopyGenSts = document.getElementById('btn-copy-gen-sts');
  const genStsExpiryText = document.getElementById('gen-sts-expiry-text');

  // Universal Router
  // The management plane is authenticated. Every /api call carries the operator's
  // credential from session storage; a 401 means "sign in", not "server error".
  // --- Okta session ---------------------------------------------------------
  // The dashboard holds the access token for the tab only. A 401 means the session
  // has gone and the user signs in again; a 403 means their group does not grant
  // the action, which is a message rather than a sign-in prompt.

  const OKTA_TOKEN_KEY = 'ug_okta_access_token';
  const OKTA_USER_KEY = 'ug_okta_user';

  function oktaToken() {
    try { return sessionStorage.getItem(OKTA_TOKEN_KEY) || ''; } catch (e) { return ''; }
  }

  function oktaUser() {
    try { return JSON.parse(sessionStorage.getItem(OKTA_USER_KEY) || 'null'); } catch (e) { return null; }
  }

  function setOktaSession(token, user) {
    try {
      sessionStorage.setItem(OKTA_TOKEN_KEY, token);
      sessionStorage.setItem(OKTA_USER_KEY, JSON.stringify(user));
    } catch (e) { /* private mode: the session simply does not persist */ }
  }

  function clearOktaSession() {
    try {
      sessionStorage.removeItem(OKTA_TOKEN_KEY);
      sessionStorage.removeItem(OKTA_USER_KEY);
    } catch (e) { /* nothing to clear */ }
  }

  function adminCredential() {
    // Kept for the universal-invoke panel, which takes a gateway credential directly.
    try { return sessionStorage.getItem('ug_universal_admin_key') || ''; } catch (e) { return ''; }
  }

  async function apiFetch(url, options) {
    const opts = Object.assign({}, options || {});
    opts.headers = Object.assign({}, opts.headers || {});

    const token = oktaToken();
    if (token) {
      opts.headers['Authorization'] = 'Bearer ' + token;
    }

    const res = await fetch(url, opts);
    if (res.status === 401) {
      clearOktaSession();
      showLogin();
    } else if (res.status === 403 && !opts.quiet) {
      showAuthRequired(403);
    }
    return res;
  }

  // --- Sign-in flow ----------------------------------------------------------

  function showLogin() {
    const overlay = document.getElementById('okta-login');
    const session = document.getElementById('okta-session');
    if (overlay) overlay.hidden = false;
    if (session) session.hidden = true;
  }

  function hideLogin(user) {
    const overlay = document.getElementById('okta-login');
    const session = document.getElementById('okta-session');
    const label = document.getElementById('okta-session-user');
    if (overlay) overlay.hidden = true;
    if (session) session.hidden = false;
    if (label && user) {
      label.textContent = user.email + '  •  ' + (user.groups || []).join(', ');
    }
  }

  /**
   * Hides controls the signed-in user's groups do not permit. This is presentation
   * only - the gateway evaluates every request against IAM regardless of what the
   * page shows, so a hidden button is a courtesy, not a control.
   */
  function applyGroupVisibility(user) {
    const isAdmin = (user.groups || []).indexOf('UnifiedGateway-Admins') !== -1;
    document.querySelectorAll('[data-requires-admin]').forEach(el => {
      el.hidden = !isAdmin;
    });
  }

  async function signIn(username, password) {
    const res = await fetch('/okta/oauth2/v1/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username, password: password })
    });

    if (!res.ok) {
      throw new Error('Sign-in failed. Check the username and password.');
    }

    const data = await res.json();
    const user = { email: data.email, groups: data.groups || [] };
    setOktaSession(data.access_token, user);
    return user;
  }

  const loginForm = document.getElementById('okta-login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errorBox = document.getElementById('okta-login-error');
      if (errorBox) errorBox.hidden = true;

      try {
        const user = await signIn(
          document.getElementById('okta-username').value.trim(),
          document.getElementById('okta-password').value
        );
        hideLogin(user);
        applyGroupVisibility(user);
        location.reload();
      } catch (err) {
        if (errorBox) {
          errorBox.textContent = err.message;
          errorBox.hidden = false;
        }
      }
    });
  }

  const signOutBtn = document.getElementById('okta-signout');
  if (signOutBtn) {
    signOutBtn.addEventListener('click', () => {
      clearOktaSession();
      location.reload();
    });
  }

  function showAuthRequired(status) {
    const banner = document.getElementById('auth-banner');
    const message = status === 403
      ? 'Your role is not permitted to perform this action.'
      : 'Enter an admin credential or STS token to use the console.';

    if (banner) {
      banner.textContent = message;
      banner.hidden = false;
    } else {
      console.warn('Management API returned ' + status + ': ' + message);
    }
  }

  const univApiKey = document.getElementById('univ-api-key');
  const btnToggleUnivKey = document.getElementById('btn-toggle-univ-key');
  const univProvider = document.getElementById('univ-provider');
  const univModel = document.getElementById('univ-model');
  const btnRunUnivTest = document.getElementById('btn-run-univ-test');

  // Initialize stored Universal API Key
  const storedUnivKey = sessionStorage.getItem('ug_universal_admin_key') || '';
  if (univApiKey) {
    univApiKey.value = storedUnivKey;
    univApiKey.addEventListener('input', () => {
      sessionStorage.setItem('ug_universal_admin_key', univApiKey.value.trim());
    });
  }

  if (btnToggleUnivKey && univApiKey) {
    btnToggleUnivKey.addEventListener('click', () => {
      if (univApiKey.type === 'password') {
        univApiKey.type = 'text';
        btnToggleUnivKey.textContent = 'Hide';
      } else {
        univApiKey.type = 'password';
        btnToggleUnivKey.textContent = 'Show';
      }
    });
  }

  // Navigation Logic
  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      navButtons.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      document.getElementById(`pane-${tab}`).classList.add('active');

      updatePageHeader(tab);
      if (tab === 'telemetry') {
        loadMetrics();
      } else if (tab === 'billing') {
        loadBilling();
      } else if (tab === 'guardrails') {
        loadGuardrailConfig();
      }
    });
  });

  function updatePageHeader(tab) {
    // The spend page carries its own header with its own range and export controls, so
    // the shared topbar would repeat the title and offer a second Refresh button.
    const topbar = document.querySelector(".topbar");
    if (topbar) topbar.hidden = (tab === "billing");

    const titles = {
      apps: { title: 'Application Registry', sub: 'Manage per-application AI routing endpoints and system prompts' },
      guardrails: { title: 'Guardrails & Data Safety', sub: 'Admin-level PCI, PII, Secrets, and Prompt Injection policies for all requests' },
      generator: { title: 'API Generator & Test Console', sub: 'Generated REST endpoints with sample SDK code and interactive sandbox' },
      universal: { title: 'Universal Router', sub: 'Direct normalized schema invocation across Bedrock and Local engines' },
      telemetry: { title: 'Telemetry & Observability', sub: 'Real-time throughput, token analytics, latency percentiles, and request logs' },
      billing: { title: 'Billing & Cost', sub: 'Account spend and per-application token cost, daily, weekly and monthly' }
    };
    pageHeading.textContent = titles[tab]?.title || 'Dashboard';
    pageSubheading.textContent = titles[tab]?.sub || '';
  }

  // Fetch STS Status
  async function loadStsStatus() {
    try {
      const res = await apiFetch('/api/credentials/status', { quiet: true });
      if (!res.ok) throw new Error('Status check failed');
      const data = await res.json();

      if (data.isInitialized) {
        stsIndicator.classList.add('online');
        const role = data.isAssumedRole ? 'STS Assumed' : 'Direct AWS';
        const region = data.region || 'us-east-1';
        stsDetail.textContent = `${role} (${region})`;
      } else {
        stsIndicator.classList.remove('online');
        stsDetail.textContent = data.lastError ? `Error: ${data.lastError.substring(0, 30)}...` : 'Offline';
      }
    } catch (e) {
      stsIndicator.classList.remove('online');
      stsDetail.textContent = 'Service Unreachable';
    }
  }

  // Guardrail Configuration & Sandbox
  async function loadGuardrailConfig() {
    try {
      const res = await apiFetch('/api/guardrails/config', { quiet: true });
      if (!res.ok) return;
      const config = await res.json();

      document.getElementById('gr-enabled').value = config.enabled ? "true" : "false";
      document.getElementById('gr-mode').value = config.mode !== undefined ? config.mode : 0;

      // PCI
      document.getElementById('gr-pci-cc').checked = config.pci?.maskCreditCards ?? true;
      document.getElementById('gr-pci-iban').checked = config.pci?.maskIban ?? true;
      document.getElementById('gr-pci-cvv').checked = config.pci?.maskCvv ?? true;

      // PII
      document.getElementById('gr-pii-ssn').checked = config.pii?.maskSsn ?? true;
      document.getElementById('gr-pii-email').checked = config.pii?.maskEmails ?? true;
      document.getElementById('gr-pii-phone').checked = config.pii?.maskPhoneNumbers ?? true;
      document.getElementById('gr-pii-passport').checked = config.pii?.maskPassports ?? true;

      // Secrets
      document.getElementById('gr-sec-aws').checked = config.secrets?.maskAwsKeys ?? true;
      document.getElementById('gr-sec-privkey').checked = config.secrets?.maskPrivateKeys ?? true;
      document.getElementById('gr-sec-jwt').checked = config.secrets?.maskJwtTokens ?? true;
      document.getElementById('gr-sec-keys').checked = config.secrets?.maskGenericApiKeys ?? true;

      // Injection
      document.getElementById('gr-inj-override').checked = config.promptInjection?.blockSystemOverrides ?? true;
      document.getElementById('gr-inj-jailbreak').checked = config.promptInjection?.blockJailbreaks ?? true;
    } catch (e) {
      console.error('Failed to load guardrail config', e);
    }
  }

  guardrailsForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const payload = {
      enabled: document.getElementById('gr-enabled').value === "true",
      mode: parseInt(document.getElementById('gr-mode').value),
      pci: {
        enabled: true,
        maskCreditCards: document.getElementById('gr-pci-cc').checked,
        maskIban: document.getElementById('gr-pci-iban').checked,
        maskCvv: document.getElementById('gr-pci-cvv').checked
      },
      pii: {
        enabled: true,
        maskSsn: document.getElementById('gr-pii-ssn').checked,
        maskEmails: document.getElementById('gr-pii-email').checked,
        maskPhoneNumbers: document.getElementById('gr-pii-phone').checked,
        maskPassports: document.getElementById('gr-pii-passport').checked
      },
      secrets: {
        enabled: true,
        maskAwsKeys: document.getElementById('gr-sec-aws').checked,
        maskPrivateKeys: document.getElementById('gr-sec-privkey').checked,
        maskJwtTokens: document.getElementById('gr-sec-jwt').checked,
        maskGenericApiKeys: document.getElementById('gr-sec-keys').checked
      },
      promptInjection: {
        enabled: true,
        blockSystemOverrides: document.getElementById('gr-inj-override').checked,
        blockJailbreaks: document.getElementById('gr-inj-jailbreak').checked
      },
      bedrockGuardrails: {
        enabled: false,
        guardrailIdentifier: "",
        guardrailVersion: "DRAFT"
      }
    };

    try {
      const res = await apiFetch('/api/guardrails/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        alert('Enterprise Guardrail Policy saved successfully!');
      } else {
        alert('Failed to save Guardrail configuration.');
      }
    } catch (err) {
      alert(`Save error: ${err.message}`);
    }
  });

  // Guardrail Sandbox Run
  btnRunGrTest.addEventListener('click', async () => {
    const input = document.getElementById('gr-test-input').value;
    const modeVal = document.getElementById('gr-test-mode').value;

    btnRunGrTest.disabled = true;
    btnRunGrTest.textContent = 'Inspecting...';

    const resultBox = document.getElementById('gr-sandbox-result');
    resultBox.style.display = 'block';

    try {
      const payload = {
        input: input,
        mode: modeVal !== "" ? parseInt(modeVal) : undefined
      };

      const res = await apiFetch('/api/guardrails/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await res.json();

      document.getElementById('gr-res-action').textContent = data.actionTaken.toUpperCase();
      document.getElementById('gr-res-count').textContent = data.violations?.length || 0;
      document.getElementById('gr-res-risk').textContent = `${(data.riskScore * 100).toFixed(0)}%`;
      document.getElementById('gr-res-lat').textContent = `${data.latencyMs} ms`;

      const vContainer = document.getElementById('gr-res-violations-container');
      vContainer.innerHTML = '';

      if (data.violations && data.violations.length > 0) {
        data.violations.forEach(v => {
          const pill = document.createElement('div');
          pill.className = `violation-pill severity-${v.severity}`;
          pill.innerHTML = `
            <div>
              <span class="violation-title">[${v.category}] ${escapeHtml(v.ruleName)} (${v.severity})</span>
              <div class="violation-desc">${escapeHtml(v.description)} - Snippet: <code>${escapeHtml(v.detectedSnippet || '')}</code></div>
            </div>
          `;
          vContainer.appendChild(pill);
        });
      } else {
        vContainer.innerHTML = `<div style="color:var(--accent-green); font-size:13px;">No security policy violations detected in this text snippet.</div>`;
      }

      document.getElementById('gr-res-sanitized').textContent = data.sanitizedInput || '(None)';
    } catch (e) {
      document.getElementById('gr-res-sanitized').textContent = `Inspection error: ${e.message}`;
    } finally {
      btnRunGrTest.disabled = false;
      btnRunGrTest.textContent = 'Analyze & Sanitize';
    }
  });

  // Fetch Models
  async function loadModels() {
    try {
      const res = await apiFetch('/api/models');
      if (res.ok) {
        availableModels = await res.json();
        populateModelDropdowns();
      }
    } catch (e) {
      console.error('Error fetching models', e);
    }
  }

  function populateModelDropdowns() {
    const modalProvider = document.getElementById('modal-app-provider').value;
    const modalModelSelect = document.getElementById('modal-app-model');
    modalModelSelect.innerHTML = '';

    const models = modalProvider === 'bedrock' ? availableModels.bedrock : availableModels.local;
    models.forEach(m => {
      const opt = document.createElement('option');
      opt.value = typeof m === 'string' ? m : m.id;
      opt.textContent = typeof m === 'string' ? m : `${m.name} (${m.id})`;
      modalModelSelect.appendChild(opt);
    });

    updateUniversalModelSelect();
  }

  function updateUniversalModelSelect() {
    const provider = univProvider.value;
    univModel.innerHTML = '';
    const models = provider === 'bedrock' ? availableModels.bedrock : availableModels.local;
    models.forEach(m => {
      const opt = document.createElement('option');
      opt.value = typeof m === 'string' ? m : m.id;
      opt.textContent = typeof m === 'string' ? m : `${m.name} (${m.id})`;
      univModel.appendChild(opt);
    });
  }

  univProvider.addEventListener('change', updateUniversalModelSelect);
  document.getElementById('modal-app-provider').addEventListener('change', populateModelDropdowns);

  // Fetch Applications
  async function loadApps() {
    try {
      const res = await apiFetch('/api/apps');
      if (!res.ok) throw new Error('Failed to fetch apps');
      allApps = await res.json();
      renderAppCards(allApps);
      renderGeneratorSelect(allApps);
    } catch (e) {
      console.error('Error loading apps', e);
    }
  }

  function renderAppCards(apps) {
    const container = document.getElementById('apps-container');
    container.innerHTML = '';

    if (apps.length === 0) {
      container.innerHTML = `<div class="card" style="grid-column: 1/-1; text-align: center; color: var(--text-muted);">No applications registered yet. Click 'New Application' to generate one.</div>`;
      return;
    }

    apps.forEach(app => {
      const card = document.createElement('div');
      card.className = 'app-card';
      card.innerHTML = `
        <div class="app-card-header">
          <div>
            <h3 class="app-title">${escapeHtml(app.name)}</h3>
            <span class="app-id-badge">${escapeHtml(app.appId)}</span>
          </div>
          <span class="badge ${app.provider === 'bedrock' ? 'badge-net' : ''}" style="background: rgba(16, 185, 129, 0.15); color: #34d399;">v${app.version}</span>
        </div>
        <p class="app-desc">${escapeHtml(app.description || 'No description provided.')}</p>
        <div class="app-meta-list">
          <div class="app-meta-row">
            <span>Provider:</span>
            <span>${escapeHtml(String(app.provider || '').toUpperCase())}</span>
          </div>
          <div class="app-meta-row">
            <span>Model:</span>
            <span style="font-family: var(--font-mono); font-size: 11px;">${escapeHtml(app.model)}</span>
          </div>
          <div class="app-meta-row">
            <span>Fallback:</span>
            <span>${app.fallbackModel ? escapeHtml(app.fallbackModel) : 'None'}</span>
          </div>
          <div class="app-meta-row">
            <span>Key Prefix:</span>
            <span style="font-family: var(--font-mono);">${escapeHtml(app.apiKeyPrefix || 'ug_live_***')}</span>
          </div>
        </div>
        <div class="app-card-actions" style="display:flex; gap:6px; flex-wrap:wrap;">
          <button class="btn btn-primary btn-sm" data-action="test">Test API</button>
          <button class="btn btn-outline btn-sm" data-action="mint-sts" data-requires-admin style="border-color: rgba(16,185,129,0.5); color:#34d399;">⚡ Mint STS</button>
          <button class="btn btn-danger btn-sm" data-action="delete" data-requires-admin>Delete</button>
        </div>
      `;
      card.dataset.appId = app.appId;
      card.querySelectorAll('button[data-action]').forEach(btn => {
        btn.addEventListener('click', () => {
          const id = card.dataset.appId;
          if (btn.dataset.action === 'test') selectAppForTest(id);
          else if (btn.dataset.action === 'mint-sts') openStsModalForApp(id);
          else if (btn.dataset.action === 'delete') deleteApp(id);
        });
      });

      container.appendChild(card);
    });

    const user = oktaUser();
    if (user) applyGroupVisibility(user);
  }

  function renderGeneratorSelect(apps) {
    const prevSelected = genAppSelect.value;
    genAppSelect.innerHTML = '';
    apps.forEach(app => {
      const opt = document.createElement('option');
      opt.value = app.appId;
      opt.textContent = `${app.name} (${app.appId})`;
      genAppSelect.appendChild(opt);
    });

    if (apps.length > 0) {
      if (prevSelected && apps.some(a => a.appId === prevSelected)) {
        genAppSelect.value = prevSelected;
      }
      const selected = apps.find(a => a.appId === genAppSelect.value) || apps[0];
      updateGeneratorView(selected);
    }
  }

  genAppSelect.addEventListener('change', () => {
    const selected = allApps.find(a => a.appId === genAppSelect.value);
    if (selected) updateGeneratorView(selected);
  });

  // Auth Mode Toggles (STS vs Long-term Key)
  btnModeSts.addEventListener('click', () => {
    activeAuthMode = 'sts';
    btnModeSts.classList.add('active');
    btnModeKey.classList.remove('active');
    genAuthBadge.textContent = 'Short-Term STS Secret';
    genAuthBadge.style.background = 'rgba(139, 92, 246, 0.2)';
    genAuthBadge.style.color = '#a78bfa';
    genStsControlsPanel.style.display = 'block';
    const selected = allApps.find(a => a.appId === genAppSelect.value);
    if (selected) updateGeneratorView(selected);
  });

  btnModeKey.addEventListener('click', () => {
    activeAuthMode = 'key';
    btnModeKey.classList.add('active');
    btnModeSts.classList.remove('active');
    genAuthBadge.textContent = 'Permanent Application Key';
    genAuthBadge.style.background = 'rgba(239, 68, 68, 0.2)';
    genAuthBadge.style.color = '#f87171';
    genStsControlsPanel.style.display = 'none';
    const selected = allApps.find(a => a.appId === genAppSelect.value);
    if (selected) updateGeneratorView(selected);
  });

  // Mint STS button in generator panel
  btnMintGenSts.addEventListener('click', async () => {
    const appId = genAppSelect.value;
    if (!appId) return;

    const duration = parseInt(genStsTtlSelect.value) || 3600;
    btnMintGenSts.disabled = true;
    btnMintGenSts.textContent = 'Minting...';

    try {
      const res = await apiFetch(`/api/apps/${encodeURIComponent(appId)}/sts-token?durationSeconds=${encodeURIComponent(duration)}`, {
        method: 'POST'
      });
      if (!res.ok) throw new Error('Failed to mint STS token');
      const data = await res.json();

      appStsCache[appId] = {
        token: data.token,
        expiresAt: data.expiresAt
      };

      genCurrentStsInput.value = data.token;
      const expiryDate = new Date(data.expiresAt);
      genStsExpiryText.textContent = `Valid for ${Math.round(data.durationSeconds / 60)} mins (Expires: ${expiryDate.toLocaleTimeString()})`;

      const selected = allApps.find(a => a.appId === appId);
      if (selected) updateGeneratorView(selected);
    } catch (err) {
      alert(`Error minting STS token: ${err.message}`);
    } finally {
      btnMintGenSts.disabled = false;
      btnMintGenSts.textContent = 'Mint New STS Token';
    }
  });

  btnCopyGenSts.addEventListener('click', () => {
    if (!genCurrentStsInput.value) return;
    navigator.clipboard.writeText(genCurrentStsInput.value);
    alert('STS Token copied to clipboard!');
  });

  function updateGeneratorView(app) {
    const host = window.location.origin;
    const endpoint = `${host}/gateway/${app.appId}/invoke`;
    genEndpointUrl.textContent = `/gateway/${app.appId}/invoke`;

    genAppDetails.innerHTML = `
      <div class="app-meta-list" style="border:none; padding:0; margin-bottom:12px;">
        <div class="app-meta-row"><span>System Prompt:</span><span style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(app.systemPrompt)}</span></div>
        <div class="app-meta-row"><span>Target Engine:</span><span>${escapeHtml(String(app.provider || '').toUpperCase())} (${escapeHtml(app.model || '')})</span></div>
        <div class="app-meta-row"><span>Default Temp / MaxTokens:</span><span>${app.temperature} / ${app.maxTokens}</span></div>
      </div>
    `;

    // Check if we have cached STS token for this app
    const cachedSts = appStsCache[app.appId];
    if (cachedSts) {
      genCurrentStsInput.value = cachedSts.token;
      const expiry = new Date(cachedSts.expiresAt);
      genStsExpiryText.textContent = `Active STS Token (Expires: ${expiry.toLocaleTimeString()})`;
    } else {
      genCurrentStsInput.value = '';
      genStsExpiryText.textContent = 'No active STS token yet. Click "Mint New STS Token" to generate.';
    }

    updateCodeSnippet(app, endpoint);
  }

  function updateCodeSnippet(app, endpoint) {
    const host = window.location.origin;
    const cachedSts = appStsCache[app.appId]?.token || 'ug_sts_eyJhbGciOi...';
    const authHeaderValue = activeAuthMode === 'sts' ? cachedSts : 'YOUR_APP_API_KEY';
    const authComment = activeAuthMode === 'sts' ? 'Short Temporary Secret (STS token)' : 'Permanent Application API Key';

    if (activeLang === 'curl') {
      if (activeAuthMode === 'sts') {
        genCodeSnippet.textContent = `# Step 1 (Optional): Mint Short-Term STS Token from long-term key:
# curl -X POST "${host}/gateway/sts/token" -H "X-API-Key: YOUR_APP_API_KEY" -d '{"durationSeconds": 3600}'

# Step 2: Invoke Gateway using Short-Term STS Token (ug_sts_...)
curl -X POST "${endpoint}" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer ${authHeaderValue}" \\
  -d '{
    "input": "User query message",
    "sessionId": "sess_abc123"
  }'`;
      } else {
        genCodeSnippet.textContent = `curl -X POST "${endpoint}" \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ${authHeaderValue}" \\
  -d '{
    "input": "User query message",
    "sessionId": "sess_abc123"
  }'`;
      }
    } else if (activeLang === 'csharp') {
      const headerCode = activeAuthMode === 'sts'
        ? `client.DefaultRequestHeaders.Add("Authorization", "Bearer ${authHeaderValue}");`
        : `client.DefaultRequestHeaders.Add("X-API-Key", "${authHeaderValue}");`;

      genCodeSnippet.textContent = `using var client = new HttpClient();
// ${authComment}
${headerCode}

var payload = new {
    input = "User query message",
    sessionId = "sess_abc123"
};

var response = await client.PostAsJsonAsync("${endpoint}", payload);
var result = await response.Content.ReadFromJsonAsync<UniversalResponse>();
Console.WriteLine(result?.Output);`;
    } else if (activeLang === 'python') {
      const headerLine = activeAuthMode === 'sts'
        ? `    "Authorization": "Bearer ${authHeaderValue}"`
        : `    "X-API-Key": "${authHeaderValue}"`;

      genCodeSnippet.textContent = `import requests

url = "${endpoint}"
# ${authComment}
headers = {
    "Content-Type": "application/json",
${headerLine}
}
data = {
    "input": "User query message",
    "sessionId": "sess_abc123"
}

resp = requests.post(url, headers=headers, json=data)
print(resp.json()["output"])`;
    } else if (activeLang === 'java') {
      const headerCode = activeAuthMode === 'sts'
        ? `            .header("Authorization", "Bearer ${authHeaderValue}")`
        : `            .header("X-API-Key", "${authHeaderValue}")`;

      genCodeSnippet.textContent = `// Java 11+ Standard HttpClient
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class GatewayClient {
    public static void main(String[] args) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        String jsonPayload = """
            {
              "input": "User query message",
              "sessionId": "sess_abc123"
            }
            """;

        // ${authComment}
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("${endpoint}"))
            .header("Content-Type", "application/json")
${headerCode}
            .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());
    }
}`;
    } else if (activeLang === 'powershell') {
      const headerLine = activeAuthMode === 'sts'
        ? `    "Authorization" = "Bearer ${authHeaderValue}"`
        : `    "X-API-Key"     = "${authHeaderValue}"`;

      genCodeSnippet.textContent = `# PowerShell - Invoke-RestMethod (${authComment})
$headers = @{
    "Content-Type"  = "application/json"
${headerLine}
}

$body = @{
    input     = "User query message"
    sessionId = "sess_abc123"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "${endpoint}" \`
    -Method Post \`
    -Headers $headers \`
    -Body $body

Write-Output $response.output`;
    }
  }

  codeTabBtns.forEach(b => {
    b.addEventListener('click', () => {
      codeTabBtns.forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      activeLang = b.dataset.lang;
      const selected = allApps.find(a => a.appId === genAppSelect.value);
      if (selected) updateGeneratorView(selected);
    });
  });

  // App Invocation Test
  btnRunAppTest.addEventListener('click', async () => {
    const appId = genAppSelect.value;
    if (!appId) return;

    const input = document.getElementById('test-input').value;
    const session = document.getElementById('test-session').value;
    const temp = document.getElementById('test-temp').value;

    btnRunAppTest.disabled = true;
    btnRunAppTest.textContent = 'Invoking Gateway...';

    const respArea = document.getElementById('app-test-response-area');
    respArea.style.display = 'block';
    document.getElementById('res-output').textContent = 'Processing request across guardrails & routing layer...';

    try {
      const payload = {
        input: input,
        sessionId: session || undefined,
        temperature: temp ? parseFloat(temp) : undefined
      };

      const res = await apiFetch(`/api/apps/${encodeURIComponent(appId)}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await res.json();

      document.getElementById('res-latency').textContent = `${data.latency_ms || 0} ms`;
      document.getElementById('res-tokens').textContent = `${data.tokens?.total || 0} (in: ${data.tokens?.input || 0}, out: ${data.tokens?.output || 0})`;
      document.getElementById('res-provider').textContent = data.provider || 'unknown';
      document.getElementById('res-fallback').textContent = data.fallback_used ? 'YES' : 'NO';

      if (data.error) {
        document.getElementById('res-output').innerHTML = `<span style="color:var(--accent-red);">Error [${data.error.code}]: ${escapeHtml(data.error.message)} ${data.error.details ? '<br/><small>' + escapeHtml(data.error.details) + '</small>' : ''}</span>`;
      } else {
        document.getElementById('res-output').textContent = data.output || '(Empty response)';
      }
    } catch (e) {
      document.getElementById('res-output').textContent = `Invocation failed: ${e.message}`;
    } finally {
      btnRunAppTest.disabled = false;
      btnRunAppTest.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Execute Invocations`;
    }
  });

  // Universal Invocation Test
  btnRunUnivTest.addEventListener('click', async () => {
    const provider = univProvider.value;
    const model = univModel.value;
    const system = document.getElementById('univ-system').value;
    const input = document.getElementById('univ-input').value;
    const temp = parseFloat(document.getElementById('univ-temp').value) || 0.7;
    const maxTokens = parseInt(document.getElementById('univ-tokens').value) || 1024;
    const adminKeyOrToken = univApiKey?.value?.trim() || '';

    const respArea = document.getElementById('univ-response-area');
    respArea.innerHTML = '<p>Dispatching universal request through guardrails...</p>';
    btnRunUnivTest.disabled = true;

    try {
      const payload = {
        model,
        provider,
        system,
        input,
        temperature: temp,
        max_tokens: maxTokens
      };

      const headers = {
        'Content-Type': 'application/json'
      };

      if (adminKeyOrToken) {
        headers['X-API-Key'] = adminKeyOrToken;
      }

      const res = await fetch('/gateway/universal/invoke', {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      
      if (data.error) {
        respArea.innerHTML = `
          <div class="response-meta">
            <span class="meta-item">Status: <strong style="color:var(--accent-red)">Unauthorized / Error</strong></span>
          </div>
          <div class="response-output-box">
            <label>Error Details:</label>
            <div class="response-text" style="color:var(--accent-red)">[${escapeHtml(data.error.code || 'ERROR')}]: ${escapeHtml(data.error.message || '')}</div>
          </div>
        `;
      } else {
        respArea.innerHTML = `
          <div class="response-meta">
            <span class="meta-item">Latency: <strong>${data.latency_ms || 0} ms</strong></span>
            <span class="meta-item">Tokens: <strong>${data.tokens?.total || 0}</strong></span>
            <span class="meta-item">Provider: <strong>${escapeHtml(data.provider || '')}</strong></span>
          </div>
          <div class="response-output-box">
            <label>Generated Output:</label>
            <div class="response-text">${escapeHtml(data.output || '')}</div>
          </div>
        `;
      }
    } catch (e) {
      respArea.innerHTML = `<div style="color:var(--accent-red)">Request failed: ${escapeHtml(e.message)}</div>`;
    } finally {
      btnRunUnivTest.disabled = false;
    }
  });

  // Telemetry & Metrics
  async function loadMetrics() {
    try {
      const res = await apiFetch('/api/metrics');
      if (!res.ok) return;
      const data = await res.json();

      document.getElementById('kpi-total-req').textContent = data.totalRequests || 0;
      document.getElementById('kpi-gr-redacted').textContent = data.guardrailRedactedCount || 0;
      document.getElementById('kpi-gr-blocked').textContent = data.guardrailBlockedCount || 0;
      document.getElementById('kpi-total-tokens').textContent = (data.totalTokens || 0).toLocaleString();

      const tbody = document.getElementById('logs-table-body');
      tbody.innerHTML = '';

      if (!data.recentLogs || data.recentLogs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted);">No invocation logs recorded yet.</td></tr>';
        return;
      }

      data.recentLogs.forEach(log => {
        const tr = document.createElement('tr');
        const time = new Date(log.timestamp).toLocaleTimeString();
        const grBadge = log.guardrailAction === 'Redacted' ? '<span class="badge" style="background:#22d3ee; color:#04241b;">Redacted</span>' :
                        log.guardrailAction === 'Blocked' ? '<span class="badge" style="background:#ef4444; color:#fff;">Blocked</span>' :
                        '<span class="badge" style="background:rgba(255,255,255,0.1); color:var(--text-muted);">Passed</span>';

        tr.innerHTML = `
          <td>${time}</td>
          <td><code>${escapeHtml(log.appId || 'universal')}</code></td>
          <td>${escapeHtml(log.provider || '-')}</td>
          <td style="font-family:var(--font-mono); font-size:11px;">${escapeHtml(log.model || '-')}</td>
          <td>${grBadge}</td>
          <td>${log.latencyMs} ms</td>
          <td>${log.totalTokens}</td>
          <td>${log.success ? '<span style="color:var(--accent-green)">Success</span>' : '<span style="color:var(--accent-red)">Error</span>'} ${log.fallbackUsed ? '<span class="badge" style="background:#f59e0b; color:#000;">Fallback</span>' : ''}</td>
        `;
        tbody.appendChild(tr);
      });
    } catch (e) {
      console.error('Failed to load metrics', e);
    }
  }

  // Modals handling
  btnOpenCreateModal.addEventListener('click', () => {
    createModal.classList.add('active');
  });

  btnCloseCreateModal.addEventListener('click', () => createModal.classList.remove('active'));
  btnCancelCreate.addEventListener('click', () => createModal.classList.remove('active'));
  btnCloseKeyModal.addEventListener('click', () => keyModal.classList.remove('active'));
  btnDoneKey.addEventListener('click', () => keyModal.classList.remove('active'));

  if (btnCloseStsModal) btnCloseStsModal.addEventListener('click', () => stsModal.classList.remove('active'));
  if (btnCloseStsModalBottom) btnCloseStsModalBottom.addEventListener('click', () => stsModal.classList.remove('active'));

  // Create App Form Submission
  createAppForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const payload = {
      appId: document.getElementById('modal-app-id').value,
      name: document.getElementById('modal-app-name').value,
      description: document.getElementById('modal-app-desc').value,
      provider: document.getElementById('modal-app-provider').value,
      model: document.getElementById('modal-app-model').value,
      systemPrompt: document.getElementById('modal-app-prompt').value,
      temperature: parseFloat(document.getElementById('modal-app-temp').value),
      maxTokens: parseInt(document.getElementById('modal-app-tokens').value),
      fallbackProvider: document.getElementById('modal-app-fallback-provider').value || null,
      fallbackModel: document.getElementById('modal-app-fallback-model').value || null,
      inputCostPerMillion: parseFloat(document.getElementById('modal-app-input-cost')?.value) || 0,
      outputCostPerMillion: parseFloat(document.getElementById('modal-app-output-cost')?.value) || 0
    };

    try {
      const res = await apiFetch('/api/apps', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const err = await res.json();
        alert(`Error: ${err.error || 'Failed to create app'}`);
        return;
      }

      const created = await res.json();
      createModal.classList.remove('active');
      createAppForm.reset();

      // Cache initial STS token
      if (created.stsToken) {
        appStsCache[created.app.appId] = {
          token: created.stsToken,
          expiresAt: created.stsExpiresAt
        };
      }

      // Show Key & STS Modal
      document.getElementById('key-modal-endpoint').value = `${window.location.origin}${created.endpointUrl}`;
      document.getElementById('key-modal-key').value = created.apiKey;
      document.getElementById('key-modal-sts').value = created.stsToken || '(STS Generated)';
      keyModal.classList.add('active');

      await loadApps();
    } catch (err) {
      alert(`Submission error: ${err.message}`);
    }
  });

  document.getElementById('btn-copy-key').addEventListener('click', () => {
    const keyInput = document.getElementById('key-modal-key');
    keyInput.select();
    navigator.clipboard.writeText(keyInput.value);
    alert('Permanent API Key copied to clipboard!');
  });

  document.getElementById('btn-copy-sts').addEventListener('click', () => {
    const stsInput = document.getElementById('key-modal-sts');
    stsInput.select();
    navigator.clipboard.writeText(stsInput.value);
    alert('Short Temporary Secret (STS token) copied to clipboard!');
  });

  // On-demand STS Modal Actions
  window.openStsModalForApp = (appId) => {
    const app = allApps.find(a => a.appId === appId);
    if (!app) return;

    selectedAppForStsModal = app;
    document.getElementById('sts-modal-app-name').value = `${app.name} (${app.appId})`;
    document.getElementById('sts-modal-result').style.display = 'none';
    stsModal.classList.add('active');
  };

  if (btnMintStsModal) {
    btnMintStsModal.addEventListener('click', async () => {
      if (!selectedAppForStsModal) return;

      const duration = parseInt(document.getElementById('sts-modal-duration').value) || 3600;
      btnMintStsModal.disabled = true;
      btnMintStsModal.textContent = 'Minting STS Token...';

      try {
        const res = await apiFetch(`/api/apps/${encodeURIComponent(selectedAppForStsModal.appId)}/sts-token?durationSeconds=${encodeURIComponent(duration)}`, {
          method: 'POST'
        });

        if (!res.ok) throw new Error('Failed to mint STS token');
        const data = await res.json();

        appStsCache[selectedAppForStsModal.appId] = {
          token: data.token,
          expiresAt: data.expiresAt
        };

        document.getElementById('sts-modal-token-output').value = data.token;
        const expiry = new Date(data.expiresAt);
        document.getElementById('sts-modal-meta').textContent = `Expires at: ${expiry.toLocaleString()} (${Math.round(data.durationSeconds / 60)} minutes TTL)`;
        document.getElementById('sts-modal-result').style.display = 'block';

        // Update generator if this app is selected
        if (genAppSelect.value === selectedAppForStsModal.appId) {
          updateGeneratorView(selectedAppForStsModal);
        }
      } catch (err) {
        alert(`Error: ${err.message}`);
      } finally {
        btnMintStsModal.disabled = false;
        btnMintStsModal.textContent = 'Mint STS Token';
      }
    });
  }

  if (btnCopyStsModalToken) {
    btnCopyStsModalToken.addEventListener('click', () => {
      const tokenInput = document.getElementById('sts-modal-token-output');
      tokenInput.select();
      navigator.clipboard.writeText(tokenInput.value);
      alert('STS Token copied to clipboard!');
    });
  }

  btnRefreshStatus.addEventListener('click', () => {
    loadStsStatus();
    loadApps();
    loadMetrics();
    loadGuardrailConfig();
  });

  // Global window functions for cards
  window.selectAppForTest = (appId) => {
    navButtons.forEach(b => {
      if (b.dataset.tab === 'generator') b.click();
    });
    genAppSelect.value = appId;
    const selected = allApps.find(a => a.appId === appId);
    if (selected) updateGeneratorView(selected);
  };

  window.deleteApp = async (appId) => {
    if (!confirm(`Are you sure you want to delete application '${appId}'?`)) return;
    try {
      const res = await apiFetch(`/api/apps/${encodeURIComponent(appId)}`, { method: 'DELETE' });
      if (res.ok) {
        await loadApps();
      }
    } catch (e) {
      alert('Delete failed');
    }
  };

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  // ==========================================================================
  // Usage & Spend
  // ==========================================================================

  const RANGE_LABELS = { '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days' };

  let billingRange = '7d';
  let billingGrain = 'daily';
  let billingCurrency = 'USD';
  let billingData = null;
  let appSort = { key: 'totalCost', dir: 'desc' };

  function money(value, places) {
    const n = Number(value) || 0;
    // Sub-cent totals would all collapse to $0.00 and read as a broken page, so small
    // amounts keep enough precision to show that something was in fact spent.
    const decimals = places !== undefined ? places : (n > 0 && n < 0.01 ? 4 : 3);
    try {
      return new Intl.NumberFormat(undefined, {
        style: 'currency', currency: billingCurrency,
        minimumFractionDigits: decimals, maximumFractionDigits: decimals
      }).format(n);
    } catch (e) {
      return '$' + n.toFixed(decimals);
    }
  }

  function compact(value) {
    const n = Number(value) || 0;
    if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return String(Math.round(n));
  }

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function isCloud(app) {
    return String(app.provider || '').toLowerCase() === 'bedrock' ||
           String(app.provider || '').toLowerCase() === 'aws';
  }

  // --- Sparkline -------------------------------------------------------------
  // Hand-drawn SVG rather than a charting library: one polyline and a fill is the
  // whole requirement, and a dependency would outweigh it.

  function drawSpark(svg, series, opts) {
    const values = (series || []).map(v => Number(v) || 0);
    const w = 100, h = 30, pad = 2;
    svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
    svg.innerHTML = '';

    if (values.length === 0) return;

    const max = Math.max.apply(null, values);
    const min = Math.min.apply(null, values);
    const span = max - min;

    // A flat series has no shape to show. Draw a dashed baseline instead of a
    // misleading line pinned to the top or bottom of the box.
    if (max <= 0 || span === 0) {
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', pad); line.setAttribute('x2', w - pad);
      line.setAttribute('y1', h / 2); line.setAttribute('y2', h / 2);
      line.setAttribute('class', 'spark-flat');
      svg.appendChild(line);
      return;
    }

    const step = values.length > 1 ? (w - pad * 2) / (values.length - 1) : 0;
    const y = v => h - pad - ((v - min) / span) * (h - pad * 2);
    const pts = values.map((v, i) => [pad + i * step, y(v)]);

    if (opts && opts.area) {
      const area = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
      area.setAttribute('points',
        `${pad},${h - pad} ` + pts.map(p => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ') +
        ` ${w - pad},${h - pad}`);
      area.setAttribute('class', 'spark-area');
      svg.appendChild(area);
    }

    const line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    line.setAttribute('points', pts.map(p => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' '));
    line.setAttribute('class', 'spark-line');
    svg.appendChild(line);

    const last = pts[pts.length - 1];
    const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    dot.setAttribute('cx', last[0].toFixed(1));
    dot.setAttribute('cy', last[1].toFixed(1));
    dot.setAttribute('r', '1.9');
    dot.setAttribute('class', 'spark-dot');
    svg.appendChild(dot);
  }

  // --- Load ------------------------------------------------------------------

  async function loadBilling() {
    try {
      const url = '/api/billing/summary?range=' + encodeURIComponent(billingRange) +
                  '&grain=' + encodeURIComponent(billingGrain);
      const res = await apiFetch(url);
      if (!res.ok) return;

      billingData = await res.json();
      billingCurrency = billingData.currency || 'USD';

      renderNotices(billingData);
      renderHero(billingData);
      renderSeries(billingData);
      renderAnalytics(billingData);
      renderModelFilter(billingData);
      renderApps();

      setText('spend-range-label', RANGE_LABELS[billingRange] || billingRange);
      setText('spend-updated', new Date(billingData.generatedAt).toLocaleTimeString());
    } catch (e) {
      console.error('Failed to load spend', e);
    }
  }

  // --- Notices ---------------------------------------------------------------

  function notice(kind, text) {
    const el = document.createElement('div');
    el.className = 'bill-notice bill-notice-' + kind;
    el.textContent = text;
    return el;
  }

  function renderNotices(d) {
    const box = document.getElementById('billing-notices');
    if (!box) return;
    box.innerHTML = '';

    // Surface what makes a total untrustworthy. A confident figure resting on
    // guessed rates is worse than an annotated one.
    if (d.estimatedRequests > 0) {
      box.appendChild(notice('warn',
        d.estimatedRequests.toLocaleString() + ' request(s) were priced with the fallback rate ' +
        'because no rate card applied. Those charges are estimates.'));
    }
    if ((d.applicationsMissingRates || []).length > 0) {
      box.appendChild(notice('warn',
        'No rate card set for: ' + d.applicationsMissingRates.join(', ') +
        '. Set input and output cost per million tokens to bill these accurately.'));
    }
    if (d.unregisteredApplicationCount > 0) {
      box.appendChild(notice('info',
        d.unregisteredApplicationCount + ' application(s) billed in this window are no longer ' +
        'registered. Their history is still charged.'));
    }
  }

  // --- Hero ------------------------------------------------------------------

  function renderHero(d) {
    setText('spend-total', money(d.totalCost));

    const delta = document.getElementById('spend-delta');
    if (delta) {
      const pct = d.changeVsPreviousPercent;
      if (pct === null || pct === undefined) {
        delta.textContent = 'no prior period to compare';
        delta.className = 'delta';
      } else {
        const up = pct >= 0;
        delta.textContent = (up ? '▲ ' : '▼ ') + Math.abs(pct).toFixed(1) + '% vs prior period';
        delta.className = 'delta ' + (up ? 'delta-up' : 'delta-down');
      }
    }

    // Log-ish placement against the $0 / $1 / $10 / $25+ ticks, so both a $0.04
    // day and a $30 day land somewhere meaningful on the same track.
    const marker = document.getElementById('spend-scale-marker');
    if (marker) {
      const v = Number(d.totalCost) || 0;
      let pos;
      if (v <= 0) pos = 0;
      else if (v <= 1) pos = (v / 1) * 33.3;
      else if (v <= 10) pos = 33.3 + (Math.log10(v) / 1) * 33.3;
      else if (v <= 25) pos = 66.6 + ((v - 10) / 15) * 33.3;
      else pos = 100;
      marker.style.left = 'calc(' + Math.min(100, Math.max(0, pos)) + '% - 1.5px)';
    }

    const inputCost = (d.buckets || []).reduce((s, b) => s + (Number(b.inputCost) || 0), 0);
    const outputCost = (d.buckets || []).reduce((s, b) => s + (Number(b.outputCost) || 0), 0);

    setText('spend-input-cost', money(inputCost));
    setText('spend-output-cost', money(outputCost));
    setText('spend-input-tokens', compact(d.totalInputTokens) + ' tokens in');
    setText('spend-output-tokens', compact(d.totalOutputTokens) + ' tokens out');

    const eff = Number(d.tokenEfficiency) || 0;
    setText('spend-efficiency', eff.toFixed(3) + '×');
    const effMeter = document.getElementById('spend-efficiency-meter');
    // 4x output-per-input is a generous ceiling for a full bar; beyond that it clamps.
    if (effMeter) effMeter.style.width = Math.min(100, (eff / 4) * 100) + '%';

    const apps = d.applications || [];
    const top = apps.length > 0 ? apps[0] : null;
    setText('spend-top-app', top ? top.name : 'None');
    setText('spend-top-cost', money(top ? top.totalCost : 0, 2));
    setText('spend-top-share', (top ? (Number(top.shareOfTotalPercent) || 0).toFixed(1) : '0') + '% of spend');

    const spark = document.getElementById('spend-top-spark');
    if (spark) drawSpark(spark, top ? top.trend : [], { area: true });
  }

  // --- Time series -----------------------------------------------------------

  function shortLabel(period) {
    if (billingGrain === 'monthly') return period;
    if (billingGrain === 'weekly') return period.slice(5);
    // Daily: a weekday name reads faster than a date when the window is a week.
    const d = new Date(period + 'T00:00:00Z');
    if (isNaN(d)) return period.slice(5);
    return billingRange === '7d' || billingRange === '24h'
      ? d.toLocaleDateString(undefined, { weekday: 'short' })
      : period.slice(5);
  }

  function renderSeries(d) {
    const host = document.getElementById('spend-series');
    if (!host) return;

    host.innerHTML = '';
    const buckets = d.buckets || [];

    if (buckets.length === 0) {
      host.innerHTML = '<div class="spend-empty">No usage recorded in this window.</div>';
      return;
    }

    const max = Math.max.apply(null, buckets.map(b => Number(b.totalCost) || 0));

    buckets.forEach(b => {
      const cost = Number(b.totalCost) || 0;
      const col = document.createElement('div');
      col.className = 'series-col' + (cost === 0 ? ' is-empty' : '');
      col.title = b.period + '\n' + money(cost) + '\n' +
                  Number(b.requests).toLocaleString() + ' requests\n' +
                  compact(b.totalTokens) + ' tokens';

      const plot = document.createElement('div');
      plot.className = 'series-plot';

      const bar = document.createElement('div');
      bar.className = 'series-bar';
      // Any non-zero spend gets a visible floor, so a small real charge does not
      // render identically to a period with no usage at all.
      bar.style.height = (cost > 0 ? Math.max((cost / max) * 100, 4) : 0) + '%';
      plot.appendChild(bar);

      const value = document.createElement('div');
      value.className = 'series-value';
      value.textContent = money(cost, cost > 0 && cost < 0.01 ? 3 : 2);

      const label = document.createElement('div');
      label.className = 'series-label';
      label.textContent = shortLabel(b.period);

      col.appendChild(plot);
      col.appendChild(value);
      col.appendChild(label);
      host.appendChild(col);
    });

    // Open on the most recent period: the right edge is what anyone came to see.
    const wrap = host.parentElement;
    if (wrap) wrap.scrollLeft = wrap.scrollWidth;
  }

  // --- Analytics -------------------------------------------------------------

  function bar(label, valueText, fraction, color) {
    const li = document.createElement('li');
    li.innerHTML =
      '<span>' + escapeHtml(label) + '</span>' +
      '<span class="bl-track"><span class="bl-fill" style="width:' +
        Math.min(100, Math.max(0, fraction * 100)).toFixed(1) + '%;background:' + color + '"></span></span>' +
      '<span class="bl-value">' + escapeHtml(valueText) + '</span>';
    return li;
  }

  function facts(pairs) {
    const dl = document.createDocumentFragment();
    pairs.forEach(([k, v]) => {
      const row = document.createElement('div');
      row.innerHTML = '<dt>' + escapeHtml(k) + '</dt><dd>' + escapeHtml(v) + '</dd>';
      dl.appendChild(row);
    });
    return dl;
  }

  function renderAnalytics(d) {
    const inTok = Number(d.totalInputTokens) || 0;
    const outTok = Number(d.totalOutputTokens) || 0;
    const total = inTok + outTok;

    const inCost = (d.buckets || []).reduce((s, b) => s + (Number(b.inputCost) || 0), 0);
    const outCost = (d.buckets || []).reduce((s, b) => s + (Number(b.outputCost) || 0), 0);
    const totalCost = Number(d.totalCost) || 0;
    const requests = Number(d.totalRequests) || 0;
    const apps = d.applications || [];

    const tokenBars = document.getElementById('token-bars');
    if (tokenBars) {
      tokenBars.innerHTML = '';
      tokenBars.appendChild(bar('Input tokens', compact(inTok), total ? inTok / total : 0, 'var(--input)'));
      tokenBars.appendChild(bar('Output tokens', compact(outTok), total ? outTok / total : 0, 'var(--output)'));
      tokenBars.appendChild(bar('Total tokens', compact(total), total ? 1 : 0,
        'linear-gradient(90deg,var(--input),var(--output))'));
    }

    const tokenFacts = document.getElementById('token-facts');
    if (tokenFacts) {
      tokenFacts.innerHTML = '';
      tokenFacts.appendChild(facts([
        ['Token efficiency', (Number(d.tokenEfficiency) || 0).toFixed(3) + '×'],
        ['Cost per 1K tokens', money(total ? (totalCost / total) * 1000 : 0, 4)],
        ['Tokens per request', requests ? Math.round(total / requests).toLocaleString() : '0'],
        ['Largest consumer', apps.length ? apps.slice().sort((a, b) =>
          (b.totalTokens || 0) - (a.totalTokens || 0))[0].name : 'None']
      ]));
    }

    const costBars = document.getElementById('cost-bars');
    if (costBars) {
      costBars.innerHTML = '';
      costBars.appendChild(bar('Input cost', money(inCost), totalCost ? inCost / totalCost : 0, 'var(--input)'));
      costBars.appendChild(bar('Output cost', money(outCost), totalCost ? outCost / totalCost : 0, 'var(--output)'));
      costBars.appendChild(bar('Total cost', money(totalCost), totalCost ? 1 : 0,
        'linear-gradient(90deg,var(--input),var(--output))'));
    }

    const costFacts = document.getElementById('cost-facts');
    if (costFacts) {
      costFacts.innerHTML = '';
      const billedApps = apps.length;
      costFacts.innerHTML = '';
      costFacts.appendChild(facts([
        ['Cost per request', money(requests ? totalCost / requests : 0, 4)],
        ['Cost per app', money(billedApps ? totalCost / billedApps : 0)],
        ['Output share of cost', (totalCost ? (outCost / totalCost) * 100 : 0).toFixed(1) + '%'],
        ['Bedrock cloud share', (totalCost ? ((Number(d.cloudCost) || 0) / totalCost) * 100 : 0).toFixed(1) + '%']
      ]));
    }
  }

  // --- Applications table ----------------------------------------------------

  function renderModelFilter(d) {
    const select = document.getElementById('apps-model');
    if (!select) return;

    const current = select.value;
    select.innerHTML = '<option value="">All models</option>';
    (d.models || []).forEach(m => {
      const opt = document.createElement('option');
      opt.value = m;
      opt.textContent = m;
      select.appendChild(opt);
    });
    select.value = current;
  }

  function filteredApps() {
    if (!billingData) return [];

    const term = (document.getElementById('apps-search')?.value || '').trim().toLowerCase();
    const model = document.getElementById('apps-model')?.value || '';
    const host = document.getElementById('apps-host')?.value || '';
    const minCost = parseFloat(document.getElementById('apps-min-cost')?.value);
    const minEff = parseFloat(document.getElementById('apps-min-eff')?.value);

    let rows = (billingData.applications || []).filter(a => {
      if (term && !((a.name || '') + ' ' + (a.appId || '') + ' ' + (a.model || ''))
            .toLowerCase().includes(term)) return false;
      if (model && a.model !== model) return false;
      if (host === 'cloud' && !isCloud(a)) return false;
      if (host === 'local' && isCloud(a)) return false;
      if (!isNaN(minCost) && (Number(a.totalCost) || 0) < minCost) return false;
      if (!isNaN(minEff) && (Number(a.tokenEfficiency) || 0) < minEff) return false;
      return true;
    });

    const key = appSort.key, dir = appSort.dir === 'asc' ? 1 : -1;
    rows.sort((a, b) => {
      const x = a[key], y = b[key];
      if (typeof x === 'string' || typeof y === 'string') {
        return String(x || '').localeCompare(String(y || '')) * dir;
      }
      return ((Number(x) || 0) - (Number(y) || 0)) * dir;
    });

    return rows;
  }

  function renderApps() {
    const tbody = document.getElementById('apps-rows');
    if (!tbody || !billingData) return;

    const rows = filteredApps();
    const totalApps = (billingData.applications || []).length;
    setText('apps-count', rows.length + ' of ' + totalApps + ' app' + (totalApps === 1 ? '' : 's'));

    tbody.innerHTML = '';

    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="spend-empty">' +
        (totalApps === 0 ? 'No application usage in this window.' : 'No apps match these filters.') +
        '</td></tr>';
      return;
    }

    rows.forEach(a => {
      const cloud = isCloud(a);
      const hasRate = (Number(a.inputCostPerMillion) || 0) > 0 || (Number(a.outputCostPerMillion) || 0) > 0;
      const share = Math.min(100, Number(a.shareOfTotalPercent) || 0);

      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td><div class="cell-app"><strong>' + escapeHtml(a.name) +
          (a.isRegistered ? '' : '<span class="tag tag-deleted">deleted</span>') +
          (hasRate ? '' : '<span class="tag tag-norate">no rate</span>') +
          '</strong><span class="host-tag"><span class="host-dot' + (cloud ? ' cloud' : '') + '"></span>' +
          (cloud ? 'Cloud' : 'Local') + '</span></div></td>' +
        '<td><div class="cell-model"><span class="model-name">' + escapeHtml(a.model) + '</span>' +
          '<span class="rate-chip" title="Input ' + money(a.inputCostPerMillion, 2) +
          ' / output ' + money(a.outputCostPerMillion, 2) + ' per 1M tokens">rates</span></div></td>' +
        '<td class="num">' + compact(a.inputTokens) + '</td>' +
        '<td class="num">' + compact(a.outputTokens) + '</td>' +
        '<td class="num">' + compact(a.totalTokens) + '</td>' +
        '<td class="num">' + money(a.totalCost) + '</td>' +
        '<td><div class="share-cell"><span class="share-track"><span class="share-fill" style="width:' +
          share + '%"></span></span><span class="share-pct">' + share.toFixed(1) + '%</span></div></td>' +
        '<td><svg class="spark-cell" preserveAspectRatio="none"></svg></td>' +
        '<td class="num"><button class="row-menu" type="button" aria-label="Details for ' +
          escapeHtml(a.name) + '">&#8943;</button></td>';

      drawSpark(tr.querySelector('.spark-cell'), a.trend, { area: false });

      tr.querySelector('.row-menu').addEventListener('click', () => {
        const lines = [
          a.name + '  (' + a.appId + ')',
          'Model: ' + a.model + '  ·  ' + (cloud ? 'Cloud' : 'Local'),
          'Rates: ' + money(a.inputCostPerMillion, 2) + ' in / ' + money(a.outputCostPerMillion, 2) + ' out per 1M',
          'Requests: ' + Number(a.requests).toLocaleString(),
          'Tokens: ' + compact(a.inputTokens) + ' in / ' + compact(a.outputTokens) + ' out',
          'Cost: ' + money(a.totalCost) + '  (' + share.toFixed(1) + '% of spend)',
          'Cost per request: ' + money(a.averageCostPerRequest, 4),
          'Token efficiency: ' + (Number(a.tokenEfficiency) || 0).toFixed(3) + '×',
          'Cloud / local: ' + money(a.cloudCost) + ' / ' + money(a.localCost)
        ];
        alert(lines.join('\n'));
      });

      tbody.appendChild(tr);
    });
  }

  // --- Controls --------------------------------------------------------------

  document.querySelectorAll('#pane-billing .seg-btn[data-range]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#pane-billing .seg-btn[data-range]')
        .forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      billingRange = btn.dataset.range;
      loadBilling();
    });
  });

  document.querySelectorAll('#pane-billing .seg-btn[data-grain]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#pane-billing .seg-btn[data-grain]')
        .forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      billingGrain = btn.dataset.grain;
      loadBilling();
    });
  });

  ['apps-search', 'apps-model', 'apps-host', 'apps-min-cost', 'apps-min-eff'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', renderApps);
  });

  const appsClear = document.getElementById('apps-clear');
  if (appsClear) {
    appsClear.addEventListener('click', () => {
      ['apps-search', 'apps-model', 'apps-host', 'apps-min-cost', 'apps-min-eff'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
      });
      renderApps();
    });
  }

  document.querySelectorAll('#pane-billing .spend-table th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      appSort = { key: key, dir: appSort.key === key && appSort.dir === 'desc' ? 'asc' : 'desc' };
      document.querySelectorAll('#pane-billing .spend-table th[data-sort]')
        .forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
      th.classList.add(appSort.dir === 'asc' ? 'sort-asc' : 'sort-desc');
      renderApps();
    });
  });

  const billingRefresh = document.getElementById('btn-billing-refresh');
  if (billingRefresh) billingRefresh.addEventListener('click', loadBilling);

  const copyEndpoint = document.getElementById('btn-copy-billing-endpoint');
  if (copyEndpoint) {
    copyEndpoint.addEventListener('click', async () => {
      const url = window.location.origin + '/api/billing/summary?range=' + billingRange +
                  '&grain=' + billingGrain;
      try {
        await navigator.clipboard.writeText(url);
        const original = copyEndpoint.innerHTML;
        copyEndpoint.textContent = 'Copied';
        setTimeout(() => { copyEndpoint.innerHTML = original; }, 1400);
      } catch (e) {
        window.prompt('Billing API endpoint', url);
      }
    });
  }

  document.querySelectorAll('#pane-billing [data-export]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const format = btn.dataset.export;
      // The endpoint is authenticated, so this is fetched with the session token and the
      // resulting blob handed to the browser rather than opened as a plain link.
      const res = await apiFetch('/api/billing/export?format=' + encodeURIComponent(format) +
                                 '&range=' + encodeURIComponent(billingRange) +
                                 '&grain=' + encodeURIComponent(billingGrain));
      if (!res.ok) return;

      const blob = await res.blob();
      const ext = format === 'xlsx' ? 'xlsx' : format;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'gateway-billing-' + billingRange + '.' + ext;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  });

  // Initial load. Nothing is fetched until there is a session, so an unauthenticated
  // visitor sees the sign-in form rather than a wall of failed requests.
  const existingUser = oktaUser();
  if (!oktaToken() || !existingUser) {
    showLogin();
    return;
  }

  hideLogin(existingUser);
  applyGroupVisibility(existingUser);

  loadStsStatus();
  loadModels();
  loadApps();
  loadGuardrailConfig();
});
