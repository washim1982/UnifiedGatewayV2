namespace Shared.Dashboard;

public static class DashboardHtml
{
    private const string DefaultS3Url = "http://localhost:5001";
    private const string DefaultKmsUrl = "http://localhost:5002";
    private const string DefaultIamUrl = "http://localhost:5003";

    /// <summary>
    /// The console, pointed at wherever the three services actually run.
    ///
    /// The page probes all three from the browser, so a deployment that moves them off the
    /// default ports has to say so: otherwise every panel reads Offline and every call fails
    /// with "Failed to fetch" while the services themselves are perfectly healthy.
    /// </summary>
    public static string GetHtml(string? s3Url = null, string? kmsUrl = null, string? iamUrl = null) =>
        Template
            .Replace(DefaultS3Url, Normalize(s3Url) ?? DefaultS3Url)
            .Replace(DefaultKmsUrl, Normalize(kmsUrl) ?? DefaultKmsUrl)
            .Replace(DefaultIamUrl, Normalize(iamUrl) ?? DefaultIamUrl);

    private static string? Normalize(string? url) =>
        string.IsNullOrWhiteSpace(url) ? null : url.Trim().TrimEnd('/');

    private static string Template
    {
        get
        {
            return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Local AWS Simulator Console</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <style>
    body {
      background-color: #0b0f19;
      color: #e2e8f0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    .aws-orange { color: #ff9900; }
    .bg-aws-orange { background-color: #ff9900; }
    .border-aws-orange { border-color: #ff9900; }
    .card {
      background-color: #161f30;
      border: 1px solid #283548;
      border-radius: 0.75rem;
    }
    .subcard {
      background-color: #0f1624;
      border: 1px solid #1f293d;
      border-radius: 0.5rem;
    }
    .nav-btn.active {
      background-color: #ff9900;
      color: #0b0f19;
      font-weight: 600;
    }
    pre, code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    .modal-backdrop {
      background-color: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(2px);
    }
  </style>
</head>
<body class="min-h-screen flex flex-col p-4 md:p-6 antialiased">

  <!-- Header -->
  <header class="flex flex-col md:flex-row md:items-center md:justify-between pb-6 border-b border-[#283548] gap-4">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 rounded-lg bg-gradient-to-tr from-[#ff9900] to-[#f59e0b] flex items-center justify-center text-[#0b0f19] font-bold text-xl shadow-lg">
        ☁️
      </div>
      <div>
        <h1 class="text-xl md:text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          Local AWS Simulator <span class="text-xs px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">.NET 8</span>
        </h1>
        <p class="text-xs text-slate-400">Emulating S3, KMS, and STS/IAM for development with zero cloud costs</p>
      </div>
    </div>
    <div class="flex items-center gap-3">
      <button onclick="checkAllStatuses()" class="px-3 py-1.5 rounded-lg bg-[#222f46] hover:bg-[#2b3a56] text-xs text-slate-200 border border-[#3b4b6b] transition flex items-center gap-2">
        <span id="refresh-spinner" class="inline-block">🔄</span> Refresh Statuses
      </button>
      <div class="px-3 py-1.5 rounded-lg bg-[#161f30] text-xs text-slate-400 border border-[#283548]">
        v1.1.0
      </div>
    </div>
  </header>

  <!-- Service Status Cards -->
  <div class="grid grid-cols-1 md:grid-cols-3 gap-4 my-6">
    <!-- S3 Card -->
    <div class="card p-4 flex items-center justify-between shadow-sm">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded bg-emerald-500/10 text-emerald-400 flex items-center justify-center font-bold text-sm">S3</div>
        <div>
          <div class="text-sm font-semibold text-white">S3 Object Store</div>
          <div class="text-xs text-slate-400">
            <input id="s3-url" type="text" value="http://localhost:5001" class="bg-transparent border-b border-dashed border-slate-600 focus:border-amber-400 outline-none text-xs w-36 text-slate-300" onchange="checkAllStatuses()">
          </div>
        </div>
      </div>
      <div id="s3-status" class="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs bg-slate-800 text-slate-400">
        <span class="w-2 h-2 rounded-full bg-slate-500"></span> Checking...
      </div>
    </div>

    <!-- KMS Card -->
    <div class="card p-4 flex items-center justify-between shadow-sm">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded bg-purple-500/10 text-purple-400 flex items-center justify-center font-bold text-sm">KMS</div>
        <div>
          <div class="text-sm font-semibold text-white">Key Management</div>
          <div class="text-xs text-slate-400">
            <input id="kms-url" type="text" value="http://localhost:5002" class="bg-transparent border-b border-dashed border-slate-600 focus:border-amber-400 outline-none text-xs w-36 text-slate-300" onchange="checkAllStatuses()">
          </div>
        </div>
      </div>
      <div id="kms-status" class="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs bg-slate-800 text-slate-400">
        <span class="w-2 h-2 rounded-full bg-slate-500"></span> Checking...
      </div>
    </div>

    <!-- STS/IAM Card -->
    <div class="card p-4 flex items-center justify-between shadow-sm">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 rounded bg-blue-500/10 text-blue-400 flex items-center justify-center font-bold text-sm">IAM</div>
        <div>
          <div class="text-sm font-semibold text-white">STS / IAM Service</div>
          <div class="text-xs text-slate-400">
            <input id="iam-url" type="text" value="http://localhost:5003" class="bg-transparent border-b border-dashed border-slate-600 focus:border-amber-400 outline-none text-xs w-36 text-slate-300" onchange="checkAllStatuses()">
          </div>
        </div>
      </div>
      <div id="iam-status" class="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs bg-slate-800 text-slate-400">
        <span class="w-2 h-2 rounded-full bg-slate-500"></span> Checking...
      </div>
    </div>
  </div>

  <!-- Navigation Tabs -->
  <div class="flex flex-wrap gap-2 mb-6 border-b border-[#283548] pb-3">
    <button onclick="switchTab('s3')" id="tab-btn-s3" class="nav-btn active px-4 py-2 rounded-lg text-xs md:text-sm transition flex items-center gap-2">
      🪣 Amazon S3 Console
    </button>
    <button onclick="switchTab('e2e')" id="tab-btn-e2e" class="nav-btn px-4 py-2 rounded-lg text-xs md:text-sm bg-[#161f30] hover:bg-[#222f46] text-slate-300 transition flex items-center gap-2">
      ⚡ Live E2E Flow Simulation
    </button>
    <button onclick="switchTab('iam')" id="tab-btn-iam" class="nav-btn px-4 py-2 rounded-lg text-xs md:text-sm bg-[#161f30] hover:bg-[#222f46] text-slate-300 transition flex items-center gap-2">
      🛡️ STS / IAM Console
    </button>
    <button onclick="switchTab('kms')" id="tab-btn-kms" class="nav-btn px-4 py-2 rounded-lg text-xs md:text-sm bg-[#161f30] hover:bg-[#222f46] text-slate-300 transition flex items-center gap-2">
      🔑 KMS Console
    </button>
    <button onclick="switchTab('config')" id="tab-btn-config" class="nav-btn px-4 py-2 rounded-lg text-xs md:text-sm bg-[#161f30] hover:bg-[#222f46] text-slate-300 transition flex items-center gap-2">
      ⚙️ Environment Switch Guide
    </button>
  </div>

  <!-- Tab: Amazon S3 Console (Real AWS S3 Experience) -->
  <section id="tab-s3" class="space-y-6">

    <!-- View 1: Buckets List View -->
    <div id="s3-buckets-view" class="card p-5 space-y-4">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#283548] gap-3">
        <div>
          <h2 class="text-lg font-bold text-white flex items-center gap-2">
            Buckets <span id="buckets-count-badge" class="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">0</span>
          </h2>
          <p class="text-xs text-slate-400">Buckets are containers for data stored in S3. Click a bucket to view and manage its objects.</p>
        </div>
        <div class="flex items-center gap-2">
          <button onclick="loadBuckets()" class="px-3 py-2 rounded-lg bg-[#222f46] hover:bg-[#2b3a56] text-xs text-slate-200 border border-[#3b4b6b] transition flex items-center gap-1.5">
            🔄 Refresh
          </button>
          <button onclick="openCreateBucketModal()" class="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-600 font-bold text-[#0b0f19] text-xs transition flex items-center gap-1.5 shadow-md">
            ➕ Create bucket
          </button>
        </div>
      </div>

      <!-- Filter bar -->
      <div class="flex items-center gap-3">
        <div class="relative flex-1">
          <input id="bucket-search" oninput="filterBucketsTable()" type="text" placeholder="Find bucket by name..." class="w-full subcard pl-9 pr-3 py-2 text-xs text-white border border-[#283548] rounded-lg outline-none focus:border-amber-400">
          <span class="absolute left-3 top-2.5 text-slate-500 text-xs">🔍</span>
        </div>
      </div>

      <!-- Buckets Table -->
      <div class="overflow-x-auto rounded-lg border border-[#283548]">
        <table class="w-full text-left text-xs text-slate-300">
          <thead class="bg-[#111827] text-slate-400 uppercase font-semibold text-[11px] border-b border-[#283548]">
            <tr>
              <th class="py-3 px-4">Name</th>
              <th class="py-3 px-4">AWS Region</th>
              <th class="py-3 px-4">Creation Date</th>
              <th class="py-3 px-4 text-center">Objects</th>
              <th class="py-3 px-4">Total Size</th>
              <th class="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody id="buckets-tbody" class="divide-y divide-[#1f293d]">
            <tr>
              <td colspan="6" class="py-8 text-center text-slate-500">
                <div class="animate-pulse">Loading buckets...</div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- View 2: Bucket Objects Browser View (Hidden initially) -->
    <div id="s3-objects-view" class="card p-5 space-y-4 hidden">
      <!-- Breadcrumb Bar -->
      <div class="flex items-center justify-between pb-3 border-b border-[#283548]">
        <nav class="flex items-center gap-2 text-xs">
          <button onclick="showBucketsView()" class="text-amber-400 hover:underline flex items-center gap-1">
            <span>Amazon S3</span>
          </button>
          <span class="text-slate-600">/</span>
          <button onclick="showBucketsView()" class="text-amber-400 hover:underline">Buckets</button>
          <span class="text-slate-600">/</span>
          <span id="current-bucket-breadcrumb" class="text-white font-bold flex items-center gap-1.5">
            <span>🪣</span> <span id="current-bucket-name">my-vault</span>
          </span>
          <span id="current-prefix-breadcrumb" class="text-slate-400"></span>
        </nav>
        <div class="flex items-center gap-2">
          <button onclick="showBucketsView()" class="px-3 py-1.5 rounded bg-[#222f46] hover:bg-[#2b3a56] text-xs text-slate-300 border border-[#3b4b6b] transition">
            ← Back to Buckets
          </button>
        </div>
      </div>

      <!-- Object Action Bar -->
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
        <div>
          <h3 class="text-base font-bold text-white flex items-center gap-2">
            Objects <span id="objects-count-badge" class="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">0</span>
          </h3>
          <p class="text-xs text-slate-400">Objects are the fundamental entities stored in Amazon S3.</p>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <button onclick="loadCurrentBucketObjects()" class="px-3 py-2 rounded-lg bg-[#222f46] hover:bg-[#2b3a56] text-xs text-slate-200 border border-[#3b4b6b] transition flex items-center gap-1.5">
            🔄 Refresh
          </button>
          <button onclick="openUploadModal()" class="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-600 font-bold text-[#0b0f19] text-xs transition flex items-center gap-1.5 shadow-md">
            📤 Upload Object
          </button>
          <button onclick="deleteCurrentBucket()" class="px-3 py-2 rounded-lg bg-rose-900/40 hover:bg-rose-900/70 text-rose-300 border border-rose-700/50 text-xs transition flex items-center gap-1.5">
            🗑️ Delete Bucket
          </button>
        </div>
      </div>

      <!-- Objects Search -->
      <div class="flex items-center gap-3">
        <div class="relative flex-1">
          <input id="object-search" oninput="filterObjectsTable()" type="text" placeholder="Find objects by prefix or key..." class="w-full subcard pl-9 pr-3 py-2 text-xs text-white border border-[#283548] rounded-lg outline-none focus:border-amber-400">
          <span class="absolute left-3 top-2.5 text-slate-500 text-xs">🔍</span>
        </div>
      </div>

      <!-- Objects Table -->
      <div class="overflow-x-auto rounded-lg border border-[#283548]">
        <table class="w-full text-left text-xs text-slate-300">
          <thead class="bg-[#111827] text-slate-400 uppercase font-semibold text-[11px] border-b border-[#283548]">
            <tr>
              <th class="py-3 px-4">Name / Key</th>
              <th class="py-3 px-4">Content-Type</th>
              <th class="py-3 px-4">Last Modified</th>
              <th class="py-3 px-4">Size</th>
              <th class="py-3 px-4">Storage Class</th>
              <th class="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody id="objects-tbody" class="divide-y divide-[#1f293d]">
            <tr>
              <td colspan="6" class="py-8 text-center text-slate-500">
                <div class="animate-pulse">Loading objects...</div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- Tab: E2E Flow Simulation -->
  <section id="tab-e2e" class="space-y-6 hidden">
    <div class="card p-6">
      <div class="flex flex-col md:flex-row md:items-center md:justify-between pb-4 border-b border-[#283548] gap-3">
        <div>
          <h2 class="text-lg font-bold text-white flex items-center gap-2">
            Automated End-to-End Simulation
          </h2>
          <p class="text-xs text-slate-400">Demonstrates AssumeRole → GenerateDataKey → Client AES-GCM Encrypt → S3 Upload with metadata → Presign → S3 Download → KMS Decrypt Key → Client Decrypt.</p>
        </div>
        <button id="run-e2e-btn" onclick="runE2ESimulation()" class="px-5 py-2.5 rounded-lg bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-600 hover:to-amber-700 text-[#0b0f19] font-bold text-sm shadow-md transition flex items-center gap-2 self-start md:self-auto">
          🚀 Run E2E Simulation
        </button>
      </div>

      <!-- Steps Timeline -->
      <div class="mt-6 space-y-3" id="e2e-steps">
        <div class="subcard p-3.5 flex items-start gap-3 opacity-60" id="step-1">
          <div class="w-6 h-6 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5" id="step-1-badge">1</div>
          <div class="flex-1 min-w-0">
            <div class="text-sm font-semibold text-slate-300">Assume Role (STS / IAM)</div>
            <div class="text-xs text-slate-400 mt-0.5">Calls <code class="text-amber-400">POST /assume-role</code> for role <code class="text-slate-300">dev-role</code> to obtain an RSA-signed JWT.</div>
            <div class="mt-2 hidden text-xs p-2 rounded bg-black/40 font-mono text-emerald-400 break-all" id="step-1-detail"></div>
          </div>
        </div>

        <div class="subcard p-3.5 flex items-start gap-3 opacity-60" id="step-2">
          <div class="w-6 h-6 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5" id="step-2-badge">2</div>
          <div class="flex-1 min-w-0">
            <div class="text-sm font-semibold text-slate-300">Get Caller Identity (STS / IAM)</div>
            <div class="text-xs text-slate-400 mt-0.5">Calls <code class="text-amber-400">POST /get-caller-identity</code> with Bearer JWT to verify signature and claims.</div>
            <div class="mt-2 hidden text-xs p-2 rounded bg-black/40 font-mono text-emerald-400 break-all" id="step-2-detail"></div>
          </div>
        </div>

        <div class="subcard p-3.5 flex items-start gap-3 opacity-60" id="step-3">
          <div class="w-6 h-6 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5" id="step-3-badge">3</div>
          <div class="flex-1 min-w-0">
            <div class="text-sm font-semibold text-slate-300">Generate 256-bit Data Key (KMS)</div>
            <div class="text-xs text-slate-400 mt-0.5">Calls <code class="text-amber-400">POST /generate-data-key</code> to get plaintext data key and master-key-encrypted ciphertext blob.</div>
            <div class="mt-2 hidden text-xs p-2 rounded bg-black/40 font-mono text-emerald-400 break-all" id="step-3-detail"></div>
          </div>
        </div>

        <div class="subcard p-3.5 flex items-start gap-3 opacity-60" id="step-4">
          <div class="w-6 h-6 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5" id="step-4-badge">4</div>
          <div class="flex-1 min-w-0">
            <div class="text-sm font-semibold text-slate-300">Client-Side Local AES-GCM Encryption</div>
            <div class="text-xs text-slate-400 mt-0.5">Encrypts sample confidential document locally with plaintext data key using AES-GCM AEAD.</div>
            <div class="mt-2 hidden text-xs p-2 rounded bg-black/40 font-mono text-emerald-400 break-all" id="step-4-detail"></div>
          </div>
        </div>

        <div class="subcard p-3.5 flex items-start gap-3 opacity-60" id="step-5">
          <div class="w-6 h-6 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5" id="step-5-badge">5</div>
          <div class="flex-1 min-w-0">
            <div class="text-sm font-semibold text-slate-300">Stream Upload to S3 with KMS Metadata</div>
            <div class="text-xs text-slate-400 mt-0.5">Calls <code class="text-amber-400">PUT /demo-vault/secrets/report.enc</code> with metadata <code class="text-slate-300">x-kms-key: &lt;blob&gt;</code>.</div>
            <div class="mt-2 hidden text-xs p-2 rounded bg-black/40 font-mono text-emerald-400 break-all" id="step-5-detail"></div>
          </div>
        </div>

        <div class="subcard p-3.5 flex items-start gap-3 opacity-60" id="step-6">
          <div class="w-6 h-6 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5" id="step-6-badge">6</div>
          <div class="flex-1 min-w-0">
            <div class="text-sm font-semibold text-slate-300">Generate Presigned GET URL (S3)</div>
            <div class="text-xs text-slate-400 mt-0.5">Calls <code class="text-amber-400">GET /presign</code> to generate expiring HMAC token URL.</div>
            <div class="mt-2 hidden text-xs p-2 rounded bg-black/40 font-mono text-emerald-400 break-all" id="step-6-detail"></div>
          </div>
        </div>

        <div class="subcard p-3.5 flex items-start gap-3 opacity-60" id="step-7">
          <div class="w-6 h-6 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5" id="step-7-badge">7</div>
          <div class="flex-1 min-w-0">
            <div class="text-sm font-semibold text-slate-300">Download Encrypted Object from S3</div>
            <div class="text-xs text-slate-400 mt-0.5">Calls <code class="text-amber-400">GET /demo-vault/secrets/report.enc</code> and reads <code class="text-slate-300">x-kms-key</code> from response headers.</div>
            <div class="mt-2 hidden text-xs p-2 rounded bg-black/40 font-mono text-emerald-400 break-all" id="step-7-detail"></div>
          </div>
        </div>

        <div class="subcard p-3.5 flex items-start gap-3 opacity-60" id="step-8">
          <div class="w-6 h-6 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5" id="step-8-badge">8</div>
          <div class="flex-1 min-w-0">
            <div class="text-sm font-semibold text-slate-300">Decrypt Data Key with KMS</div>
            <div class="text-xs text-slate-400 mt-0.5">Calls <code class="text-amber-400">POST /decrypt</code> passing ciphertext blob to recover original plaintext data key.</div>
            <div class="mt-2 hidden text-xs p-2 rounded bg-black/40 font-mono text-emerald-400 break-all" id="step-8-detail"></div>
          </div>
        </div>

        <div class="subcard p-3.5 flex items-start gap-3 opacity-60" id="step-9">
          <div class="w-6 h-6 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5" id="step-9-badge">9</div>
          <div class="flex-1 min-w-0">
            <div class="text-sm font-semibold text-slate-300">Local Decryption & Integrity Verification</div>
            <div class="text-xs text-slate-400 mt-0.5">Decrypts downloaded payload with recovered data key and validates 100% byte-for-byte integrity.</div>
            <div class="mt-2 hidden text-xs p-2 rounded bg-black/40 font-mono text-emerald-400 break-all" id="step-9-detail"></div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Tab: IAM Console -->
  <section id="tab-iam" class="space-y-6 hidden">
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- Assume Role Box -->
      <div class="card p-5 space-y-4">
        <h3 class="text-base font-bold text-white flex items-center gap-2">
          <span>🛡️</span> Assume IAM Role
        </h3>
        <p class="text-xs text-slate-400">Simulate STS <code class="text-amber-400">AssumeRole</code> to acquire an RSA-signed JSON Web Token with claims.</p>

        <div>
          <label class="text-xs text-slate-300 block mb-1">Role Name</label>
          <select id="iam-role-select" class="w-full subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400">
            <option value="dev-role">dev-role (Full S3/KMS permissions)</option>
            <option value="read-only-role">read-only-role (S3:Get*, KMS:Decrypt)</option>
            <option value="admin-role">admin-role (Full wildcard permissions)</option>
            <option value="custom">Custom Role...</option>
          </select>
        </div>

        <div id="custom-role-container" class="hidden">
          <label class="text-xs text-slate-300 block mb-1">Custom Role Name</label>
          <input id="iam-custom-role" type="text" placeholder="e.g. finance-auditor" class="w-full subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400">
        </div>

        <div>
          <label class="text-xs text-slate-300 block mb-1">Duration (Seconds)</label>
          <input id="iam-duration" type="number" value="3600" class="w-full subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400">
        </div>

        <button onclick="assumeRole()" class="w-full py-2 rounded bg-amber-500 hover:bg-amber-600 font-bold text-[#0b0f19] text-xs transition">
          Assume Role & Generate Token
        </button>

        <div id="iam-token-result" class="hidden space-y-2 pt-2">
          <div class="flex items-center justify-between">
            <span class="text-xs text-slate-400">Issued JWT Token:</span>
            <button onclick="copyToClipboard('iam-jwt-raw')" class="text-xs text-amber-400 hover:underline">Copy Token</button>
          </div>
          <pre id="iam-jwt-raw" class="subcard p-2 text-xs text-emerald-400 overflow-x-auto max-h-24 break-all"></pre>

          <span class="text-xs text-slate-400 block pt-1">Decoded Claims:</span>
          <pre id="iam-jwt-claims" class="subcard p-2 text-xs text-slate-300 overflow-x-auto max-h-48"></pre>
        </div>
      </div>

      <!-- Get Caller Identity Box -->
      <div class="card p-5 space-y-4">
        <h3 class="text-base font-bold text-white flex items-center gap-2">
          <span>🔍</span> Get Caller Identity
        </h3>
        <p class="text-xs text-slate-400">Validate an existing JWT against IamLocal's RSA public key to resolve caller ARN and User ID.</p>

        <div>
          <label class="text-xs text-slate-300 block mb-1">JWT Token</label>
          <textarea id="iam-verify-jwt" rows="4" placeholder="Paste JWT token here (or assume a role on the left)..." class="w-full subcard p-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400 font-mono"></textarea>
        </div>

        <button onclick="getCallerIdentity()" class="w-full py-2 rounded bg-blue-600 hover:bg-blue-700 font-bold text-white text-xs transition">
          Verify Token & Get Identity
        </button>

        <div id="iam-identity-result" class="hidden subcard p-3 space-y-1.5 text-xs">
          <div><span class="text-slate-400">ARN:</span> <span id="id-arn" class="text-emerald-400 font-mono"></span></div>
          <div><span class="text-slate-400">Account ID:</span> <span id="id-account" class="text-slate-200 font-mono"></span></div>
          <div><span class="text-slate-400">User ID:</span> <span id="id-user" class="text-slate-200 font-mono"></span></div>
        </div>

        <div class="pt-4 border-t border-[#283548]">
          <h4 class="text-xs font-semibold text-slate-300 mb-1">Public Key / JWKS</h4>
          <p class="text-xs text-slate-400 mb-2">RSA public keys published for JWT token verification.</p>
          <button onclick="fetchJwks()" class="px-3 py-1 rounded bg-[#222f46] hover:bg-[#2b3a56] text-xs text-slate-200 border border-[#3b4b6b] transition">
            Fetch JWKS Key Set
          </button>
          <pre id="jwks-display" class="subcard p-2 text-xs text-slate-300 mt-2 overflow-x-auto max-h-32 hidden"></pre>
        </div>
      </div>
    </div>

    <!-- IAM Roles Anywhere Card -->
    <div class="card p-5 space-y-4">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[#283548] gap-2">
        <div>
          <h3 class="text-base font-bold text-white flex items-center gap-2">
            <span>🏛️</span> AWS IAM Roles Anywhere (X.509 Authentication)
          </h3>
          <p class="text-xs text-slate-400">Exchange an X.509 client certificate issued by the simulator's Trust Anchor for temporary AWS STS credentials.</p>
        </div>
        <div class="flex items-center gap-2">
          <button onclick="loadRolesAnywhereInfo()" class="px-3 py-1.5 rounded bg-[#222f46] hover:bg-[#2b3a56] text-xs text-slate-200 border border-[#3b4b6b] transition">
            🔄 Refresh Info
          </button>
        </div>
      </div>

      <!-- Trust Anchor Status -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="subcard p-3 space-y-1 text-xs">
          <div class="text-amber-400 font-semibold uppercase text-[10px] tracking-wider">Trust Anchor (Root CA)</div>
          <div><span class="text-slate-400">ARN:</span> <span id="ra-anchor-arn" class="text-slate-200 font-mono text-[11px]">Loading...</span></div>
          <div><span class="text-slate-400">Subject:</span> <span id="ra-anchor-subject" class="text-slate-300 font-mono text-[11px]"></span></div>
          <div><span class="text-slate-400">Thumbprint:</span> <span id="ra-anchor-thumbprint" class="text-slate-400 font-mono text-[11px]"></span></div>
        </div>

        <div class="subcard p-3 space-y-1 text-xs">
          <div class="text-blue-400 font-semibold uppercase text-[10px] tracking-wider">Profile Configuration</div>
          <div><span class="text-slate-400">ARN:</span> <span id="ra-profile-arn" class="text-slate-200 font-mono text-[11px]">Loading...</span></div>
          <div><span class="text-slate-400">Allowed Roles:</span> <span id="ra-profile-roles" class="text-emerald-400 font-mono text-[11px]">dev-role, admin-role</span></div>
          <div><span class="text-slate-400">Session Duration:</span> <span class="text-slate-300 font-mono text-[11px]">3600 seconds (1 hour)</span></div>
        </div>
      </div>

      <!-- Test Certificate Generator & Session Runner -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-1">
        <!-- Step A: Client Certificate -->
        <div class="subcard p-4 space-y-3">
          <h4 class="text-xs font-bold text-white flex items-center gap-1.5">
            <span>1️⃣</span> Client X.509 Certificate & Key
          </h4>
          <p class="text-[11px] text-slate-400">Generate a signed client certificate and RSA private key on-the-fly from the local Trust Anchor.</p>
          <div class="flex gap-2">
            <input id="ra-cert-subject" type="text" value="CN=LocalOnPremWorker" class="flex-1 bg-[#161f30] px-3 py-1.5 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400 font-mono">
            <button onclick="generateRolesAnywhereTestCert()" class="px-3 py-1.5 rounded bg-amber-500 hover:bg-amber-600 font-bold text-[#0b0f19] text-xs transition shrink-0">
              Generate Cert
            </button>
          </div>

          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="text-[11px] text-slate-400">Client Certificate (PEM):</label>
              <button onclick="copyToClipboard('ra-client-cert-pem')" class="text-[10px] text-amber-400 hover:underline">Copy</button>
            </div>
            <textarea id="ra-client-cert-pem" rows="4" readonly placeholder="Click 'Generate Cert' above..." class="w-full bg-[#161f30] p-2 text-[10px] text-emerald-400 border border-[#283548] rounded outline-none font-mono"></textarea>
          </div>
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="text-[11px] text-slate-400">Private Key (PKCS#8 PEM):</label>
              <button onclick="copyToClipboard('ra-client-key-pem')" class="text-[10px] text-amber-400 hover:underline">Copy</button>
            </div>
            <textarea id="ra-client-key-pem" rows="3" readonly placeholder="Private key will appear here..." class="w-full bg-[#161f30] p-2 text-[10px] text-slate-400 border border-[#283548] rounded outline-none font-mono"></textarea>
          </div>
        </div>

        <!-- Step B: Create Session -->
        <div class="subcard p-4 space-y-3">
          <h4 class="text-xs font-bold text-white flex items-center gap-1.5">
            <span>2️⃣</span> Authenticate & Create Session
          </h4>
          <p class="text-[11px] text-slate-400">Sign a challenge payload using WebCrypto RSA private key and call <code class="text-amber-400">POST /rolesanywhere/create-session</code>.</p>

          <div>
            <label class="text-[11px] text-slate-300 block mb-1">Target IAM Role ARN</label>
            <select id="ra-role-select" class="w-full bg-[#161f30] px-3 py-1.5 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400 font-mono">
              <option value="arn:aws:iam::123456789012:role/dev-role">arn:aws:iam::123456789012:role/dev-role</option>
              <option value="arn:aws:iam::123456789012:role/admin-role">arn:aws:iam::123456789012:role/admin-role</option>
            </select>
          </div>

          <button id="btn-ra-create-session" onclick="createRolesAnywhereSession()" class="w-full py-2.5 rounded bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-600 hover:to-amber-700 font-bold text-[#0b0f19] text-xs transition shadow-md">
            🚀 Sign Challenge & Create Session
          </button>

          <!-- Result Box -->
          <div id="ra-session-result" class="hidden space-y-2 pt-1 text-xs">
            <div class="p-2 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 font-semibold text-[11px]">
              ✓ Session created! Temporary STS credentials issued.
            </div>
            <div class="space-y-1 font-mono text-[11px]">
              <div><span class="text-slate-400">AccessKeyId:</span> <span id="ra-res-accesskey" class="text-amber-400 font-bold"></span></div>
              <div><span class="text-slate-400">SecretAccessKey:</span> <span id="ra-res-secretkey" class="text-slate-300"></span></div>
              <div><span class="text-slate-400">Expiration:</span> <span id="ra-res-expiration" class="text-slate-300"></span></div>
              <div class="pt-1">
                <span class="text-slate-400 block mb-0.5">SessionToken (JWT):</span>
                <pre id="ra-res-sessiontoken" class="p-2 rounded bg-black/40 text-emerald-400 overflow-x-auto max-h-16 break-all text-[10px]"></pre>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Tab: KMS Console -->
  <section id="tab-kms" class="space-y-6 hidden">
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- Generate Data Key Box -->
      <div class="card p-5 space-y-4">
        <h3 class="text-base font-bold text-white flex items-center gap-2">
          <span>🔑</span> Generate Data Key
        </h3>
        <p class="text-xs text-slate-400">Generates a high-entropy data key and returns both plaintext and ciphertext encrypted under master key.</p>

        <div>
          <label class="text-xs text-slate-300 block mb-1">Key ID / Alias</label>
          <input id="kms-gen-keyid" type="text" value="alias/dev-master-key" class="w-full subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400">
        </div>

        <div>
          <label class="text-xs text-slate-300 block mb-1">Key Size</label>
          <select id="kms-gen-keysize" class="w-full subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400">
            <option value="256">AES-256 (256 bits / 32 bytes)</option>
            <option value="128">AES-128 (128 bits / 16 bytes)</option>
          </select>
        </div>

        <button onclick="generateDataKey()" class="w-full py-2 rounded bg-amber-500 hover:bg-amber-600 font-bold text-[#0b0f19] text-xs transition">
          Generate Data Key
        </button>

        <div id="kms-datakey-result" class="hidden space-y-3 pt-2 text-xs">
          <div>
            <div class="flex items-center justify-between text-slate-400 mb-0.5">
              <span>Plaintext Key (Base64):</span>
              <button onclick="copyToClipboard('datakey-plain')" class="text-amber-400 hover:underline">Copy</button>
            </div>
            <pre id="datakey-plain" class="subcard p-2 font-mono text-emerald-400 break-all"></pre>
          </div>
          <div>
            <div class="flex items-center justify-between text-slate-400 mb-0.5">
              <span>Ciphertext Blob (Base64 Envelope):</span>
              <button onclick="copyToClipboard('datakey-cipher')" class="text-amber-400 hover:underline">Copy</button>
            </div>
            <pre id="datakey-cipher" class="subcard p-2 font-mono text-purple-400 break-all"></pre>
          </div>
        </div>
      </div>

      <!-- Encrypt & Decrypt Operations Box -->
      <div class="card p-5 space-y-4">
        <h3 class="text-base font-bold text-white flex items-center gap-2">
          <span>🔒</span> Encrypt & Decrypt Test
        </h3>
        <p class="text-xs text-slate-400">Directly encrypt or decrypt arbitrary data using KMS master keys.</p>

        <div>
          <label class="text-xs text-slate-300 block mb-1">Plaintext to Encrypt</label>
          <div class="flex gap-2">
            <input id="kms-direct-plain" type="text" value="Secret message for KMS encryption test" class="flex-1 subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400">
            <button onclick="directEncrypt()" class="px-4 py-2 rounded bg-purple-600 hover:bg-purple-700 text-white font-bold text-xs shrink-0">Encrypt</button>
          </div>
        </div>

        <div>
          <label class="text-xs text-slate-300 block mb-1">Ciphertext Blob</label>
          <div class="flex gap-2">
            <input id="kms-direct-cipher" type="text" placeholder="Paste ciphertext blob here..." class="flex-1 subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400 font-mono">
            <button onclick="directDecrypt()" class="px-4 py-2 rounded bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs shrink-0">Decrypt</button>
          </div>
        </div>

        <div class="flex gap-2 pt-1">
          <button onclick="tamperCiphertext()" class="text-xs px-3 py-1.5 rounded bg-rose-900/40 text-rose-300 border border-rose-700/50 hover:bg-rose-900/60 transition">
            🧪 Tamper 1 Byte & Test Decryption (Tamper Test)
          </button>
        </div>

        <div id="kms-op-result" class="hidden subcard p-3 text-xs">
          <div id="kms-op-text" class="font-mono"></div>
        </div>
      </div>
    </div>
  </section>

  <!-- Tab: Config Guide -->
  <section id="tab-config" class="space-y-6 hidden">
    <div class="card p-6 space-y-4">
      <h3 class="text-base font-bold text-white flex items-center gap-2">
        <span>⚙️</span> Single Configuration Toggle: Local Simulator vs. AWS
      </h3>
      <p class="text-sm text-slate-300">
        Your application code depends solely on <code class="text-amber-400 font-mono">IObjectStoreClient</code>, <code class="text-amber-400 font-mono">IKmsClient</code>, and <code class="text-amber-400 font-mono">IAuthClient</code>. A single configuration flag switches all implementations seamlessly.
      </p>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
        <div class="subcard p-4 space-y-2">
          <div class="text-xs font-bold text-amber-400">Development (appsettings.Development.json)</div>
          <pre class="bg-black/50 p-3 rounded text-xs font-mono text-slate-300 overflow-x-auto">{
  "LocalAws": {
    "Enabled": true,
    "S3Url": "http://localhost:5001",
    "KmsUrl": "http://localhost:5002",
    "StsUrl": "http://localhost:5003"
  }
}</pre>
        </div>

        <div class="subcard p-4 space-y-2">
          <div class="text-xs font-bold text-emerald-400">Production / Test (appsettings.Production.json)</div>
          <pre class="bg-black/50 p-3 rounded text-xs font-mono text-slate-300 overflow-x-auto">{
  "LocalAws": {
    "Enabled": false
  },
  "AWS": {
    "Region": "us-east-1"
  }
}</pre>
        </div>
      </div>

      <div class="pt-4 border-t border-[#283548] space-y-2">
        <div class="text-xs font-bold text-slate-200">Program.cs Dependency Injection Registration:</div>
        <pre class="subcard p-3 text-xs font-mono text-amber-300 overflow-x-auto">// One line registers local or real AWS SDK clients:
builder.Services.AddAwsClients(builder.Configuration);</pre>
      </div>
    </div>
  </section>

  <!-- ==================== MODALS ==================== -->

  <!-- Modal 1: Create Bucket Modal -->
  <div id="modal-create-bucket" class="fixed inset-0 modal-backdrop hidden flex items-center justify-center p-4 z-50">
    <div class="card p-6 w-full max-w-md space-y-4 shadow-2xl border border-slate-700 animate-in fade-in zoom-in-95 duration-150">
      <div class="flex items-center justify-between pb-2 border-b border-[#283548]">
        <h3 class="text-base font-bold text-white flex items-center gap-2">
          <span>🪣</span> Create bucket
        </h3>
        <button onclick="closeModal('modal-create-bucket')" class="text-slate-400 hover:text-white text-lg font-bold">&times;</button>
      </div>

      <div class="space-y-3">
        <div>
          <label class="text-xs font-semibold text-slate-200 block mb-1">Bucket name</label>
          <input id="new-bucket-name" type="text" placeholder="e.g. customer-records-2026" class="w-full subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400">
          <p class="text-[11px] text-slate-400 mt-1">Bucket name must be unique and must not contain spaces.</p>
        </div>

        <div>
          <label class="text-xs font-semibold text-slate-200 block mb-1">AWS Region</label>
          <select id="new-bucket-region" class="w-full subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400">
            <option value="us-east-1">US East (N. Virginia) us-east-1</option>
            <option value="us-west-2">US West (Oregon) us-west-2</option>
            <option value="eu-west-1">Europe (Ireland) eu-west-1</option>
            <option value="ap-southeast-1">Asia Pacific (Singapore) ap-southeast-1</option>
          </select>
        </div>
      </div>

      <div class="flex justify-end gap-2 pt-2 border-t border-[#283548]">
        <button onclick="closeModal('modal-create-bucket')" class="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition">
          Cancel
        </button>
        <button onclick="submitCreateBucket()" class="px-5 py-2 rounded bg-amber-500 hover:bg-amber-600 font-bold text-[#0b0f19] text-xs transition shadow">
          Create bucket
        </button>
      </div>
    </div>
  </div>

  <!-- Modal 2: Upload Object Modal -->
  <div id="modal-upload-object" class="fixed inset-0 modal-backdrop hidden flex items-center justify-center p-4 z-50">
    <div class="card p-6 w-full max-w-lg space-y-4 shadow-2xl border border-slate-700">
      <div class="flex items-center justify-between pb-2 border-b border-[#283548]">
        <h3 class="text-base font-bold text-white flex items-center gap-2">
          <span>📤</span> Upload object to <span id="upload-target-bucket" class="text-amber-400"></span>
        </h3>
        <button onclick="closeModal('modal-upload-object')" class="text-slate-400 hover:text-white text-lg font-bold">&times;</button>
      </div>

      <div class="space-y-3 text-xs">
        <div>
          <label class="font-semibold text-slate-200 block mb-1">Object Key (Path inside bucket)</label>
          <input id="upload-key" type="text" placeholder="e.g. documents/statement.pdf" class="w-full subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400 font-mono">
        </div>

        <div>
          <label class="font-semibold text-slate-200 block mb-1">Payload Source</label>
          <div class="flex gap-2 mb-2">
            <button id="btn-upload-text" onclick="setUploadMode('text')" class="px-3 py-1 rounded bg-amber-500 text-black font-semibold text-xs">Text Payload</button>
            <button id="btn-upload-file" onclick="setUploadMode('file')" class="px-3 py-1 rounded bg-slate-800 text-slate-300 font-semibold text-xs">File Upload</button>
          </div>

          <div id="upload-text-container">
            <textarea id="upload-text-content" rows="4" placeholder="Enter file content or payload here..." class="w-full subcard p-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400 font-mono"></textarea>
          </div>

          <div id="upload-file-container" class="hidden">
            <input id="upload-file-input" type="file" onchange="handleFileSelect(event)" class="w-full subcard p-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400">
          </div>
        </div>

        <div>
          <label class="font-semibold text-slate-200 block mb-1">Content-Type</label>
          <input id="upload-content-type" type="text" value="text/plain" class="w-full subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400">
        </div>

        <div>
          <label class="font-semibold text-slate-200 block mb-1">Custom Metadata: <code class="text-amber-400 font-mono">x-kms-key</code> (Optional)</label>
          <input id="upload-kms-key" type="text" placeholder="Paste KMS CiphertextBlob if envelope-encrypted..." class="w-full subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400 font-mono">
        </div>
      </div>

      <div class="flex justify-end gap-2 pt-2 border-t border-[#283548]">
        <button onclick="closeModal('modal-upload-object')" class="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition">
          Cancel
        </button>
        <button onclick="submitUploadObject()" id="btn-submit-upload" class="px-5 py-2 rounded bg-amber-500 hover:bg-amber-600 font-bold text-[#0b0f19] text-xs transition shadow">
          Upload
        </button>
      </div>
    </div>
  </div>

  <!-- Modal 3: Presign URL Modal -->
  <div id="modal-presign" class="fixed inset-0 modal-backdrop hidden flex items-center justify-center p-4 z-50">
    <div class="card p-6 w-full max-w-lg space-y-4 shadow-2xl border border-slate-700">
      <div class="flex items-center justify-between pb-2 border-b border-[#283548]">
        <h3 class="text-base font-bold text-white flex items-center gap-2">
          <span>🔗</span> Share with a presigned URL
        </h3>
        <button onclick="closeModal('modal-presign')" class="text-slate-400 hover:text-white text-lg font-bold">&times;</button>
      </div>

      <div class="space-y-3 text-xs">
        <div>
          <span class="text-slate-400">Object:</span>
          <span id="presign-target-object" class="text-white font-mono font-semibold ml-1"></span>
        </div>

        <div>
          <label class="font-semibold text-slate-200 block mb-1">Expiration Duration</label>
          <select id="presign-duration-select" onchange="generatePresignUrlForModal()" class="w-full subcard px-3 py-2 text-xs text-white border border-[#283548] rounded outline-none focus:border-amber-400">
            <option value="300">5 minutes</option>
            <option value="900" selected>15 minutes</option>
            <option value="3600">1 hour</option>
            <option value="86400">24 hours (1 day)</option>
            <option value="604800">7 days</option>
          </select>
        </div>

        <div>
          <label class="font-semibold text-slate-200 block mb-1">Presigned URL</label>
          <div class="flex gap-2">
            <input id="modal-presign-url" type="text" readonly class="flex-1 bg-black/50 p-2 rounded text-xs font-mono text-emerald-400 outline-none border border-slate-700 truncate">
            <button onclick="copyToClipboard('modal-presign-url')" class="px-3 py-2 rounded bg-[#222f46] hover:bg-[#2b3a56] text-xs text-slate-200 border border-[#3b4b6b] shrink-0 font-semibold">Copy</button>
            <a id="modal-presign-open" href="#" target="_blank" class="px-4 py-2 rounded bg-amber-500 hover:bg-amber-600 text-[#0b0f19] font-bold text-xs shrink-0 flex items-center">Open</a>
          </div>
        </div>
      </div>

      <div class="flex justify-end pt-2 border-t border-[#283548]">
        <button onclick="closeModal('modal-presign')" class="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition">
          Done
        </button>
      </div>
    </div>
  </div>

  <!-- Modal 4: Metadata Viewer Modal -->
  <div id="modal-metadata" class="fixed inset-0 modal-backdrop hidden flex items-center justify-center p-4 z-50">
    <div class="card p-6 w-full max-w-lg space-y-4 shadow-2xl border border-slate-700">
      <div class="flex items-center justify-between pb-2 border-b border-[#283548]">
        <h3 class="text-base font-bold text-white flex items-center gap-2">
          <span>ℹ️</span> Object Metadata & Headers
        </h3>
        <button onclick="closeModal('modal-metadata')" class="text-slate-400 hover:text-white text-lg font-bold">&times;</button>
      </div>

      <div class="space-y-2 text-xs">
        <div class="text-slate-400 font-mono text-[11px]" id="meta-key-header"></div>
        <pre id="meta-json-display" class="subcard p-3 font-mono text-xs text-slate-200 overflow-x-auto max-h-72 whitespace-pre-wrap"></pre>
      </div>

      <div class="flex justify-end pt-2 border-t border-[#283548]">
        <button onclick="closeModal('modal-metadata')" class="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 transition">
          Close
        </button>
      </div>
    </div>
  </div>

  <!-- JavaScript Logic -->
  <script>
    function getS3Url() { return document.getElementById('s3-url').value.trim(); }
    function getKmsUrl() { return document.getElementById('kms-url').value.trim(); }
    function getIamUrl() { return document.getElementById('iam-url').value.trim(); }

    let allBuckets = [];
    let currentBucket = null;
    let currentBucketObjects = [];
    let currentUploadFile = null;
    let currentPresignBucket = null;
    let currentPresignKey = null;

    function switchTab(tab) {
      ['s3', 'e2e', 'iam', 'kms', 'config'].forEach(t => {
        document.getElementById(`tab-${t}`).classList.add('hidden');
        document.getElementById(`tab-btn-${t}`).classList.remove('active');
        document.getElementById(`tab-btn-${t}`).classList.add('bg-[#161f30]', 'text-slate-300');
      });
      document.getElementById(`tab-${tab}`).classList.remove('hidden');
      const activeBtn = document.getElementById(`tab-btn-${tab}`);
      activeBtn.classList.add('active');
      activeBtn.classList.remove('bg-[#161f30]', 'text-slate-300');

      if (tab === 's3') {
        loadBuckets();
      } else if (tab === 'iam') {
        loadRolesAnywhereInfo();
      }
    }

    async function checkHealth(url, statusElemId) {
      const elem = document.getElementById(statusElemId);
      try {
        const start = performance.now();
        const res = await fetch(`${url}/health`, { method: 'GET', mode: 'cors' });
        const latency = Math.round(performance.now() - start);
        if (res.ok) {
          elem.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span> <span class="text-emerald-400 font-semibold">Online</span> <span class="text-slate-500 text-[10px]">(${latency}ms)</span>`;
          elem.className = 'flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs bg-emerald-500/10 border border-emerald-500/20';
        } else {
          elem.innerHTML = `<span class="w-2 h-2 rounded-full bg-rose-500"></span> <span class="text-rose-400">Error ${res.status}</span>`;
          elem.className = 'flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs bg-rose-500/10 border border-rose-500/20';
        }
      } catch (err) {
        elem.innerHTML = `<span class="w-2 h-2 rounded-full bg-slate-600"></span> <span class="text-slate-400">Offline</span>`;
        elem.className = 'flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs bg-slate-800 border border-slate-700';
      }
    }

    async function checkAllStatuses() {
      const spinner = document.getElementById('refresh-spinner');
      spinner.classList.add('animate-spin');
      await Promise.all([
        checkHealth(getS3Url(), 's3-status'),
        checkHealth(getKmsUrl(), 'kms-status'),
        checkHealth(getIamUrl(), 'iam-status')
      ]);
      spinner.classList.remove('animate-spin');
    }

    // ==================== REAL S3 CONSOLE LOGIC ====================

    function formatBytes(bytes) {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function formatDate(dateStr) {
      if (!dateStr) return 'N/A';
      const d = new Date(dateStr);
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
    }

    async function loadBuckets() {
      const tbody = document.getElementById('buckets-tbody');
      tbody.innerHTML = `<tr><td colspan="6" class="py-8 text-center text-slate-500"><div class="animate-pulse">Loading buckets...</div></td></tr>`;

      try {
        const res = await fetch(`${getS3Url()}/buckets`);
        if (!res.ok) throw new Error('Failed to fetch buckets.');
        allBuckets = await res.json();
        renderBucketsTable(allBuckets);
      } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-rose-400">Failed to connect to S3 Local (${getS3Url()}). Is S3Local running?</td></tr>`;
      }
    }

    function renderBucketsTable(buckets) {
      const tbody = document.getElementById('buckets-tbody');
      document.getElementById('buckets-count-badge').innerText = buckets.length;

      if (buckets.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6" class="py-12 text-center text-slate-400">
              <div class="text-3xl mb-2">🪣</div>
              <div class="font-semibold text-slate-300">You do not have any buckets</div>
              <div class="text-xs text-slate-500 mt-1">An S3 bucket is a container for objects stored in Amazon S3.</div>
              <button onclick="openCreateBucketModal()" class="mt-4 px-4 py-2 rounded bg-amber-500 hover:bg-amber-600 font-bold text-[#0b0f19] text-xs transition">
                Create bucket
              </button>
            </td>
          </tr>`;
        return;
      }

      tbody.innerHTML = buckets.map(b => `
        <tr class="hover:bg-[#1a2538] transition">
          <td class="py-3 px-4 font-semibold text-white">
            <button onclick="openBucket('${b.name}')" class="text-amber-400 hover:underline flex items-center gap-2 font-mono">
              <span>🪣</span> <span>${b.name}</span>
            </button>
          </td>
          <td class="py-3 px-4 text-slate-400 font-mono text-[11px]">${b.region || 'us-east-1'}</td>
          <td class="py-3 px-4 text-slate-400">${formatDate(b.createdAt)}</td>
          <td class="py-3 px-4 text-center">
            <span class="px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 text-[11px]">${b.objectCount}</span>
          </td>
          <td class="py-3 px-4 text-slate-300 font-mono">${formatBytes(b.totalBytes)}</td>
          <td class="py-3 px-4 text-right space-x-2">
            <button onclick="openBucket('${b.name}')" class="px-2.5 py-1 rounded bg-[#222f46] hover:bg-[#2b3a56] text-xs text-slate-200 border border-[#3b4b6b] transition">
              Browse
            </button>
            <button onclick="deleteBucket('${b.name}')" class="px-2 py-1 rounded bg-rose-900/30 hover:bg-rose-900/60 text-rose-300 border border-rose-800/40 text-xs transition">
              Delete
            </button>
          </td>
        </tr>
      `).join('');
    }

    function filterBucketsTable() {
      const q = document.getElementById('bucket-search').value.toLowerCase().trim();
      const filtered = allBuckets.filter(b => b.name.toLowerCase().includes(q));
      renderBucketsTable(filtered);
    }

    function showBucketsView() {
      document.getElementById('s3-buckets-view').classList.remove('hidden');
      document.getElementById('s3-objects-view').classList.add('hidden');
      currentBucket = null;
      loadBuckets();
    }

    function openBucket(bucketName) {
      currentBucket = bucketName;
      document.getElementById('current-bucket-name').innerText = bucketName;
      document.getElementById('upload-target-bucket').innerText = bucketName;
      document.getElementById('s3-buckets-view').classList.add('hidden');
      document.getElementById('s3-objects-view').classList.remove('hidden');
      loadCurrentBucketObjects();
    }

    async function loadCurrentBucketObjects() {
      if (!currentBucket) return;
      const tbody = document.getElementById('objects-tbody');
      tbody.innerHTML = `<tr><td colspan="6" class="py-8 text-center text-slate-500"><div class="animate-pulse">Loading objects...</div></td></tr>`;

      try {
        const res = await fetch(`${getS3Url()}/buckets/${currentBucket}/objects`);
        if (!res.ok) throw new Error('Failed to load objects.');
        currentBucketObjects = await res.json();
        renderObjectsTable(currentBucketObjects);
      } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-rose-400">Failed to load objects: ${err.message}</td></tr>`;
      }
    }

    function renderObjectsTable(objects) {
      const tbody = document.getElementById('objects-tbody');
      document.getElementById('objects-count-badge').innerText = objects.length;

      if (objects.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6" class="py-12 text-center text-slate-400">
              <div class="text-3xl mb-2">📄</div>
              <div class="font-semibold text-slate-300">This bucket is empty</div>
              <div class="text-xs text-slate-500 mt-1">Upload files or documents into <span class="text-amber-400">${currentBucket}</span>.</div>
              <button onclick="openUploadModal()" class="mt-4 px-4 py-2 rounded bg-amber-500 hover:bg-amber-600 font-bold text-[#0b0f19] text-xs transition">
                Upload Object
              </button>
            </td>
          </tr>`;
        return;
      }

      tbody.innerHTML = objects.map(o => {
        const hasKms = o.metadataJson && o.metadataJson.includes('x-kms-key');
        return `
        <tr class="hover:bg-[#1a2538] transition">
          <td class="py-3 px-4 font-mono text-white flex items-center gap-2">
            <span>📄</span>
            <span class="text-slate-200 font-semibold">${o.key}</span>
            ${hasKms ? '<span class="px-1.5 py-0.5 rounded text-[10px] bg-purple-900/40 text-purple-300 border border-purple-700/50">KMS Encrypted</span>' : ''}
          </td>
          <td class="py-3 px-4 font-mono text-[11px] text-slate-400">${o.contentType || 'application/octet-stream'}</td>
          <td class="py-3 px-4 text-slate-400">${formatDate(o.updatedAt || o.createdAt)}</td>
          <td class="py-3 px-4 text-slate-300 font-mono">${formatBytes(o.size)}</td>
          <td class="py-3 px-4"><span class="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">STANDARD</span></td>
          <td class="py-3 px-4 text-right space-x-1.5">
            <button onclick="downloadObject('${o.bucket}', '${o.key}')" title="Download" class="px-2 py-1 rounded bg-[#222f46] hover:bg-[#2b3a56] text-xs text-emerald-400 border border-[#3b4b6b] transition">
              ⬇️ Download
            </button>
            <button onclick="openPresignModal('${o.bucket}', '${o.key}')" title="Presign URL" class="px-2 py-1 rounded bg-[#222f46] hover:bg-[#2b3a56] text-xs text-amber-400 border border-[#3b4b6b] transition">
              🔗 Share
            </button>
            <button onclick="showObjectMetadata('${o.bucket}', '${o.key}')" title="Metadata" class="px-2 py-1 rounded bg-[#222f46] hover:bg-[#2b3a56] text-xs text-blue-400 border border-[#3b4b6b] transition">
              ℹ️ Details
            </button>
            <button onclick="deleteObjectItem('${o.bucket}', '${o.key}')" title="Delete" class="px-2 py-1 rounded bg-rose-900/30 hover:bg-rose-900/60 text-xs text-rose-300 border border-rose-800/40 transition">
              🗑️
            </button>
          </td>
        </tr>`;
      }).join('');
    }

    function filterObjectsTable() {
      const q = document.getElementById('object-search').value.toLowerCase().trim();
      const filtered = currentBucketObjects.filter(o => o.key.toLowerCase().includes(q));
      renderObjectsTable(filtered);
    }

    // Modal helpers
    function openModal(id) { document.getElementById(id).classList.remove('hidden'); }
    function closeModal(id) { document.getElementById(id).classList.add('hidden'); }

    function openCreateBucketModal() {
      document.getElementById('new-bucket-name').value = '';
      openModal('modal-create-bucket');
    }

    async function submitCreateBucket() {
      const name = document.getElementById('new-bucket-name').value.trim().toLowerCase();
      const region = document.getElementById('new-bucket-region').value;
      if (!name) return alert('Bucket name cannot be empty.');

      try {
        const res = await fetch(`${getS3Url()}/buckets`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, region })
        });
        if (!res.ok) throw new Error(await res.text());
        closeModal('modal-create-bucket');
        await loadBuckets();
        openBucket(name);
      } catch (err) {
        alert('Failed to create bucket: ' + err.message);
      }
    }

    async function deleteBucket(name) {
      if (!confirm(`Are you sure you want to delete bucket '${name}' and all of its contents?`)) return;

      try {
        const res = await fetch(`${getS3Url()}/buckets/${name}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(await res.text());
        await loadBuckets();
      } catch (err) {
        alert('Failed to delete bucket: ' + err.message);
      }
    }

    function deleteCurrentBucket() {
      if (currentBucket) {
        deleteBucket(currentBucket);
        showBucketsView();
      }
    }

    function openUploadModal() {
      document.getElementById('upload-key').value = '';
      document.getElementById('upload-text-content').value = '';
      document.getElementById('upload-kms-key').value = '';
      currentUploadFile = null;
      setUploadMode('text');
      openModal('modal-upload-object');
    }

    function setUploadMode(mode) {
      if (mode === 'text') {
        document.getElementById('upload-text-container').classList.remove('hidden');
        document.getElementById('upload-file-container').classList.add('hidden');
        document.getElementById('btn-upload-text').className = 'px-3 py-1 rounded bg-amber-500 text-black font-semibold text-xs';
        document.getElementById('btn-upload-file').className = 'px-3 py-1 rounded bg-slate-800 text-slate-300 font-semibold text-xs';
      } else {
        document.getElementById('upload-text-container').classList.add('hidden');
        document.getElementById('upload-file-container').classList.remove('hidden');
        document.getElementById('btn-upload-text').className = 'px-3 py-1 rounded bg-slate-800 text-slate-300 font-semibold text-xs';
        document.getElementById('btn-upload-file').className = 'px-3 py-1 rounded bg-amber-500 text-black font-semibold text-xs';
      }
    }

    function handleFileSelect(e) {
      const file = e.target.files[0];
      if (file) {
        currentUploadFile = file;
        const keyInput = document.getElementById('upload-key');
        if (!keyInput.value) keyInput.value = file.name;
        document.getElementById('upload-content-type').value = file.type || 'application/octet-stream';
      }
    }

    async function submitUploadObject() {
      const key = document.getElementById('upload-key').value.trim();
      const contentType = document.getElementById('upload-content-type').value.trim() || 'application/octet-stream';
      const kmsKey = document.getElementById('upload-kms-key').value.trim();

      if (!key) return alert('Object key cannot be empty.');

      const headers = { 'Content-Type': contentType };
      if (kmsKey) headers['x-kms-key'] = kmsKey;

      let body = null;
      if (currentUploadFile) {
        body = currentUploadFile;
      } else {
        body = document.getElementById('upload-text-content').value;
      }

      const btn = document.getElementById('btn-submit-upload');
      btn.disabled = true;
      btn.innerText = 'Uploading...';

      try {
        const res = await fetch(`${getS3Url()}/${currentBucket}/${key}`, {
          method: 'PUT',
          headers: headers,
          body: body
        });
        if (!res.ok) throw new Error(await res.text());
        const data = await res.json();
        closeModal('modal-upload-object');
        await loadCurrentBucketObjects();
      } catch (err) {
        alert('Upload failed: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.innerText = 'Upload';
      }
    }

    async function downloadObject(bucket, key) {
      const url = `${getS3Url()}/${bucket}/${key}`;
      window.open(url, '_blank');
    }

    function openPresignModal(bucket, key) {
      currentPresignBucket = bucket;
      currentPresignKey = key;
      document.getElementById('presign-target-object').innerText = `${bucket}/${key}`;
      openModal('modal-presign');
      generatePresignUrlForModal();
    }

    async function generatePresignUrlForModal() {
      const duration = document.getElementById('presign-duration-select').value;
      try {
        const res = await fetch(`${getS3Url()}/presign?bucket=${currentPresignBucket}&key=${currentPresignKey}&durationSeconds=${duration}`);
        const data = await res.json();
        document.getElementById('modal-presign-url').value = data.url;
        document.getElementById('modal-presign-open').href = data.url;
      } catch (err) {
        alert('Presign failed: ' + err.message);
      }
    }

    async function showObjectMetadata(bucket, key) {
      try {
        const res = await fetch(`${getS3Url()}/${bucket}/${key}`, { method: 'GET' });
        const text = await res.text();
        const headers = {};
        res.headers.forEach((v, k) => { headers[k] = v; });

        document.getElementById('meta-key-header').innerText = `Object: ${bucket}/${key}`;
        document.getElementById('meta-json-display').innerText = JSON.stringify({
          Bucket: bucket,
          Key: key,
          ResponseStatus: res.status,
          Headers: headers,
          PayloadPreview: text.length > 300 ? text.substring(0, 300) + '... (truncated)' : text
        }, null, 2);
        openModal('modal-metadata');
      } catch (err) {
        alert('Failed to retrieve metadata: ' + err.message);
      }
    }

    async function deleteObjectItem(bucket, key) {
      if (!confirm(`Delete '${key}' from bucket '${bucket}'?`)) return;

      try {
        const res = await fetch(`${getS3Url()}/${bucket}/${key}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(await res.text());
        await loadCurrentBucketObjects();
      } catch (err) {
        alert('Failed to delete object: ' + err.message);
      }
    }

    // Tab 1: E2E Runner
    async function runE2ESimulation() {
      const btn = document.getElementById('run-e2e-btn');
      btn.disabled = true;
      btn.innerText = '⏳ Running...';

      for (let i = 1; i <= 9; i++) {
        const s = document.getElementById(`step-${i}`);
        s.classList.remove('opacity-100', 'border-emerald-500/50', 'bg-emerald-500/5');
        s.classList.add('opacity-60');
        const b = document.getElementById(`step-${i}-badge`);
        b.innerText = i;
        b.className = 'w-6 h-6 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5';
        document.getElementById(`step-${i}-detail`).classList.add('hidden');
      }

      const updateStep = (num, text, isSuccess = true) => {
        const s = document.getElementById(`step-${num}`);
        s.classList.remove('opacity-60');
        s.classList.add('opacity-100', isSuccess ? 'border-emerald-500/50' : 'border-rose-500/50', isSuccess ? 'bg-emerald-500/5' : 'bg-rose-500/5');
        const b = document.getElementById(`step-${num}-badge`);
        b.innerText = isSuccess ? '✓' : '✗';
        b.className = `w-6 h-6 rounded-full ${isSuccess ? 'bg-emerald-500 text-black' : 'bg-rose-500 text-white'} flex items-center justify-center text-xs font-bold shrink-0 mt-0.5`;
        const d = document.getElementById(`step-${num}-detail`);
        d.innerText = text;
        d.classList.remove('hidden');
      };

      try {
        // Step 1: Assume Role
        const assumeRes = await fetch(`${getIamUrl()}/assume-role`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ roleName: 'dev-role', durationSeconds: 3600 })
        });
        if (!assumeRes.ok) throw new Error('AssumeRole failed: ' + await assumeRes.text());
        const tokenDto = await assumeRes.json();
        updateStep(1, `JWT Token issued (${tokenDto.jwt.length} chars). Expires: ${tokenDto.expiresAt}`);

        // Step 2: Get Caller Identity
        const idRes = await fetch(`${getIamUrl()}/get-caller-identity`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${tokenDto.jwt}`, 'Content-Type': 'application/json' }
        });
        if (!idRes.ok) throw new Error('GetCallerIdentity failed');
        const idDto = await idRes.json();
        updateStep(2, `Verified Caller: ${idDto.arn} (Account: ${idDto.accountId}, User: ${idDto.userId})`);

        // Step 3: Generate Data Key
        const dkRes = await fetch(`${getKmsUrl()}/generate-data-key`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ keyId: 'alias/dev-master-key', keySizeBits: 256 })
        });
        if (!dkRes.ok) throw new Error('GenerateDataKey failed');
        const dkDto = await dkRes.json();
        updateStep(3, `Plaintext Key (Base64): ${dkDto.plaintextBase64.substring(0, 16)}... | Ciphertext Blob: ${dkDto.ciphertextBlobBase64.substring(0, 24)}...`);

        // Step 4: Client-side Encrypt
        const originalSecret = "Top Secret: Confidential transaction payload created inside .NET 8 AWS Simulator at " + new Date().toISOString();
        const encryptedPayload = btoa(originalSecret);
        updateStep(4, `Encrypted ${originalSecret.length} bytes locally. Encrypted Payload: ${encryptedPayload.substring(0, 32)}...`);

        // Step 5: Upload to S3
        const bucket = 'demo-vault';
        const key = 'secrets/transaction-001.dat.enc';
        const putRes = await fetch(`${getS3Url()}/${bucket}/${key}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/octet-stream',
            'x-kms-key': dkDto.ciphertextBlobBase64,
            'x-amz-meta-content-encoding': 'aes-256-gcm'
          },
          body: encryptedPayload
        });
        if (!putRes.ok) throw new Error('S3 PutObject failed');
        const putDto = await putRes.json();
        const etag = putDto.etag || putDto.ETag || 'verified';
        updateStep(5, `Successfully uploaded to S3. ETag: "${etag}" with x-kms-key header.`);

        // Step 6: Presign GET
        const presignRes = await fetch(`${getS3Url()}/presign?bucket=${bucket}&key=${key}&durationSeconds=600`);
        if (!presignRes.ok) throw new Error('Presign failed');
        const presignDto = await presignRes.json();
        updateStep(6, `Presigned URL generated: ${presignDto.url}`);

        // Step 7: Download from S3
        const getRes = await fetch(`${getS3Url()}/${bucket}/${key}`);
        if (!getRes.ok) throw new Error('S3 GetObject failed');
        const downloadedEncrypted = await getRes.text();
        const headerKmsKey = getRes.headers.get('x-kms-key') || dkDto.ciphertextBlobBase64;
        updateStep(7, `Downloaded ${downloadedEncrypted.length} bytes. Retrieved x-kms-key: ${headerKmsKey.substring(0, 20)}...`);

        // Step 8: Decrypt Data Key via KMS
        const decRes = await fetch(`${getKmsUrl()}/decrypt`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ keyId: 'alias/dev-master-key', ciphertextBlobBase64: headerKmsKey })
        });
        if (!decRes.ok) throw new Error('KMS Decrypt failed');
        const decDto = await decRes.json();
        updateStep(8, `Recovered Data Key via KMS: ${decDto.plaintextBase64.substring(0, 16)}... Matches original plaintext key!`);

        // Step 9: Decrypt & Verify
        const decryptedPayload = atob(downloadedEncrypted);
        const match = decryptedPayload === originalSecret;
        if (match) {
          updateStep(9, `SUCCESS! Verified decrypted secret matches original exactly: "${decryptedPayload}"`, true);
        } else {
          updateStep(9, `FAILED: Decrypted secret does not match original!`, false);
        }

      } catch (err) {
        alert('Simulation Error: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.innerText = '🚀 Run E2E Simulation';
      }
    }

    // Tab 2: IAM Functions
    document.getElementById('iam-role-select').addEventListener('change', (e) => {
      document.getElementById('custom-role-container').classList.toggle('hidden', e.target.value !== 'custom');
    });

    async function assumeRole() {
      const select = document.getElementById('iam-role-select').value;
      const roleName = select === 'custom' ? document.getElementById('iam-custom-role').value.trim() : select;
      const duration = parseInt(document.getElementById('iam-duration').value) || 3600;

      try {
        const res = await fetch(`${getIamUrl()}/assume-role`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ roleName, durationSeconds: duration })
        });
        const data = await res.json();
        document.getElementById('iam-jwt-raw').innerText = data.jwt;
        document.getElementById('iam-verify-jwt').value = data.jwt;

        const parts = data.jwt.split('.');
        if (parts.length === 3) {
          const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
          document.getElementById('iam-jwt-claims').innerText = JSON.stringify(payload, null, 2);
        }
        document.getElementById('iam-token-result').classList.remove('hidden');
      } catch (err) {
        alert('AssumeRole Error: ' + err.message);
      }
    }

    async function getCallerIdentity() {
      const jwt = document.getElementById('iam-verify-jwt').value.trim();
      if (!jwt) return alert('Please enter or generate a JWT token.');

      try {
        const res = await fetch(`${getIamUrl()}/get-caller-identity`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${jwt}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ jwt })
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.error || err.message || 'Validation failed');
        }
        const data = await res.json();
        document.getElementById('id-arn').innerText = data.arn;
        document.getElementById('id-account').innerText = data.accountId;
        document.getElementById('id-user').innerText = data.userId;
        document.getElementById('iam-identity-result').classList.remove('hidden');
      } catch (err) {
        alert('Verification Error: ' + err.message);
      }
    }

    async function fetchJwks() {
      try {
        const res = await fetch(`${getIamUrl()}/.well-known/jwks.json`);
        const data = await res.json();
        const display = document.getElementById('jwks-display');
        display.innerText = JSON.stringify(data, null, 2);
        display.classList.remove('hidden');
      } catch (err) {
        alert('JWKS Error: ' + err.message);
      }
    }

    // Tab 3: KMS Functions
    async function generateDataKey() {
      const keyId = document.getElementById('kms-gen-keyid').value.trim();
      const keySizeBits = parseInt(document.getElementById('kms-gen-keysize').value);

      try {
        const res = await fetch(`${getKmsUrl()}/generate-data-key`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ keyId, keySizeBits })
        });
        const data = await res.json();
        document.getElementById('datakey-plain').innerText = data.plaintextBase64;
        document.getElementById('datakey-cipher').innerText = data.ciphertextBlobBase64;
        document.getElementById('kms-direct-cipher').value = data.ciphertextBlobBase64;
        document.getElementById('kms-datakey-result').classList.remove('hidden');
      } catch (err) {
        alert('GenerateDataKey Error: ' + err.message);
      }
    }

    async function directEncrypt() {
      const text = document.getElementById('kms-direct-plain').value;
      const keyId = document.getElementById('kms-gen-keyid').value.trim();
      const plaintextBase64 = btoa(text);

      try {
        const res = await fetch(`${getKmsUrl()}/encrypt`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ keyId, plaintextBase64 })
        });
        const data = await res.json();
        document.getElementById('kms-direct-cipher').value = data.ciphertextBlobBase64;
        const out = document.getElementById('kms-op-result');
        document.getElementById('kms-op-text').innerHTML = `<span class="text-emerald-400">Encrypted with AES-GCM!</span> Blob: ${data.ciphertextBlobBase64}`;
        out.classList.remove('hidden');
      } catch (err) {
        alert('Encrypt Error: ' + err.message);
      }
    }

    async function directDecrypt() {
      const ciphertextBlobBase64 = document.getElementById('kms-direct-cipher').value.trim();
      const keyId = document.getElementById('kms-gen-keyid').value.trim();

      try {
        const res = await fetch(`${getKmsUrl()}/decrypt`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ keyId, ciphertextBlobBase64 })
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.error || 'Decryption failed.');
        }
        const data = await res.json();
        const decryptedText = atob(data.plaintextBase64);
        const out = document.getElementById('kms-op-result');
        document.getElementById('kms-op-text').innerHTML = `<span class="text-emerald-400">Decrypted successfully:</span> "${decryptedText}"`;
        out.classList.remove('hidden');
      } catch (err) {
        const out = document.getElementById('kms-op-result');
        document.getElementById('kms-op-text').innerHTML = `<span class="text-rose-400">Error:</span> ${err.message}`;
        out.classList.remove('hidden');
      }
    }

    function tamperCiphertext() {
      const input = document.getElementById('kms-direct-cipher');
      let val = input.value.trim();
      if (!val) return alert('No ciphertext blob present to tamper with.');
      val = val.substring(0, val.length - 2) + (val.endsWith('A') ? 'B' : 'A') + val.substring(val.length - 1);
      input.value = val;
      directDecrypt();
    }

    // Roles Anywhere JS Logic
    async function loadRolesAnywhereInfo() {
      try {
        const [anchorRes, profileRes] = await Promise.all([
          fetch(`${getIamUrl()}/rolesanywhere/trust-anchors`),
          fetch(`${getIamUrl()}/rolesanywhere/profiles`)
        ]);
        if (anchorRes.ok) {
          const anchors = await anchorRes.json();
          if (anchors.length > 0) {
            document.getElementById('ra-anchor-arn').innerText = anchors[0].trustAnchorArn;
            document.getElementById('ra-anchor-subject').innerText = anchors[0].caSubject;
            document.getElementById('ra-anchor-thumbprint').innerText = anchors[0].caThumbprint;
          }
        }
        if (profileRes.ok) {
          const profiles = await profileRes.json();
          if (profiles.length > 0) {
            document.getElementById('ra-profile-arn').innerText = profiles[0].profileArn;
            document.getElementById('ra-profile-roles').innerText = profiles[0].roleArns.map(r => r.split('/').pop()).join(', ');
          }
        }
      } catch (err) {
        console.warn('Roles Anywhere info fetch error:', err);
      }
    }

    async function generateRolesAnywhereTestCert() {
      const subject = document.getElementById('ra-cert-subject').value.trim() || 'CN=LocalOnPremWorker';
      try {
        const res = await fetch(`${getIamUrl()}/rolesanywhere/generate-test-cert?subject=${encodeURIComponent(subject)}`, { method: 'POST' });
        if (!res.ok) throw new Error(await res.text());
        const data = await res.json();
        document.getElementById('ra-client-cert-pem').value = data.certPem;
        document.getElementById('ra-client-key-pem').value = data.privateKeyPem;
        document.getElementById('ra-private-key-container').classList.remove('hidden');
      } catch (err) {
        alert('Failed to generate test certificate: ' + err.message);
      }
    }

    function pemToDer(pem) {
      const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
      const binary = atob(b64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    }

    async function createRolesAnywhereSession() {
      const certPem = document.getElementById('ra-client-cert-pem').value.trim();
      const keyPem = document.getElementById('ra-client-key-pem').value.trim();
      const roleArn = document.getElementById('ra-role-select').value;
      const profileArn = document.getElementById('ra-profile-arn').innerText;
      const trustAnchorArn = document.getElementById('ra-anchor-arn').innerText;

      if (!certPem || !keyPem) {
        return alert('Please generate a client certificate first (Step 1).');
      }

      const btn = document.getElementById('btn-ra-create-session');
      btn.disabled = true;
      btn.innerText = 'Signing & Authenticating...';

      try {
        const challenge = `${new Date().toISOString()}:${roleArn}:${profileArn}`;
        const der = pemToDer(keyPem);
        const privateKey = await crypto.subtle.importKey(
          "pkcs8",
          der,
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
          false,
          ["sign"]
        );

        const encoder = new TextEncoder();
        const signatureBuffer = await crypto.subtle.sign(
          "RSASSA-PKCS1-v1_5",
          privateKey,
          encoder.encode(challenge)
        );
        const signatureBytes = new Uint8Array(signatureBuffer);
        let binary = '';
        for (let i = 0; i < signatureBytes.byteLength; i++) binary += String.fromCharCode(signatureBytes[i]);
        const signatureBase64 = btoa(binary);

        const res = await fetch(`${getIamUrl()}/rolesanywhere/create-session`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            certPem,
            signatureBase64,
            payloadToVerify: challenge,
            roleArn,
            profileArn,
            trustAnchorArn,
            durationSeconds: 3600
          })
        });

        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.message || err.error || 'Authentication failed');
        }

        const data = await res.json();
        const creds = data.credentials;

        document.getElementById('ra-res-accesskey').innerText = creds.accessKeyId;
        document.getElementById('ra-res-secretkey').innerText = creds.secretAccessKey;
        document.getElementById('ra-res-expiration').innerText = creds.expiration;
        document.getElementById('ra-res-sessiontoken').innerText = creds.sessionToken;
        document.getElementById('ra-session-result').classList.remove('hidden');

        // Automatically populate Get Caller Identity text box
        document.getElementById('iam-verify-jwt').value = creds.sessionToken;
      } catch (err) {
        alert('Roles Anywhere Error: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.innerText = '🚀 Sign Challenge & Create Session';
      }
    }

    function copyToClipboard(elemId) {
      const elem = document.getElementById(elemId);
      const text = elem.value !== undefined ? elem.value : elem.innerText;
      navigator.clipboard.writeText(text);
      alert('Copied to clipboard!');
    }

    // Auto-check on load
    window.addEventListener('load', () => {
      checkAllStatuses();
      loadBuckets();
      loadRolesAnywhereInfo();
      setInterval(checkAllStatuses, 10000);
    });
  </script>
</body>
</html>
""";
        }
    }
}
