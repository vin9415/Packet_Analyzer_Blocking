const form = document.getElementById("analyze-form");
const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("pcap-file");
const fileName = document.getElementById("file-name");
const submitBtn = document.getElementById("submit-btn");
const loading = document.getElementById("loading");
const errorBox = document.getElementById("error");
const results = document.getElementById("results");

dropZone.addEventListener("click", () => fileInput.click());

dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("dragover");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("dragover");
});

dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("dragover");
  if (e.dataTransfer.files.length) {
    fileInput.files = e.dataTransfer.files;
    showFileName(e.dataTransfer.files[0]);
  }
});

fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) showFileName(fileInput.files[0]);
});

function showFileName(file) {
  fileName.textContent = `Selected: ${file.name} (${formatBytes(file.size)})`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  if (!fileInput.files[0]) {
    showError("Please select a .pcap file first.");
    return;
  }

  hideError();
  results.classList.add("hidden");
  loading.classList.remove("hidden");
  submitBtn.disabled = true;

  const formData = new FormData(form);

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      body: formData,
    });
    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(data.error || "Analysis failed");
    }

    renderResults(data);
  } catch (err) {
    showError(err.message);
  } finally {
    loading.classList.add("hidden");
    submitBtn.disabled = false;
  }
});

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}

function hideError() {
  errorBox.classList.add("hidden");
}

function renderResults(data) {
  document.getElementById("stat-total").textContent = data.total_packets;
  document.getElementById("stat-forwarded").textContent = data.forwarded;
  document.getElementById("stat-dropped").textContent = data.dropped;
  document.getElementById("stat-flows").textContent = data.active_flows;

  const breakdown = document.getElementById("app-breakdown");
  breakdown.innerHTML = data.app_breakdown.map((item) => `
    <div class="bar-row">
      <span>${item.name}</span>
      <div class="bar-track">
        <div class="bar-fill" style="width: ${Math.max(item.percent, 2)}%"></div>
      </div>
      <span>${item.count} (${item.percent}%)</span>
    </div>
  `).join("");

  const domains = document.getElementById("domains-list");
  if (data.detected_domains.length) {
    domains.innerHTML = `
      <table>
        <thead><tr><th>Domain</th><th>Application</th></tr></thead>
        <tbody>
          ${data.detected_domains.map((d) => `
            <tr><td>${escapeHtml(d.domain)}</td><td>${escapeHtml(d.app)}</td></tr>
          `).join("")}
        </tbody>
      </table>`;
  } else {
    domains.innerHTML = "<p class='hint'>No domains detected in this capture.</p>";
  }

  const blocked = document.getElementById("blocked-list");
  const blockedCard = document.getElementById("blocked-card");
  if (data.blocked_events.length) {
    blockedCard.classList.remove("hidden");
    blocked.innerHTML = `
      <table>
        <thead><tr><th>Source</th><th>Destination</th><th>App</th><th>Domain</th></tr></thead>
        <tbody>
          ${data.blocked_events.map((b) => `
            <tr>
              <td>${escapeHtml(b.src_ip)}</td>
              <td>${escapeHtml(b.dest_ip)}</td>
              <td>${escapeHtml(b.app)}</td>
              <td>${escapeHtml(b.sni || "—")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>`;
  } else {
    blockedCard.classList.add("hidden");
  }

  const downloadBtn = document.getElementById("download-btn");
  downloadBtn.href = `/api/download/${data.job_id}`;

  results.classList.remove("hidden");
  results.scrollIntoView({ behavior: "smooth" });
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
