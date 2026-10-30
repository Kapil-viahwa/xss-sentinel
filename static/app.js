const metricNames = ["assessments", "urls_discovered", "endpoints_discovered", "injection_points", "confirmed_vulnerabilities", "potential_vulnerabilities", "active_assessments", "waf_blocked"];
const dialog = document.getElementById("assessment-dialog");
const form = document.getElementById("assessment-form");
const errorBox = document.getElementById("form-error");
const toast = document.getElementById("toast");
let injectionPoints = [];
let selectedInjectionId = null;
let loadedInjectionAssessmentId = null;
let scanWasActive = false;
const browserContexts = new Set(["html_text", "html_attribute", "javascript_text", "html_comment", "css_text"]);

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  window.setTimeout(() => toast.classList.remove("visible"), 3500);
}

function setMetric(name, value) {
  const node = document.querySelector(`[data-metric="${name}"]`);
  if (node) node.textContent = Number(value || 0).toLocaleString();
}

async function loadAuthProfiles() {
  const response = await fetch("/api/auth-profiles");
  if (!response.ok) throw new Error("Could not load server-side authentication profile names.");
  const data = await response.json();
  const picker = document.getElementById("auth-profile-select");
  const selected = picker.value;
  picker.replaceChildren();
  const emptyOption = document.createElement("option");
  emptyOption.value = "";
  emptyOption.textContent = "Unauthenticated";
  picker.append(emptyOption);
  data.profiles.forEach((name) => {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    picker.append(option);
  });
  picker.value = data.profiles.includes(selected) ? selected : "";
}

async function loadOverview() {
  const response = await fetch("/api/overview");
  if (!response.ok) throw new Error("Could not load assessment metrics.");
  const data = await response.json();
  metricNames.forEach((name) => setMetric(name, data[name]));
  return data;
}

function cell(text, className = "") {
  const node = document.createElement("td");
  node.textContent = text ?? "—";
  if (className) node.className = className;
  return node;
}

function showInjectionDetail(point) {
  const panel = document.getElementById("injection-detail");
  panel.replaceChildren();
  if (!point) {
    const placeholder = document.createElement("div");
    placeholder.className = "detail-placeholder";
    placeholder.textContent = "Select an input to inspect discovered metadata and any inert-marker comparison.";
    panel.append(placeholder);
    return;
  }
  const heading = document.createElement("div");
  heading.className = "detail-heading";
  heading.textContent = `Input #${point.id} · ${point.method} ${point.parameter}`;
  panel.append(heading);
  const grid = document.createElement("div");
  grid.className = "detail-grid";
  [["URL", point.url], ["Location", point.location], ["Input type", point.input_type || "—"],
    ["Reflection context", point.reflection_context || point.context], ["Reflection result", point.reflection_status],
    ["Browser result", point.browser_result || "not_tested"], ["XSS validation state", point.status],
    ["Baseline HTTP", point.browser_baseline_status ?? point.baseline_status ?? "—"],
    ["Browser HTTP", point.browser_response_status ?? "—"], ["Probe HTTP", point.response_status ?? "—"],
    ["Probe marker", point.reflection_marker || "—"], ["Browser marker", point.browser_marker || "—"],
    ["Console errors", point.browser_console_error_count ?? 0], ["Page errors", point.browser_page_error_count ?? 0],
    ["Original value", point.original_value || "—"], ["Stored-XSS result", point.stored_test_result || "not_tested"],
    ["Stored callback requests", point.stored_callback_requests ?? 0], ["Callback HTTP", point.stored_callback_response_status ?? "—"]]
    .forEach(([labelText, valueText]) => {
      const item = document.createElement("div");
      item.className = "detail-item";
      const label = document.createElement("span");
      label.className = "detail-label";
      label.textContent = labelText;
      const value = document.createElement("span");
      value.className = "detail-value";
      value.textContent = valueText;
      item.append(label, value);
      grid.append(item);
    });
  const note = document.createElement("p");
  note.className = "detail-note";
  note.textContent = point.browser_evidence || point.reflection_evidence || "No validation evidence has been recorded. Reflection alone is not proof of vulnerability; XSS requires browser execution evidence.";
  panel.append(grid, note);
  if (point.browser_screenshot_available && point.browser_verification_id) {
    const screenshot = document.createElement("img");
    screenshot.className = "verification-screenshot";
    screenshot.src = `/api/browser-verifications/${point.browser_verification_id}/screenshot`;
    screenshot.alt = "Screenshot captured during browser execution verification";
    panel.append(screenshot);
  } else if (point.stored_screenshot_available && point.stored_test_id) {
    const screenshot = document.createElement("img");
    screenshot.className = "verification-screenshot";
    screenshot.src = `/api/stored-xss-tests/${point.stored_test_id}/screenshot`;
    screenshot.alt = "Screenshot captured during stored-XSS verification";
    panel.append(screenshot);
  }
}

function renderInjectionPoints() {
  const body = document.getElementById("injection-rows");
  body.replaceChildren();
  const query = document.getElementById("injection-search").value.trim().toLowerCase();
  const location = document.getElementById("injection-location-filter").value;
  const status = document.getElementById("injection-status-filter").value;
  const visible = injectionPoints.filter((point) => {
    const searchable = `${point.url} ${point.parameter} ${point.input_type} ${point.context} ${point.reflection_context || ""}`.toLowerCase();
    return (!query || searchable.includes(query)) && (!location || point.location === location) && (!status || point.status === status);
  });
  if (visible.length === 0) {
    const row = document.createElement("tr");
    const empty = cell(injectionPoints.length ? "No inputs match the current filters." : "No discovered inputs for this assessment yet.", "empty-state");
    empty.colSpan = 10;
    row.append(empty);
    body.append(row);
    showInjectionDetail(null);
    return;
  }
  visible.forEach((point) => {
    const row = document.createElement("tr");
    row.append(cell(point.url, "target-cell"), cell(point.method), cell(point.parameter, "assessment-name"),
      cell(point.location), cell(point.input_type || "—"), cell(point.reflection_context || point.context),
      cell(point.reflection_status), cell(point.browser_result || "not_tested"), cell(point.status));
    const action = document.createElement("td");
    const inspectButton = document.createElement("button");
    inspectButton.className = "inspect-button";
    inspectButton.textContent = "Inspect";
    inspectButton.addEventListener("click", () => {
      selectedInjectionId = point.id;
      showInjectionDetail(point);
    });
    action.append(inspectButton);
    if (point.method === "POST" && ["body", "json"].includes(point.location)) {
      const storedButton = document.createElement("button");
      storedButton.className = "probe-button";
      storedButton.textContent = "Test stored XSS";
      storedButton.disabled = point.original_value === "<redacted>";
      storedButton.title = storedButton.disabled ? "Sensitive fields cannot be submitted for stored-XSS checks" : "Submit a canary only after explicit confirmation";
      storedButton.addEventListener("click", () => runStoredXssTest(point, storedButton));
      action.append(storedButton);
    }
    if (point.method === "GET" && point.location === "query" && !point.input_type) {
      const probeButton = document.createElement("button");
      probeButton.className = "probe-button";
      probeButton.textContent = "Probe marker";
      probeButton.disabled = point.original_value === "<redacted>";
      probeButton.title = probeButton.disabled ? "Redacted inputs cannot be replayed" : "Send a harmless marker between baseline and test requests";
      probeButton.addEventListener("click", () => runReflectionProbe(point, probeButton));
      action.append(probeButton);
      if (point.reflection_status === "reflected" && browserContexts.has(point.reflection_context)) {
        const verifyButton = document.createElement("button");
        verifyButton.className = "verify-button";
        verifyButton.textContent = "Verify in browser";
        verifyButton.disabled = point.original_value === "<redacted>";
        verifyButton.title = verifyButton.disabled ? "Redacted inputs cannot be replayed" : "Run a context-specific, non-destructive execution-marker check";
        verifyButton.addEventListener("click", () => runBrowserVerification(point, verifyButton));
        action.append(verifyButton);
      }
      if (["not_checked", "not_reflected"].includes(point.reflection_status)) {
        const domButton = document.createElement("button");
        domButton.className = "verify-button";
        domButton.textContent = "Check DOM";
        domButton.disabled = point.original_value === "<redacted>";
        domButton.title = domButton.disabled ? "Redacted inputs cannot be replayed" : "Check whether client-side code sends this URL input to an executable sink";
        domButton.addEventListener("click", () => runBrowserVerification(point, domButton, "dom"));
        action.append(domButton);
      }
    }
    row.append(action);
    body.append(row);
  });
  const selected = visible.find((point) => point.id === selectedInjectionId);
  showInjectionDetail(selected || null);
}

async function runReflectionProbe(point, button) {
  button.disabled = true;
  button.textContent = "Checking…";
  const assessmentId = document.getElementById("injection-assessment-select").value;
  try {
    const response = await fetch(`/api/assessments/${assessmentId}/injection-points/${point.id}/reflection-probe`, { method: "POST" });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Reflection check failed.");
    if (result.result === "reflected") {
      showToast(`Harmless marker reflected in ${result.context}. This is not a confirmed XSS finding.`);
    } else {
      showToast(`Reflection check: ${result.result}. ${result.evidence}`);
    }
    if (result.waf_result) showToast(`Security-control observation: ${result.waf_evidence}`);
    await loadInjectionPoints();
  } catch (error) {
    showToast(error.message);
    button.disabled = false;
    button.textContent = "Probe marker";
  }
}

async function runBrowserVerification(point, button, mode = "reflected") {
  const description = mode === "dom" ? "DOM-source execution marker" : "context-specific execution marker";
  const accepted = window.confirm(`This will run a ${description} check in an isolated browser. It is limited to the authorized origin, blocks writes and out-of-scope requests, and stores a screenshot if execution is observed. Continue only if this target is authorized.`);
  if (!accepted) return;
  button.disabled = true;
  button.textContent = "Verifying…";
  const assessmentId = document.getElementById("injection-assessment-select").value;
  try {
    const response = await fetch(`/api/assessments/${assessmentId}/injection-points/${point.id}/browser-verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ execution_confirmed: true, mode }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Browser verification failed.");
    if (result.result === "confirmed") {
      showToast(`${mode === "dom" ? "DOM" : "Browser"} execution confirmed with an isolated marker. Evidence and screenshot were saved.`);
    } else {
      showToast(`Browser result: ${result.result}. ${result.evidence}`);
    }
    await loadInjectionPoints();
  } catch (error) {
    showToast(error.message);
    button.disabled = false;
    button.textContent = "Verify in browser";
  }
}

async function runStoredXssTest(point, button) {
  const accepted = window.confirm("This test submits a state-changing POST containing an XSS canary. The value may persist in the target, and the scanner will visit only verification pages you provide. Use a disposable, explicitly authorized target and test account.");
  if (!accepted) return;
  const rawFields = window.prompt("Enter all required form/JSON fields as a JSON object. The selected parameter is replaced with the test marker; field values are not stored.", JSON.stringify({ [point.parameter]: "" }, null, 2));
  if (rawFields === null) return;
  let fields;
  try {
    fields = JSON.parse(rawFields);
    if (!fields || Array.isArray(fields) || typeof fields !== "object") throw new Error("Fields must be a JSON object.");
  } catch (error) {
    showToast(error.message || "Invalid field JSON.");
    return;
  }
  const rawUrls = window.prompt("Enter one to five full same-origin URLs where the stored value may later render, separated by commas.");
  if (!rawUrls) return;
  const callbackUrl = window.prompt("Enter the callback endpoint configured in this authentication profile. Only its allowlisted origin can receive the canary beacon.");
  if (!callbackUrl) return;
  const context = window.prompt("Known output context (html_text, html_attribute, javascript_text, html_comment, css_text)", "html_text");
  if (!context) return;
  if (!window.confirm("I confirm this target is authorized, the POST may persist data, and the configured callback endpoint is approved to receive a marker-only GET beacon.")) return;
  button.disabled = true;
  button.textContent = "Submitting…";
  const assessmentId = document.getElementById("injection-assessment-select").value;
  try {
    const response = await fetch(`/api/assessments/${assessmentId}/injection-points/${point.id}/stored-test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        submission_confirmed: true,
        callback_confirmed: true,
        fields,
        verification_urls: rawUrls.split(",").map((value) => value.trim()).filter(Boolean),
        callback_url: callbackUrl.trim(),
        body_format: point.location === "json" ? "json" : "form",
        context,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Stored-XSS test failed.");
    showToast(`Stored-XSS result: ${result.result}. Callback responses: ${result.callback_response_status ?? "none"}.`);
    await loadInjectionPoints();
  } catch (error) {
    showToast(error.message);
    button.disabled = false;
    button.textContent = "Test stored XSS";
  }
}

async function loadInjectionPoints() {
  const assessmentId = document.getElementById("injection-assessment-select").value;
  if (!assessmentId) {
    injectionPoints = [];
    selectedInjectionId = null;
    loadedInjectionAssessmentId = null;
    renderInjectionPoints();
    return;
  }
  if (String(assessmentId) !== loadedInjectionAssessmentId) selectedInjectionId = null;
  const response = await fetch(`/api/assessments/${assessmentId}/injection-points`);
  if (!response.ok) throw new Error("Could not load discovered inputs.");
  injectionPoints = await response.json();
  loadedInjectionAssessmentId = String(assessmentId);
  if (!injectionPoints.some((point) => point.id === selectedInjectionId)) selectedInjectionId = null;
  renderInjectionPoints();
}

async function startCrawl(id, button) {
  button.disabled = true;
  button.textContent = "Queueing…";
  try {
    const response = await fetch(`/api/assessments/${id}/crawl`, { method: "POST" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Crawl could not be started.");
    showToast("Crawl queued. Progress and controls are available in the assessment row.");
    scanWasActive = true;
    await refreshDashboard();
  } catch (error) {
    showToast(error.message);
    button.disabled = false;
    button.textContent = "Start crawl";
  }
}

async function updateCrawlState(id, action, button) {
  button.disabled = true;
  try {
    const response = await fetch(`/api/assessments/${id}/${action}`, { method: "POST" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Could not ${action} crawl.`);
    showToast(`Assessment ${data.status}.`);
    await refreshDashboard();
  } catch (error) {
    showToast(error.message);
    button.disabled = false;
  }
}

async function loadAssessments() {
  const response = await fetch("/api/assessments");
  if (!response.ok) throw new Error("Could not load assessments.");
  const assessments = await response.json();
  const picker = document.getElementById("injection-assessment-select");
  const previousId = picker.value;
  picker.replaceChildren();
  const emptyOption = document.createElement("option");
  emptyOption.value = "";
  emptyOption.textContent = assessments.length ? "Choose an assessment" : "No assessments";
  picker.append(emptyOption);
  assessments.forEach((assessment) => {
    const option = document.createElement("option");
    option.value = String(assessment.id);
    option.textContent = `${assessment.name} — ${assessment.target_url}`;
    picker.append(option);
  });
  picker.value = assessments.some((assessment) => String(assessment.id) === previousId)
    ? previousId
    : (assessments.length ? String(assessments[0].id) : "");

  const body = document.getElementById("assessment-rows");
  body.replaceChildren();
  if (assessments.length === 0) {
    const row = document.createElement("tr");
    const empty = cell("No assessments yet. Create one to begin mapping an authorized application.", "empty-state");
    empty.colSpan = 9;
    row.append(empty);
    body.append(row);
    await loadInjectionPoints();
    return;
  }
  assessments.forEach((assessment) => {
    const row = document.createElement("tr");
    const name = cell(assessment.name, "assessment-name");
    const target = cell(assessment.target_url, "target-cell");
    const statusCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge ${assessment.status}`;
    badge.textContent = assessment.status;
    statusCell.append(badge);
    row.append(name, target, statusCell, cell(assessment.resources, "count-cell"), cell(assessment.endpoints, "count-cell"),
      cell(`${assessment.requests_made}/${assessment.max_requests}`, "count-cell"), cell(assessment.injection_points, "count-cell"), cell(assessment.findings, "count-cell"));
    const actionCell = document.createElement("td");
    if (["running", "queued"].includes(assessment.status)) {
      const pauseButton = document.createElement("button");
      pauseButton.className = "row-action";
      pauseButton.textContent = "Pause";
      pauseButton.addEventListener("click", () => updateCrawlState(assessment.id, "pause", pauseButton));
      actionCell.append(pauseButton);
      const cancelButton = document.createElement("button");
      cancelButton.className = "cancel-button";
      cancelButton.textContent = "Cancel";
      cancelButton.addEventListener("click", () => updateCrawlState(assessment.id, "cancel", cancelButton));
      actionCell.append(cancelButton);
    } else if (assessment.status === "paused") {
      const resumeButton = document.createElement("button");
      resumeButton.className = "row-action";
      resumeButton.textContent = "Resume";
      resumeButton.addEventListener("click", () => updateCrawlState(assessment.id, "resume", resumeButton));
      actionCell.append(resumeButton);
      const cancelButton = document.createElement("button");
      cancelButton.className = "cancel-button";
      cancelButton.textContent = "Cancel";
      cancelButton.addEventListener("click", () => updateCrawlState(assessment.id, "cancel", cancelButton));
      actionCell.append(cancelButton);
    } else {
      const button = document.createElement("button");
      button.className = "row-action";
      button.textContent = assessment.resources ? "Re-crawl" : "Start crawl";
      button.addEventListener("click", () => startCrawl(assessment.id, button));
      actionCell.append(button);
    }
    [["JSON", "json"], ["CSV", "csv"], ["HTML", "html"], ["PDF", "pdf"], ["WAF", "waf-observations"], ["JS", "javascript-analysis"]].forEach(([label, format]) => {
      const link = document.createElement("a");
      link.className = "report-link";
      link.href = format === "waf-observations" || format === "javascript-analysis"
        ? `/api/assessments/${assessment.id}/${format}`
        : `/api/assessments/${assessment.id}/report.${format}`;
      link.textContent = label;
      link.setAttribute("aria-label", `${label} assessment report`);
      actionCell.append(link);
    });
    row.append(actionCell);
    body.append(row);
  });
  await loadInjectionPoints();
}

async function refreshDashboard() {
  try {
    const [overview] = await Promise.all([loadOverview(), loadAssessments(), loadAuthProfiles()]);
    scanWasActive = overview.active_assessments > 0;
  } catch (error) {
    showToast(error.message);
  }
}

async function pollScanProgress() {
  try {
    const overview = await loadOverview();
    const currentlyActive = Number(overview.active_assessments) > 0;
    if (currentlyActive || scanWasActive) await loadAssessments();
    scanWasActive = currentlyActive;
  } catch (_error) {
    // Keep periodic progress refresh quiet; manual refresh reports errors.
  }
}

document.getElementById("new-assessment").addEventListener("click", () => {
  errorBox.textContent = "";
  dialog.showModal();
});
document.getElementById("close-dialog").addEventListener("click", () => dialog.close());
document.getElementById("cancel-dialog").addEventListener("click", () => dialog.close());
document.getElementById("refresh").addEventListener("click", refreshDashboard);
document.getElementById("injection-assessment-select").addEventListener("change", () => {
  selectedInjectionId = null;
  loadInjectionPoints().catch((error) => showToast(error.message));
});
document.getElementById("injection-search").addEventListener("input", renderInjectionPoints);
document.getElementById("injection-location-filter").addEventListener("change", renderInjectionPoints);
document.getElementById("injection-status-filter").addEventListener("change", renderInjectionPoints);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.textContent = "";
  const data = new FormData(form);
  const payload = {
    name: data.get("name").trim(),
    target_url: data.get("target_url").trim(),
    max_depth: Number(data.get("max_depth")),
    max_requests: Number(data.get("max_requests")),
    concurrency: Number(data.get("concurrency")),
    auth_profile: data.get("auth_profile") || null,
    authorization_confirmed: data.get("authorization_confirmed") === "on",
  };
  try {
    const response = await fetch("/api/assessments", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Assessment could not be created.");
    dialog.close();
    form.reset();
    form.elements.max_depth.value = 3;
    form.elements.max_requests.value = 100;
    form.elements.concurrency.value = 4;
    showToast("Authorized assessment created. Start the crawl from the assessment list.");
    await refreshDashboard();
  } catch (error) {
    errorBox.textContent = error.message;
  }
});

document.addEventListener("DOMContentLoaded", refreshDashboard);
window.setInterval(pollScanProgress, 4000);
