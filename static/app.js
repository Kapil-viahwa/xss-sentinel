const metricNames = ["assessments", "urls_discovered", "endpoints_discovered", "injection_points", "confirmed_vulnerabilities", "potential_vulnerabilities", "active_assessments", "waf_blocked"];
const dialog = document.getElementById("assessment-dialog");
const form = document.getElementById("assessment-form");
const errorBox = document.getElementById("form-error");
const toast = document.getElementById("toast");

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  window.setTimeout(() => toast.classList.remove("visible"), 3500);
}

function setMetric(name, value) {
  const node = document.querySelector(`[data-metric="${name}"]`);
  if (node) node.textContent = Number(value || 0).toLocaleString();
}

async function loadOverview() {
  const response = await fetch("/api/overview");
  if (!response.ok) throw new Error("Could not load assessment metrics.");
  const data = await response.json();
  metricNames.forEach((name) => setMetric(name, data[name]));
}

function cell(text, className = "") {
  const node = document.createElement("td");
  node.textContent = text ?? "—";
  if (className) node.className = className;
  return node;
}

async function startCrawl(id, button) {
  button.disabled = true;
  button.textContent = "Crawling…";
  try {
    const response = await fetch(`/api/assessments/${id}/crawl`, { method: "POST" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Crawl could not be started.");
    if (data.status === "failed") throw new Error(`Crawl failed (${data.error_type || "unknown error"}).`);
    showToast(`Crawl finished: ${data.resources} resources and ${data.injection_points} input points discovered.`);
    await refreshDashboard();
  } catch (error) {
    showToast(error.message);
    button.disabled = false;
    button.textContent = "Start crawl";
  }
}

async function loadAssessments() {
  const response = await fetch("/api/assessments");
  if (!response.ok) throw new Error("Could not load assessments.");
  const assessments = await response.json();
  const body = document.getElementById("assessment-rows");
  body.replaceChildren();
  if (assessments.length === 0) {
    const row = document.createElement("tr");
    const empty = cell("No assessments yet. Create one to begin mapping an authorized application.", "empty-state");
    empty.colSpan = 7;
    row.append(empty);
    body.append(row);
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
    row.append(name, target, statusCell, cell(assessment.resources, "count-cell"), cell(assessment.injection_points, "count-cell"), cell(assessment.findings, "count-cell"));
    const actionCell = document.createElement("td");
    if (assessment.status !== "running" && assessment.status !== "queued") {
      const button = document.createElement("button");
      button.className = "row-action";
      button.textContent = assessment.resources ? "Re-crawl" : "Start crawl";
      button.addEventListener("click", () => startCrawl(assessment.id, button));
      actionCell.append(button);
    }
    row.append(actionCell);
    body.append(row);
  });
}

async function refreshDashboard() {
  try {
    await Promise.all([loadOverview(), loadAssessments()]);
  } catch (error) {
    showToast(error.message);
  }
}

document.getElementById("new-assessment").addEventListener("click", () => {
  errorBox.textContent = "";
  dialog.showModal();
});
document.getElementById("close-dialog").addEventListener("click", () => dialog.close());
document.getElementById("cancel-dialog").addEventListener("click", () => dialog.close());
document.getElementById("refresh").addEventListener("click", refreshDashboard);

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
