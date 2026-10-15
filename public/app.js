const authForm = document.querySelector("#auth-form");
const loginTab = document.querySelector("#login-tab");
const registerTab = document.querySelector("#register-tab");
const nameField = document.querySelector("#name-field");
const nameInput = document.querySelector("#name");
const passwordInput = document.querySelector("#password");
const submitButton = document.querySelector("#submit-button");
const statusBox = document.querySelector("#status");
const authPanel = document.querySelector("#auth-panel");
const appView = document.querySelector("#app-view");
const appStatus = document.querySelector("#app-status");
let mode = "login";

function showStatus(box, message, isError = false) {
  box.textContent = message;
  box.classList.toggle("error", isError);
  box.hidden = false;
}
function clearStatus(box) {
  box.hidden = true;
  box.textContent = "";
  box.classList.remove("error");
}
function setMode(nextMode) {
  mode = nextMode;
  const registering = mode === "register";
  loginTab.classList.toggle("active", !registering);
  registerTab.classList.toggle("active", registering);
  loginTab.setAttribute("aria-selected", String(!registering));
  registerTab.setAttribute("aria-selected", String(registering));
  nameField.hidden = !registering;
  nameInput.required = registering;
  passwordInput.autocomplete = registering ? "new-password" : "current-password";
  document.querySelector("#form-title").textContent = registering ? "Create your account" : "Welcome back";
  document.querySelector("#form-subtitle").textContent = registering ? "Set up your CyberShield X account." : "Sign in to access your security dashboard.";
  submitButton.innerHTML = registering ? 'Create account <span aria-hidden="true">→</span>' : 'Sign in securely <span aria-hidden="true">→</span>';
  clearStatus(statusBox);
}
async function api(path, options = {}) {
  const response = await fetch(path, { ...options, credentials: "same-origin", headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
  if (response.status === 204) return null;
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || "Request failed. Please try again.");
  return payload;
}
function showDashboard(user) {
  authPanel.hidden = true;
  appView.hidden = false;
  document.querySelector("#welcome-title").textContent = `Welcome, ${user.name}`;
  const chip = document.querySelector("#user-chip");
  chip.textContent = user.email;
  chip.hidden = false;
  clearStatus(appStatus);
  loadReports();
}
function showAuth() {
  appView.hidden = true;
  authPanel.hidden = false;
  document.querySelector("#user-chip").hidden = true;
  authForm.reset();
  setMode("login");
}
function navigate(view) {
  document.querySelectorAll(".nav-tab").forEach(button => button.classList.toggle("active", button.dataset.view === view));
  document.querySelectorAll(".app-section").forEach(section => section.classList.toggle("active", section.id === `view-${view}`));
  clearStatus(appStatus);
}
document.querySelectorAll(".nav-tab").forEach(button => button.addEventListener("click", () => navigate(button.dataset.view)));
document.querySelectorAll("[data-go]").forEach(button => button.addEventListener("click", () => navigate(button.dataset.go)));
loginTab.addEventListener("click", () => setMode("login"));
registerTab.addEventListener("click", () => setMode("register"));

authForm.addEventListener("submit", async event => {
  event.preventDefault();
  clearStatus(statusBox);
  submitButton.disabled = true;
  const data = new FormData(authForm);
  const body = { email: String(data.get("email") || ""), password: String(data.get("password") || "") };
  if (mode === "register") body.name = String(data.get("name") || "");
  try {
    const result = await api(`/api/auth/${mode}`, { method: "POST", body: JSON.stringify(body) });
    showDashboard(result.user);
  } catch (error) {
    showStatus(statusBox, error.message, true);
  } finally {
    submitButton.disabled = false;
  }
});
document.querySelector("#logout-button").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", body: "{}" });
    showAuth();
    showStatus(statusBox, "You have been signed out.");
  } catch (error) { showStatus(appStatus, error.message, true); }
});

document.querySelector("#url-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button[type=submit]");
  button.disabled = true;
  const container = document.querySelector("#url-result");
  container.hidden = true;
  try {
    const result = await api("/api/security/check-url", { method: "POST", body: JSON.stringify({ url: document.querySelector("#check-url").value }) });
    container.replaceChildren();
    const heading = document.createElement("h4");
    heading.textContent = result.risk;
    const score = document.createElement("p");
    score.className = "risk-score";
    score.textContent = `Heuristic indicator score: ${result.score}/100`;
    const host = document.createElement("p");
    host.className = "muted";
    host.textContent = `Hostname: ${result.hostname}`;
    const list = document.createElement("ul");
    list.className = "finding-list";
    result.findings.forEach(finding => {
      const item = document.createElement("li");
      item.className = `finding ${finding.level}`;
      item.textContent = finding.text;
      list.append(item);
    });
    const disclaimer = document.createElement("p");
    disclaimer.className = "hint";
    disclaimer.textContent = result.disclaimer;
    container.append(heading, score, host, list, disclaimer);
    container.hidden = false;
  } catch (error) { showStatus(appStatus, error.message, true); }
  finally { button.disabled = false; }
});

const strengthInput = document.querySelector("#strength-password");
const strengthBar = document.querySelector("#strength-bar");
const strengthLabel = document.querySelector("#strength-label");
const strengthTips = document.querySelector("#strength-tips");
function assessPassword(value) {
  if (!value) return { score: 0, label: "Enter a password to see guidance.", tips: ["Use a long, unique passphrase.", "Consider a password manager."] };
  let score = 0;
  if (value.length >= 12) score += 2; else if (value.length >= 8) score += 1;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score += 1;
  if (/\d/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;
  if (value.length >= 16) score += 1;
  if (/(.)\1{3,}/.test(value) || /password|qwerty|123456|letmein/i.test(value)) score = Math.min(score, 1);
  const labels = ["Very weak", "Weak", "Fair", "Good", "Strong", "Strong", "Very strong"];
  const tips = [];
  if (value.length < 14) tips.push("Aim for 14 or more characters, or use a long passphrase.");
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value)) tips.push("Consider a memorable mix of letters.");
  if (!/\d/.test(value)) tips.push("Consider adding a number if it remains easy to remember.");
  if (!/[^A-Za-z0-9]/.test(value)) tips.push("Consider a separator or make the passphrase longer.");
  if (/(.)\1{3,}|password|qwerty|123456|letmein/i.test(value)) tips.push("Avoid common words, sequences and repeated characters.");
  if (!tips.length) tips.push("Good length and variety. Make sure it is unique and not reused.");
  return { score, label: labels[Math.min(score, labels.length - 1)], tips };
}
strengthInput.addEventListener("input", () => {
  const result = assessPassword(strengthInput.value);
  strengthBar.style.width = `${Math.min(100, result.score / 6 * 100)}%`;
  strengthBar.className = result.score <= 1 ? "weak" : result.score <= 3 ? "medium" : "strong";
  strengthLabel.textContent = result.label;
  strengthTips.replaceChildren();
  result.tips.forEach(tip => { const item = document.createElement("li"); item.textContent = tip; strengthTips.append(item); });
});
document.querySelector("#toggle-password").addEventListener("click", event => {
  const showing = strengthInput.type === "text";
  strengthInput.type = showing ? "password" : "text";
  event.currentTarget.textContent = showing ? "Show" : "Hide";
});

document.querySelector("#report-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button[type=submit]");
  button.disabled = true;
  const form = new FormData(event.currentTarget);
  try {
    const result = await api("/api/reports", { method: "POST", body: JSON.stringify({ url: String(form.get("url") || ""), reason: String(form.get("reason") || "") }) });
    showStatus(appStatus, result.report.message);
    event.currentTarget.reset();
    await loadReports();
  } catch (error) { showStatus(appStatus, error.message, true); }
  finally { button.disabled = false; }
});
async function loadReports() {
  const container = document.querySelector("#reports-list");
  try {
    const result = await api("/api/reports");
    container.replaceChildren();
    if (!result.reports.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No reports saved yet.";
      container.append(empty);
      return;
    }
    result.reports.forEach(report => {
      const card = document.createElement("article");
      card.className = "report-item";
      const url = document.createElement("p");
      url.className = "report-url";
      url.textContent = report.url;
      const reason = document.createElement("p");
      reason.textContent = report.reason;
      const date = document.createElement("small");
      date.textContent = report.createdAt;
      card.append(url, reason, date);
      container.append(card);
    });
  } catch (error) { container.textContent = error.message; }
}
async function restoreSession() {
  try { showDashboard((await api("/api/auth/me")).user); }
  catch { /* Missing or expired session leaves sign-in visible. */ }
}
restoreSession();
