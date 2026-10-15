const authForm = document.querySelector("#auth-form");
const loginTab = document.querySelector("#login-tab");
const registerTab = document.querySelector("#register-tab");
const nameField = document.querySelector("#name-field");
const nameInput = document.querySelector("#name");
const passwordInput = document.querySelector("#password");
const submitButton = document.querySelector("#submit-button");
const statusBox = document.querySelector("#status");
const authView = document.querySelector("#auth-view");
const dashboard = document.querySelector("#dashboard");

let mode = "login";

function showStatus(message, isError = false) {
  statusBox.textContent = message;
  statusBox.classList.toggle("error", isError);
  statusBox.hidden = false;
}

function clearStatus() {
  statusBox.hidden = true;
  statusBox.textContent = "";
  statusBox.classList.remove("error");
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
  document.querySelector("#form-subtitle").textContent = registering
    ? "Set up your CyberShield X account."
    : "Sign in to access your security dashboard.";
  submitButton.innerHTML = registering
    ? 'Create account <span aria-hidden="true">→</span>'
    : 'Sign in securely <span aria-hidden="true">→</span>';
  clearStatus();
}

function showDashboard(user) {
  authView.hidden = true;
  dashboard.hidden = false;
  document.querySelector("#welcome-title").textContent = `Welcome, ${user.name}`;
  document.querySelector("#welcome-email").textContent = user.email;
  clearStatus();
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) }
  });
  if (response.status === 204) return null;
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || "Request failed. Please try again.");
  return payload;
}

loginTab.addEventListener("click", () => setMode("login"));
registerTab.addEventListener("click", () => setMode("register"));

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearStatus();
  submitButton.disabled = true;
  const formData = new FormData(authForm);
  const body = {
    email: String(formData.get("email") || ""),
    password: String(formData.get("password") || "")
  };
  if (mode === "register") body.name = String(formData.get("name") || "");

  try {
    const result = await api(`/api/auth/${mode}`, {
      method: "POST",
      body: JSON.stringify(body)
    });
    showDashboard(result.user);
    authForm.reset();
  } catch (error) {
    showStatus(error.message, true);
  } finally {
    submitButton.disabled = false;
  }
});

document.querySelector("#logout-button").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", body: "{}" });
    dashboard.hidden = true;
    authView.hidden = false;
    authForm.reset();
    setMode("login");
    showStatus("You have been signed out.");
  } catch (error) {
    showStatus(error.message, true);
  }
});

async function restoreSession() {
  try {
    const result = await api("/api/auth/me");
    showDashboard(result.user);
  } catch {
    // A missing/expired session simply leaves the sign-in form visible.
  }
}
restoreSession();