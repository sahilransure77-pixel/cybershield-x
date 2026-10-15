const SHORTENER_HOSTS = new Set(["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at"]);
const SUSPICIOUS_TLDS = new Set(["zip", "mov", "top", "click", "work", "country", "gq", "tk"]);

function normalizeHttpUrl(input) {
  if (typeof input !== "string" || input.length > 2048) return null;
  try {
    const candidate = /^https?:\/\//i.test(input) ? input : "https://" + input;
    const parsed = new URL(candidate);
    if (!["http:", "https:"].includes(parsed.protocol)) return null;
    if (!parsed.hostname || parsed.username || parsed.password) return null;
    return parsed.href;
  } catch {
    return null;
  }
}

function analyzeUrl(input) {
  const parsed = new URL(input);
  const host = parsed.hostname.toLowerCase();
  const hostnameParts = host.split(".");
  const findings = [];
  let score = 0;
  if (parsed.protocol !== "https:") {
    score += 15;
    findings.push({ level: "warning", text: "This link does not use HTTPS." });
  }
  if (host.startsWith("xn--") || hostnameParts.some(part => part.startsWith("xn--"))) {
    score += 20;
    findings.push({ level: "warning", text: "The domain uses punycode, which can hide look-alike characters." });
  }
  if (SHORTENER_HOSTS.has(host)) {
    score += 15;
    findings.push({ level: "warning", text: "A URL shortener hides the final destination." });
  }
  if (SUSPICIOUS_TLDS.has(hostnameParts.at(-1))) {
    score += 10;
    findings.push({ level: "warning", text: "This top-level domain is sometimes abused. The TLD alone does not prove a scam." });
  }
  if (hostnameParts.length >= 5) {
    score += 10;
    findings.push({ level: "warning", text: "The hostname has many subdomains. Check the registered domain carefully." });
  }
  if (["login", "verify", "account", "secure"].some(word => host.includes(word))) {
    score += 10;
    findings.push({ level: "info", text: "The hostname uses a login or account-related word. This can be legitimate, but verify the domain." });
  }
  if (parsed.href.length > 180) {
    score += 10;
    findings.push({ level: "warning", text: "The link is unusually long; inspect the destination before opening it." });
  }
  score = Math.min(score, 100);
  const risk = score >= 50 ? "High indicators" : score >= 25 ? "Some indicators" : "Few indicators";
  if (!findings.length) findings.push({ level: "info", text: "No basic URL warning patterns were detected." });
  return {
    url: input, hostname: host, score, risk, findings,
    disclaimer: "This is a basic heuristic check, not a reputation lookup or a guarantee that a link is safe. Do not open unexpected links or enter credentials based on this result."
  };
}
module.exports = { analyzeUrl, normalizeHttpUrl };
