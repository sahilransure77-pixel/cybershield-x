const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeUrl, normalizeHttpUrl } = require("../security");

test("normalizes a hostname to HTTPS", () => {
  assert.equal(normalizeHttpUrl("example.com"), "https://example.com/");
});
test("rejects unsafe schemes and credential-bearing URLs", () => {
  assert.equal(normalizeHttpUrl("javascript:alert(1)"), null);
  assert.equal(normalizeHttpUrl("https://user:pass@example.com"), null);
});
test("flags plain HTTP URLs", () => {
  const result = analyzeUrl("http://example.com/");
  assert.ok(result.score >= 15);
  assert.ok(result.findings.some(item => item.text.includes("HTTPS")));
});
test("warns about URL shorteners", () => {
  const result = analyzeUrl("https://bit.ly/abc");
  assert.ok(result.findings.some(item => item.text.includes("shortener")));
});
test("does not promise a common HTTPS URL is safe", () => {
  const result = analyzeUrl("https://example.com/");
  assert.equal(result.score, 0);
  assert.match(result.disclaimer, /guarantee that a link is safe/i);
});
test("rejects excessively long URLs", () => {
  assert.equal(normalizeHttpUrl("https://example.com/" + "a".repeat(2050)), null);
});
