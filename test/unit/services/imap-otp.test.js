"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const imap = require("../../../src/services/imap-otp");

describe("extractOtpFromRaw", () => {
  it("should extract 6-digit code from div with class 'code'", () => {
    const html = '<div class="code"> 123456 </div>';
    assert.strictEqual(imap.extractOtpFromRaw(html), "123456");
  });
  it("should extract from 'Verification code:' pattern", () => {
    const html = 'Verification code: <strong>789012</strong>';
    assert.strictEqual(imap.extractOtpFromRaw(html), "789012");
  });
  it("should extract 6-digit near 'code' context as fallback", () => {
    const text = 'Your verification code is 345678. Please enter it.';
    assert.strictEqual(imap.extractOtpFromRaw(text), "345678");
  });
  it("should return null for no match", () => {
    assert.strictEqual(imap.extractOtpFromRaw("hello world"), null);
  });
  it("should return null for empty input", () => {
    assert.strictEqual(imap.extractOtpFromRaw(""), null);
    assert.strictEqual(imap.extractOtpFromRaw(null), null);
  });
});

describe("buildGmrawQuery", () => {
  it("should build gmail search query with to: and subject:", () => {
    const q = imap.buildGmrawQuery("test@example.com", "Verify your email");
    assert.ok(q.includes("to:test@example.com"));
    assert.ok(q.includes('subject:"Verify your email"'));
    assert.ok(q.includes("in:anywhere"));
  });
});

describe("pickRecencyMatch", () => {
  it("should pick the newest message with OTP", () => {
    const messages = [
      { internalDate: new Date("2026-07-19T10:00:00Z"), source: "no code here" },
      { internalDate: new Date("2026-07-19T10:01:00Z"), source: "code is 123456" },
      { internalDate: new Date("2026-07-19T10:02:00Z"), source: "no digits" },
    ];
    const picked = imap.pickRecencyMatch(messages, { since: Date.parse("2026-07-19T10:00:00Z") });
    assert.ok(picked);
    assert.strictEqual(picked.otp, "123456");
  });
  it("should return null if no messages within window", () => {
    const messages = [
      { internalDate: new Date("2020-01-01"), source: "code is 123456" },
    ];
    const picked = imap.pickRecencyMatch(messages, { since: Date.now() });
    assert.strictEqual(picked, null);
  });
});
