"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const proxy = require("../../../src/services/proxy");

describe("parseProxyLine", () => {
  it("should parse protocol://user:pass@host:port", () => {
    const p = proxy.parseProxyLine("http://user1:pass1@192.168.1.1:8080");
    assert.strictEqual(p.protocol, "http");
    assert.strictEqual(p.host, "192.168.1.1");
    assert.strictEqual(p.port, 8080);
    assert.strictEqual(p.username, "user1");
    assert.strictEqual(p.password, "pass1");
  });
  it("should parse host:port:user:pass", () => {
    const p = proxy.parseProxyLine("10.0.0.1:3128:user2:pass2");
    assert.strictEqual(p.protocol, "http");
    assert.strictEqual(p.host, "10.0.0.1");
    assert.strictEqual(p.port, 3128);
    assert.strictEqual(p.username, "user2");
  });
  it("should parse user:pass@host:port", () => {
    const p = proxy.parseProxyLine("user3:pass3@proxy.example.com:8888");
    assert.strictEqual(p.host, "proxy.example.com");
    assert.strictEqual(p.port, 8888);
  });
  it("should return null for comment lines", () => {
    assert.strictEqual(proxy.parseProxyLine("# comment"), null);
    assert.strictEqual(proxy.parseProxyLine(""), null);
  });
  it("should parse host:port without auth", () => {
    const p = proxy.parseProxyLine("192.168.1.2:8080");
    assert.strictEqual(p.host, "192.168.1.2");
    assert.strictEqual(p.port, 8080);
    assert.strictEqual(p.username, null);
  });
});

describe("getProxyForAccount", () => {
  it("should cycle through proxies by index", () => {
    const proxies = [
      { host: "a.com", port: 1 },
      { host: "b.com", port: 2 },
    ];
    assert.strictEqual(proxy.getProxyForAccount(proxies, 0).host, "a.com");
    assert.strictEqual(proxy.getProxyForAccount(proxies, 1).host, "b.com");
    assert.strictEqual(proxy.getProxyForAccount(proxies, 2).host, "a.com"); // cycle
  });
  it("should return null for empty pool", () => {
    assert.strictEqual(proxy.getProxyForAccount([], 0), null);
  });
});

describe("chromiumArgsForProxy", () => {
  it("should return --proxy-server arg", () => {
    const p = { protocol: "http", host: "1.2.3.4", port: 8080 };
    const args = proxy.chromiumArgsForProxy(p);
    assert.ok(args[0].includes("--proxy-server=http://1.2.3.4:8080"));
  });
  it("should return empty array for null proxy", () => {
    assert.deepStrictEqual(proxy.chromiumArgsForProxy(null), []);
  });
});
