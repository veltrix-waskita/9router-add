"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const { ProviderError, AuthError } = require("../../../src/base/errors");

function loadProvider() {
  delete require.cache[require.resolve("../../../src/base/provider")];
  return require("../../../src/base/provider");
}

describe("BaseProvider", () => {
  it("should throw if instantiated directly", () => {
    const { BaseProvider } = loadProvider();
    assert.throws(() => new BaseProvider(), /cannot be instantiated/i);
  });

  it("should require providerName to be overridden", () => {
    const { BaseProvider } = loadProvider();
    class TestProvider extends BaseProvider {}
    assert.strictEqual(TestProvider.providerName, undefined);
  });

  it("should allow valid subclass", () => {
    const { BaseProvider } = loadProvider();
    class ValidProvider extends BaseProvider {
      static get providerName() { return "valid"; }
      async add(creds, opts) { return { ok: true }; }
    }
    const inst = new ValidProvider({}, { request: async () => ({}) }, {});
    assert.strictEqual(ValidProvider.providerName, "valid");
  });

  it("should call beforeAdd, add, afterAdd in order", async () => {
    const { BaseProvider } = loadProvider();
    const calls = [];
    class OrderedProvider extends BaseProvider {
      static get providerName() { return "ordered"; }
      async add(creds, opts) { calls.push("add"); return { ok: true }; }
      async beforeAdd(creds, opts) { calls.push("beforeAdd"); }
      async afterAdd(result) { calls.push("afterAdd"); }
    }
    const inst = new OrderedProvider({}, { request: async () => ({}) }, {});
    await inst.add({}, {});
    assert.deepStrictEqual(calls, ["beforeAdd", "add", "afterAdd"]);
  });

  it("should call onError when add throws", async () => {
    const { BaseProvider } = loadProvider();
    const calls = [];
    class ErrorProvider extends BaseProvider {
      static get providerName() { return "error"; }
      async add(creds, opts) { throw new Error("boom"); }
      async onError(err, ctx) { calls.push("onError"); }
    }
    const inst = new ErrorProvider({}, { request: async () => ({}) }, {});
    await assert.rejects(() => inst.add({}, {}), /boom/);
    assert.strictEqual(calls[0], "onError");
  });

  it("should return skip result when beforeAdd returns skip", async () => {
    const { BaseProvider } = loadProvider();
    class SkipProvider extends BaseProvider {
      static get providerName() { return "skip"; }
      async beforeAdd(creds, opts) { return { skip: true, reason: "quota" }; }
      async add(creds, opts) { return { ok: true }; }
    }
    const inst = new SkipProvider({}, { request: async () => ({}) }, {});
    const result = await inst.add({}, {});
    assert.strictEqual(result.skip, true);
    assert.strictEqual(result.reason, "quota");
  });

  it("should convert AuthError to error result", async () => {
    const { BaseProvider } = loadProvider();
    class AuthFailProvider extends BaseProvider {
      static get providerName() { return "authfail"; }
      async add(creds, opts) { throw new AuthError("bad password"); }
    }
    const inst = new AuthFailProvider({}, { request: async () => ({}) }, {});
    const result = await inst.add({}, {});
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.error, "bad password");
  });

  it("should provide apiCall helper", async () => {
    const { BaseProvider } = loadProvider();
    let called = false;
    const mockApi = {
      request: async (cfg, opts) => {
        called = true;
        assert.strictEqual(opts.method, "GET");
        assert.strictEqual(opts.path, "/api/test");
        return { statusCode: 200, headers: {}, body: { ok: true } };
      },
    };
    class ApiProvider extends BaseProvider {
      static get providerName() { return "api"; }
      async add(creds, opts) { return this.apiCall("GET", "/api/test"); }
    }
    const inst = new ApiProvider({}, mockApi, {});
    const result = await inst.add({}, {});
    assert.ok(called);
    assert.strictEqual(result.statusCode, 200);
  });
});
