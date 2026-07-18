"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const http = require("http");

function loadHttpModule() {
  delete require.cache[require.resolve("../../../src/core/http-client")];
  return require("../../../src/core/http-client");
}

describe("request", () => {
  it("should make a GET request and return response", async () => {
    const { request } = loadHttpModule();
    // Start a local test server
    const server = http.createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
    await new Promise(r => server.listen(0, r));
    const port = server.address().port;

    const result = await request(
      { host: "localhost", port, proto: "http" },
      { method: "GET", path: "/api/test" }
    );
    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(result.body.ok, true);
    assert.strictEqual(result.body.path, "/api/test");

    server.close();
  });

  it("should POST with body", async () => {
    const { request } = loadHttpModule();
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", c => body += c);
      req.on("end", () => {
        res.writeHead(201, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ received: JSON.parse(body) }));
      });
    });
    await new Promise(r => server.listen(0, r));
    const port = server.address().port;

    const result = await request(
      { host: "localhost", port, proto: "http" },
      { method: "POST", path: "/api/test", body: JSON.stringify({ hello: "world" }) }
    );
    assert.strictEqual(result.statusCode, 201);
    assert.strictEqual(result.body.received.hello, "world");

    server.close();
  });

  it("should include custom headers", async () => {
    const { request } = loadHttpModule();
    const server = http.createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ auth: req.headers["x-9r-cli-auth"] }));
    });
    await new Promise(r => server.listen(0, r));
    const port = server.address().port;

    const result = await request(
      { host: "localhost", port, proto: "http" },
      { method: "GET", path: "/api/test", headers: { "X-9R-CLI-Auth": "abc123" } }
    );
    assert.strictEqual(result.body.auth, "abc123");

    server.close();
  });
});
