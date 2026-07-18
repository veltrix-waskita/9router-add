"use strict";

const http = require("http");
const https = require("https");

function request(config, { method = "GET", path = "/", body, headers = {}, cookies } = {}) {
  return new Promise((resolve, reject) => {
    const mod = config.proto === "https" ? https : http;
    const reqHeaders = { ...headers };

    if (cookies) {
      reqHeaders["Cookie"] = cookies;
    }
    if (body && !reqHeaders["Content-Type"]) {
      reqHeaders["Content-Type"] = "application/json";
    }
    if (body && !reqHeaders["Content-Length"]) {
      reqHeaders["Content-Length"] = Buffer.byteLength(body, "utf8");
    }

    const options = {
      hostname: config.host,
      port: config.port,
      path,
      method,
      headers: reqHeaders,
      rejectUnauthorized: config.proto === "https",
    };

    const req = mod.request(options, (res) => {
      const data = [];
      res.on("data", (chunk) => data.push(chunk));
      res.on("end", () => {
        const raw = Buffer.concat(data).toString("utf8");
        let parsed;
        try {
          parsed = JSON.parse(raw);
        } catch {
          parsed = raw;
        }
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: parsed,
        });
      });
    });

    req.on("error", reject);
    req.setTimeout(30000, () => { req.destroy(new Error("Request timeout")); });

    if (body) req.write(body);
    req.end();
  });
}

module.exports = { request };
