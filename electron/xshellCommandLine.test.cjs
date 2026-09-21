const test = require("node:test");
const assert = require("node:assert/strict");

const {
  parseXshellCommandLine,
  parseXshellCommandLineTokens,
  redactXshellCommandLineCredentials,
} = require("./xshellCommandLine.cjs");

test("parseXshellCommandLine accepts Xshell -url SSH launch", () => {
  assert.deepEqual(
    parseXshellCommandLine([
      String.raw`C:\\Program Files\\Netcatty\\Netcatty.exe`,
      "-url",
      "ssh://alice:s3cret@10.0.0.8:12024",
    ]),
    {
      protocol: "ssh",
      url: "ssh://alice:s3cret@10.0.0.8:12024",
      hostname: "10.0.0.8",
      username: "alice",
      password: "s3cret",
      port: 12024,
    },
  );
});

test("parseXshellCommandLine accepts case-insensitive /URL with -newwin", () => {
  const parsed = parseXshellCommandLine([
    "Netcatty.exe",
    "-newwin",
    "/URL",
    "ssh://bob:p%40ss@example.com:2222",
  ]);
  assert.equal(parsed?.username, "bob");
  assert.equal(parsed?.password, "p@ss");
  assert.equal(parsed?.hostname, "example.com");
  assert.equal(parsed?.port, 2222);
});

test("parseXshellCommandLine accepts Xshell telnet URL", () => {
  assert.equal(
    parseXshellCommandLine(["Netcatty.exe", "-url", "telnet://old.example.com:2323"])?.protocol,
    "telnet",
  );
});

test("parseXshellCommandLine rejects non-Xshell and unsupported URL launches", () => {
  assert.equal(parseXshellCommandLine(["Netcatty.exe", "ssh://alice@example.com"]), null);
  assert.equal(parseXshellCommandLine(["Netcatty.exe", "-url", "https://example.com"]), null);
  assert.equal(parseXshellCommandLine(["Netcatty.exe", "-url"]), null);
});

test("parseXshellCommandLineTokens marks URL operand and credentials", () => {
  const tokens = parseXshellCommandLineTokens([
    "Netcatty.exe",
    "-url",
    "ssh://alice:s3cret@example.com",
  ]);
  assert.ok(tokens);
  assert.equal(tokens.result?.protocol, "ssh");
  assert.deepEqual([...tokens.operandIndices], [2]);
  assert.deepEqual([...tokens.credentialIndices], [2]);
});

test("redactXshellCommandLineCredentials masks embedded password", () => {
  const argv = [
    "Netcatty.exe",
    "-url",
    "ssh://alice:p%40ss@example.com:12024",
  ];
  redactXshellCommandLineCredentials(argv);
  assert.deepEqual(argv, [
    "Netcatty.exe",
    "-url",
    "ssh://alice:********@example.com:12024",
  ]);
});
