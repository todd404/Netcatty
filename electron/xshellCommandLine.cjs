const SSH_PROTOCOL = "ssh";
const TELNET_PROTOCOL = "telnet";

const URL_FLAGS = new Set(["-url", "/url"]);

function normalizeFlag(value) {
  return typeof value === "string" ? value.toLowerCase() : "";
}

function decodeUrlComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function parseXshellUrl(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) return null;
  const trimmed = rawUrl.trim();

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }

  const protocol = parsed.protocol === "ssh:"
    ? SSH_PROTOCOL
    : parsed.protocol === "telnet:"
      ? TELNET_PROTOCOL
      : null;
  if (!protocol || !parsed.hostname) return null;

  const port = parsed.port ? Number(parsed.port) : undefined;
  if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) {
    return null;
  }

  return {
    protocol,
    url: trimmed,
    hostname: parsed.hostname,
    ...(parsed.username ? { username: decodeUrlComponent(parsed.username) } : {}),
    ...(parsed.password ? { password: decodeUrlComponent(parsed.password) } : {}),
    ...(port ? { port } : {}),
  };
}

function parseXshellCommandLineTokens(argv) {
  if (!Array.isArray(argv)) return null;

  const consumedIndices = new Set();
  const operandIndices = new Set();
  const credentialIndices = new Set();
  let result = null;
  let sawUrlFlag = false;

  for (let index = 1; index < argv.length; index += 1) {
    const flag = normalizeFlag(argv[index]);

    if (flag === "-newwin" || flag === "/newwin") {
      consumedIndices.add(index);
      const directOperandIndex = index + 1;
      const directOperand = argv[directOperandIndex];
      // Xshell also accepts: -newwin ssh://user:pass@host:port
      // without a separate -url switch.
      if (
        typeof directOperand === "string"
        && !directOperand.startsWith("-")
        && !directOperand.startsWith("/")
      ) {
        const parsed = parseXshellUrl(directOperand);
        if (parsed) {
          if (result) {
            return { result: null, consumedIndices, operandIndices, credentialIndices };
          }
          result = parsed;
          sawUrlFlag = true;
          consumedIndices.add(directOperandIndex);
          operandIndices.add(directOperandIndex);
          if (parsed.password !== undefined) credentialIndices.add(directOperandIndex);
          index = directOperandIndex;
        }
      }
      continue;
    }

    if (!URL_FLAGS.has(flag)) continue;

    sawUrlFlag = true;
    consumedIndices.add(index);
    const operandIndex = index + 1;
    const rawUrl = argv[operandIndex];
    if (typeof rawUrl !== "string") {
      return { result: null, consumedIndices, operandIndices, credentialIndices };
    }

    consumedIndices.add(operandIndex);
    operandIndices.add(operandIndex);

    if (result) {
      return { result: null, consumedIndices, operandIndices, credentialIndices };
    }

    const parsed = parseXshellUrl(rawUrl);
    if (!parsed) {
      return { result: null, consumedIndices, operandIndices, credentialIndices };
    }

    result = parsed;
    if (parsed.password !== undefined) credentialIndices.add(operandIndex);
    index = operandIndex;
  }

  if (!sawUrlFlag) return null;
  return { result, consumedIndices, operandIndices, credentialIndices };
}

function parseXshellCommandLine(argv) {
  return parseXshellCommandLineTokens(argv)?.result ?? null;
}

function redactXshellCommandLineCredentials(argv) {
  if (!Array.isArray(argv)) return argv;
  const tokens = parseXshellCommandLineTokens(argv);
  if (!tokens) return argv;

  for (const index of tokens.credentialIndices) {
    const raw = argv[index];
    if (typeof raw !== "string") continue;
    argv[index] = raw.replace(
      /^([a-z][a-z0-9+.-]*:\/\/[^\/@:]*:)[^@]*(@)/i,
      "$1********$2",
    );
  }
  return argv;
}

module.exports = {
  parseXshellCommandLine,
  parseXshellCommandLineTokens,
  redactXshellCommandLineCredentials,
};
