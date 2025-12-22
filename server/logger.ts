type LogLevel = "debug" | "info" | "warn" | "error";

const levelPrefixes: Record<LogLevel, string> = {
  debug: "○",
  info: "●",
  warn: "▲",
  error: "✗",
};

function formatTime(): string {
  return new Date().toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function log(message: string, source = "server") {
  console.log(`${formatTime()} [${source}] ${message}`);
}

export function logInfo(message: string, source = "server") {
  console.log(`${formatTime()} ${levelPrefixes.info} [${source}] ${message}`);
}

export function logWarn(message: string, source = "server") {
  console.warn(`${formatTime()} ${levelPrefixes.warn} [${source}] ${message}`);
}

export function logError(message: string, source = "server") {
  console.error(`${formatTime()} ${levelPrefixes.error} [${source}] ${message}`);
}

export function logDebug(message: string, source = "server") {
  if (process.env.DEBUG) {
    console.log(`${formatTime()} ${levelPrefixes.debug} [${source}] ${message}`);
  }
}

// Forseti-specific logging for contract compilation
export function logForseti(action: string, details: Record<string, unknown>) {
  const detailStr = Object.entries(details)
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join(" | ");
  console.log(`${formatTime()} ● [forseti] ${action} | ${detailStr}`);
}
