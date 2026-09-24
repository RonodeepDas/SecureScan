export function getTargetValidationError(value) {
  const target = (value ?? "").trim();

  if (!target) {
    return "Enter a target host or IP address.";
  }

  if (/\s/.test(target)) {
    return "Target must not contain spaces. Use a hostname like localhost or an IP like 127.0.0.1.";
  }

  if (/[;|&$`<>\\\n\r'"(){}%@#^*+=~]/.test(target)) {
    return "Target contains invalid characters. Use 127.0.0.1, localhost, or a valid hostname.";
  }

  const hasDoubleDot = /\.\./.test(target);
  const hasLeadingOrTrailingDot =
    target.startsWith(".") || target.endsWith(".");
  const hasInvalidOctet =
    /(?:^|\.)\d{1,3}(?:\.|$)/.test(target) &&
    /(?:^|\.)\d{1,3}(?:\.|$)/.test(target) &&
    target.split(".").some((part) => {
      if (!part) return true;
      const n = Number(part);
      return Number.isNaN(n) || n < 0 || n > 255;
    });

  if (hasDoubleDot || hasLeadingOrTrailingDot || hasInvalidOctet) {
    return "Invalid IP address. Use 127.0.0.1 or localhost instead of values like 127..0.1.";
  }

  // accept common valid host/IP formats, while rejecting obviously malformed input
  const looksLikeIPv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(target);
  if (looksLikeIPv4) {
    const parts = target.split(".");
    const valid = parts.every(
      (p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255,
    );
    if (!valid) {
      return "Invalid IP address. Use 127.0.0.1 or localhost instead of values like 127..0.1.";
    }
    return null;
  }

  const hostnamePattern =
    /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
  if (target.length > 253 || !hostnamePattern.test(target)) {
    return "Use a valid hostname or IP address, such as 127.0.0.1 or localhost.";
  }

  return null;
}
