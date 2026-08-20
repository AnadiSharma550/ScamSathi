#!/usr/bin/env node
/**
 * PreToolUse guard: refuse writes to files that hold secrets.
 *
 * The repo is public. `.env` carries live project configuration and sits
 * next to a tracked `.env.example`, so a single mistaken write is a leak
 * that is permanent in git history. Blocking is cheaper than revoking.
 *
 * Exit 2 blocks the tool call and shows stderr to Claude.
 */

import { basename } from "node:path";

const BLOCKED = [
  /(^|[/\\])\.env$/,
  /(^|[/\\])\.env\.(local|production|prod)$/,
  /(^|[/\\])\.credentials\.json$/,
  /(^|[/\\])(id_rsa|id_ed25519)$/,
  /\.pem$/,
  /\.p12$/,
];

// .env.example is the template and is meant to be edited.
const ALLOWED = [/(^|[/\\])\.env\.example$/];

let raw = "";
process.stdin.on("data", (chunk) => (raw += chunk));
process.stdin.on("end", () => {
  let payload;
  try {
    payload = JSON.parse(raw || "{}");
  } catch {
    process.exit(0); // Malformed payload is not the user's problem.
  }

  const input = payload.tool_input ?? {};
  const paths = [input.file_path, input.path, input.notebook_path].filter(Boolean);

  for (const p of paths) {
    const normalised = String(p).replace(/\\/g, "/");
    if (ALLOWED.some((re) => re.test(normalised))) continue;
    if (BLOCKED.some((re) => re.test(normalised))) {
      process.stderr.write(
        `Blocked: ${basename(normalised)} holds secrets and this repo is public.\n` +
          `Edit it yourself, or put the value in .env.example if it is not secret.\n`,
      );
      process.exit(2);
    }
  }
  process.exit(0);
});
