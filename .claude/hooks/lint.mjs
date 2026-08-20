#!/usr/bin/env node
/**
 * PostToolUse: lint and autofix the file that was just edited.
 *
 * Catches the things that cost a round-trip to CI otherwise: import order,
 * unused imports, stray blank lines left by sed. Fixes in place and reports
 * only what it could not fix.
 *
 * Never blocks. A linter that fails the edit is worse than no linter --
 * exit 0 always, and stay quiet when there is nothing to say.
 */

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..", "..");
const RUFF = resolve(ROOT, "api", ".venv", "Scripts", "python.exe");

function run(cmd, args, cwd) {
  try {
    return execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: "pipe" });
  } catch (err) {
    return `${err.stdout ?? ""}${err.stderr ?? ""}`;
  }
}

let raw = "";
process.stdin.on("data", (chunk) => (raw += chunk));
process.stdin.on("end", () => {
  let file;
  try {
    file = JSON.parse(raw || "{}").tool_input?.file_path;
  } catch {
    process.exit(0);
  }
  if (!file || !existsSync(file)) process.exit(0);

  let output = "";

  if (file.endsWith(".py") && existsSync(RUFF)) {
    run(RUFF, ["-m", "ruff", "check", "--fix", "-q", file], resolve(ROOT, "api"));
    output = run(RUFF, ["-m", "ruff", "check", "--output-format=concise", file], resolve(ROOT, "api"));
  } else if (/\.(ts|tsx|jsx)$/.test(file)) {
    const web = resolve(ROOT, "web");
    if (existsSync(resolve(web, "node_modules", ".bin"))) {
      output = run("npx", ["--no-install", "oxlint", "--fix", file], web);
    }
  }

  const problems = output
    .split("\n")
    .filter((line) => /\b(error|warning)\b/i.test(line) && !/^Found \d+ (error|warning)s? in/.test(line))
    .slice(0, 10);

  if (problems.length) {
    process.stderr.write(`Lint (autofix applied, still outstanding):\n${problems.join("\n")}\n`);
  }
  process.exit(0);
});
