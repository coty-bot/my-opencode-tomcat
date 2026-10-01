import { tool } from "@opencode-ai/plugin"
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs"
import { basename } from "node:path"

const TOOL_DIR =
  process.env.DISCLOSURE_VERIFIER_DIR ??
  "/home/opencode/src/my-opencode-tomcat/disclosure-verifier"
const STATUS_FILE = `${TOOL_DIR}/output/pipeline-status.json`
const DEFAULT_OUT_DIR = "/home/opencode/workspace/security-scans/tomcat/verification"

type StatusFile = { pid: number; log: string; launched_at: string; slugs: string[] }

function readStatus(): StatusFile | null {
  try {
    return JSON.parse(readFileSync(STATUS_FILE, "utf8")) as StatusFile
  } catch {
    return null
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (e: any) {
    return e?.code === "EPERM"
  }
}

// The recorded log path can go stale if the tool dir moves after launch;
// fall back to the same filename in the current location, then newest pipeline-*.log.
function resolveLog(st: StatusFile): { path: string; moved: boolean } | null {
  if (existsSync(st.log)) return { path: st.log, moved: false }
  const local = `${TOOL_DIR}/output/${basename(st.log)}`
  if (existsSync(local)) return { path: local, moved: true }
  let logs: string[] = []
  try {
    logs = readdirSync(`${TOOL_DIR}/output`)
      .filter((n) => n.startsWith("pipeline-") && n.endsWith(".log"))
      .map((n) => `${TOOL_DIR}/output/${n}`)
      .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)
  } catch {
    // no output dir at all
  }
  return logs[0] ? { path: logs[0], moved: true } : null
}

// Older status files recorded raw argv (flags included); show only slug-like args.
const VALUE_FLAGS = new Set([
  "--config", "--repo-root", "--disclosures-dir", "--out-dir", "--security-model",
  "--jar-dir", "--lmstudio-url", "--evaluators", "--seed", "--temperature",
  "--top-p", "--max-tokens-eval", "--max-tokens-final",
])
function displaySlugs(st: StatusFile): string {
  const slugs: string[] = []
  let skipNext = false
  for (const s of st.slugs ?? []) {
    if (skipNext) { skipNext = false; continue }
    if (s.startsWith("--model-") || s.startsWith("--ctx-") || s.startsWith("--input-budget-")) { skipNext = true; continue }
    if (VALUE_FLAGS.has(s)) { skipNext = true; continue }
    if (s.startsWith("-")) continue
    slugs.push(s)
  }
  return slugs.length ? slugs.join(", ") : "all disclosures"
}

function tailLines(path: string, n: number): string | null {
  try {
    const lines = readFileSync(path, "utf8").split("\n")
    return lines.slice(-n).join("\n")
  } catch {
    return null
  }
}

// The run log records the out-dir on every "== verifying <slug> -> <out>/<slug>"
// line (and in the final "Done. N disclosure(s) verified -> <out>" line).
function detectOutDir(logPath: string): string | null {
  try {
    const text = readFileSync(logPath, "utf8")
    let m = text.match(/== verifying \S+ -> (.+)\/\S+\n/)
    if (m) return m[1]
    m = text.match(/verified -> (\S+)/)
    if (m) return m[1]
  } catch {
    // no log yet
  }
  return null
}

function slugProgress(outDir: string): string[] {
  let entries: string[] = []
  try {
    entries = readdirSync(outDir).filter((n) => statSync(`${outDir}/${n}`).isDirectory())
  } catch {
    return [`(no out-dir at ${outDir})`]
  }
  const lines: string[] = []
  for (const slug of entries.sort()) {
    const dir = `${outDir}/${slug}`
    const has = (f: string) => existsSync(`${dir}/${f}`)
    if (!has("mechanical.json") && !has("report.md")) continue
    const stages = ["a", "b", "c", "d"]
      .filter((s) => has(`stage-${s}.json`))
      .map((s) => s.toUpperCase())
    let state: string
    if (has("report.md")) state = "done"
    else if (stages.length) state = `through stage ${stages[stages.length - 1]}`
    else if (has("mechanical.json")) state = "mechanical checks done"
    else state = "started"
    lines.push(`  ${slug}: ${state}`)
  }
  return lines.length ? lines : ["(no slug dirs yet)"]
}

function fmtDuration(ms: number): string {
  const m = Math.floor(ms / 60000)
  if (m < 1) return "<1m"
  if (m < 60) return `${m}m`
  return `${Math.floor(m / 60)}h ${m % 60}m`
}

async function runCmd(argv: string[], timeoutMs: number): Promise<{ code: number; stdout: string; stderr: string }> {
  const child = Bun.spawn(argv, { stdout: "pipe", stderr: "pipe" })
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    const run = (async () => {
      const [stdout, stderr] = await Promise.all([
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ])
      return { code: await child.exited, stdout, stderr }
    })()
    run.catch(() => {}) // losing branch of the race must not unhandled-reject
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        child.kill("SIGKILL")
        reject(new Error(`timed out after ${Math.round(timeoutMs / 1000)}s`))
      }, timeoutMs)
    })
    return await Promise.race([run, timeout])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

export const launch = tool({
  description: `Launch the Tomcat disclosure-verifier pipeline (multi-model LM Studio verification of security disclosures/tests/patches) fully detached via run_pipeline.sh. Unloads ALL loaded LM Studio models first — including this agent's own model, which auto-reloads on demand in later turns (first token slower). Returns immediately (~3s) with pid/log/status-file; poll progress with disclosure-pipeline_status and read verdicts with disclosure-pipeline_results. A full 15-disclosure campaign takes ~2h10m.`,
  args: {
    slugs: tool.schema
      .array(tool.schema.string())
      .optional()
      .describe("Disclosure slugs to verify (e.g. '01-xff-access-control-bypass'); omit to verify every disclosure in the campaign"),
    out_dir: tool.schema
      .string()
      .optional()
      .describe("Output root for this run; default is <campaign>/verification per config.toml. Use a fresh dir (e.g. verification-run<N>-<timestamp>) to preserve prior results."),
  },
  execute: async (args) => {
    const argv = ["bash", `${TOOL_DIR}/run_pipeline.sh`]
    if (args.out_dir) argv.push("--out-dir", args.out_dir)
    for (const s of args.slugs ?? []) argv.push(s)

    let res: { code: number; stdout: string; stderr: string }
    try {
      res = await runCmd(argv, 120_000)
    } catch (e: any) {
      return `launch failed: ${e?.message ?? e}`
    }
    if (res.code !== 0) {
      return `launch failed (exit ${res.code}):\n${(res.stderr || res.stdout).slice(-2000)}`
    }
    const st = readStatus()
    let text = "Pipeline launched (detached).\n"
    if (st) {
      text += `  pid:     ${st.pid}\n`
      text += `  log:     ${st.log}\n`
      text += `  status:  ${STATUS_FILE}\n`
    } else {
      text += "  (warning: pipeline-status.json not found after launch — check the log)\n"
    }
    text += `  out-dir: ${args.out_dir ?? `default (${DEFAULT_OUT_DIR} per config.toml)`}\n`
    text += `  slugs:   ${args.slugs?.length ? args.slugs.join(", ") : "all disclosures"}\n\n`
    text +=
      "NOTE: every loaded LM Studio model was unloaded first, including this agent's own — it auto-reloads on demand in later turns. Poll with disclosure-pipeline_status; read verdicts with disclosure-pipeline_results."
    return text
  },
})

export const status = tool({
  description: `Check progress of the most recent disclosure-verifier pipeline launch: pid liveness, elapsed time since launch, detected out-dir, per-slug stage progress (mechanical -> stages A-D -> report.md), and a tail of the run log. Read-only; safe to poll while running or after completion.`,
  args: {
    tail_lines: tool.schema
      .number()
      .int()
      .min(1)
      .max(200)
      .optional()
      .describe("Number of log lines to include at the end (default 15)"),
  },
  execute: async (args) => {
    const st = readStatus()
    if (!st) return "No pipeline-status.json found — nothing launched yet (or output/ was cleaned)."
    const alive = pidAlive(st.pid)
    const started = Date.parse(st.launched_at)
    const elapsed = Number.isFinite(started) ? fmtDuration(Date.now() - started) : "?"
    const n = args.tail_lines ?? 15
    const log = resolveLog(st)
    const outDir = log ? detectOutDir(log.path) : null
    let text = `Pipeline ${alive ? "RUNNING" : "not running"} (pid ${st.pid}, launched ${st.launched_at}, ~${elapsed} since launch)\n`
    if (!log) {
      text += `log:     (missing; recorded path was ${st.log})\n`
    } else {
      text += `log:     ${log.path}${log.moved ? "  [recorded path stale, resolved to current location]" : ""}\n`
    }
    text += `out-dir: ${outDir ?? "(not detected in log yet)"}\n`
    text += `slugs:   ${displaySlugs(st)}\n\n`
    if (outDir) {
      text += "Per-slug progress:\n" + slugProgress(outDir).join("\n") + "\n\n"
    }
    const tail = log ? tailLines(log.path, n) : null
    if (tail !== null) text += `Log tail (${n} lines):\n${tail}\n`
    return text
  },
})

export const results = tool({
  description: `Read disclosure-verifier results from a run's out-dir: all-summary.json rows (classification, legit_security_finding, final CVSS score/vector, edits_status) for every slug, plus the full report.md when slug is given. Defaults to the most recent launch's out-dir (detected from its log).`,
  args: {
    slug: tool.schema.string().optional().describe("Limit to one disclosure slug; includes its full report.md"),
    out_dir: tool.schema
      .string()
      .optional()
      .describe("Run output root (default: detected from the latest pipeline-status.json log, else <campaign>/verification)"),
  },
  execute: async (args) => {
    let outDir = args.out_dir ?? null
    if (!outDir) {
      const st = readStatus()
      const log = st ? resolveLog(st) : null
      outDir = (log && detectOutDir(log.path)) || DEFAULT_OUT_DIR
    }
    const summaryPath = `${outDir}/all-summary.json`
    if (!existsSync(summaryPath)) {
      return `No all-summary.json at ${summaryPath} — the run may still be in progress (try disclosure-pipeline_status) or used a different out-dir.`
    }
    let rows: any[]
    try {
      const parsed = JSON.parse(readFileSync(summaryPath, "utf8"))
      rows = Array.isArray(parsed) ? parsed : [parsed]
    } catch (e: any) {
      return `Could not parse ${summaryPath}: ${e?.message ?? e}`
    }
    if (args.slug) rows = rows.filter((r) => r.slug === args.slug)
    if (!rows.length) {
      const all = JSON.parse(readFileSync(summaryPath, "utf8"))
      const known = (Array.isArray(all) ? all : [all]).map((r: any) => r.slug).join(", ")
      return `No row for slug '${args.slug}' in ${summaryPath}. Known slugs: ${known}`
    }

    let text = `Results from ${outDir} (${rows.length} slug${rows.length === 1 ? "" : "s"}):\n\n`
    for (const r of rows) {
      const cvss =
        typeof r.final_base_score === "number"
          ? `${r.final_base_score}${r.final_cvss_vector ? ` (${r.final_cvss_vector})` : ""}`
          : "n/a"
      text += `- ${r.slug}: ${r.classification ?? "?"} | legit_security_finding=${r.legit_security_finding ?? "?"} | cvss=${cvss} | edits=${r.edits_status ?? "?"}\n`
    }

    if (args.slug) {
      const reportPath = `${outDir}/${args.slug}/report.md`
      try {
        let report = readFileSync(reportPath, "utf8")
        text += `\n--- ${args.slug} report.md ---\n`
        if (report.length > 24000) {
          text += report.slice(0, 24000) + `\n... [truncated; full report at ${reportPath}]`
        } else {
          text += report
        }
      } catch {
        text += `\n(no report.md at ${reportPath} yet)`
      }
    }
    return text
  },
})
