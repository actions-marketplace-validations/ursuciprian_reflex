#!/usr/bin/env node
// Build the docs website (GitHub Pages) from README.md and docs/*.md. Zero dependencies.
//   node site/build.mjs [--out site/dist]
// Every page is static HTML: the four docs as they are, a landing page, and one page per search
// intent assembled from sections of those docs (by heading), with its own title, description and intro.
// Links between the docs point at the site; links to other repository files point at GitHub.
import {cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync} from "node:fs";
import {dirname, join, posix} from "node:path";
import {fileURLToPath} from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
export const SITE = pkg.homepage.replace(/\/?$/, "/");               // https://ursuciprian.github.io/reflex/
const BASE = new URL(SITE).pathname;                                   // /reflex/
const REPO = "https://github.com/ursuciprian/reflex";
const DOC_PAGE = {"README.md": "", "docs/GUIDE.md": "guide/", "docs/SETUP.md": "setup/", "docs/FAQ.md": "faq/"};

// ---------------------------------------------------------------------------------------------
// Markdown to HTML: the subset these docs use (GitHub flavoured: ATX headings, fences, nested
// lists, tables, blockquotes, raw HTML blocks, inline code, links, images, emphasis).
export const esc = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const unesc = s => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
export const text = html => unesc(html.replace(/<[^>]*>/g, "")).replace(/\s+/g, " ").trim();
// GitHub's heading anchors: lowercase, punctuation dropped, spaces to dashes.
export const slug = s => s.toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, "").replace(/ /g, "-");

const INLINE_TAGS = /<\/?(?:a|img|sub|sup|br|code|kbd|b|strong|em|i)\b[^>]*>/gi;
const BLOCK_TAG = /^ {0,3}<\/?(?:details|summary|div|p|h[1-6]|table|picture|pre|section)(?:\s|>|\/>|$)/i;
const HTML_START = /^ {0,3}<\/?[a-zA-Z][a-zA-Z0-9-]*(?:\s|>|\/>|$)/;
const FENCE = /^( {0,3})(`{3,}|~{3,})\s*([^`\s]*)/;
const HEADING = /^ {0,3}(#{1,6})(?:\s+(.*?))?\s*#*\s*$/;
const HR = /^ {0,3}([-*_])(?:\s*\1){2,}\s*$/;
const LI = /^( *)([-*+]|\d{1,9}[.)])( +|$)(.*)$/;
const DELIM = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/;

// Raw HTML from the docs: drop presentational align, send href/src through the link rewriter.
const cleanTag = (t, ctx) => t.replace(/\s+align="[^"]*"/gi, "").replace(/\b(href|src)="([^"]*)"/gi, (_, a, u) => `${a}="${esc(ctx.link(unesc(u)))}"`);

export function inline(src, ctx) {
  const keep = [], ph = h => `\u0000${keep.push(h) - 1}\u0000`;
  const run = s => {
    s = s.replace(/(`+)([\s\S]*?[^`])\1(?!`)/g, (_, _t, c) => ph(`<code>${esc(c.replace(/\n/g, " ").replace(/^ ([\s\S]*) $/, "$1"))}</code>`));
    s = s.replace(/\\([\\`*_{}[\]()#+\-.!|<>~])/g, (_, c) => ph(esc(c)));
    s = s.replace(/<(https?:\/\/[^\s>]+)>/g, (_, u) => ph(`<a href="${esc(u)}">${esc(u)}</a>`));
    s = s.replace(INLINE_TAGS, t => ph(cleanTag(t, ctx)));
    s = s.replace(/ {2,}\n/g, () => ph("<br>\n"));
    s = s.replace(/!\[([^\]]*)\]\(<?([^()\s>]+)>?(?:\s+"[^"]*")?\)/g, (_, alt, u) => ph(`<img src="${esc(ctx.link(u))}" alt="${esc(alt)}">`));
    s = s.replace(/\[((?:[^[\]]|\[[^\]]*\])*)\]\(<?([^()\s>]+(?:\([^)\s]*\)[^()\s>]*)?)>?(?:\s+"[^"]*")?\)/g,
      (_, t, u) => ph(`<a href="${esc(ctx.link(u))}">${run(t)}</a>`));
    s = esc(s);
    s = s.replace(/\*\*(?=\S)([\s\S]*?\S)\*\*/g, "<strong>$1</strong>").replace(/(^|[^\w])__(?=\S)([\s\S]*?\S)__(?!\w)/g, "$1<strong>$2</strong>");
    s = s.replace(/\*(?=[^\s*])([^*]*?[^\s*])\*/g, "<em>$1</em>").replace(/(^|[^\w])_(?=\S)([^_]*?\S)_(?!\w)/g, "$1<em>$2</em>");
    return s;
  };
  let out = run(src);
  while (/\u0000\d+\u0000/.test(out)) out = out.replace(/\u0000(\d+)\u0000/g, (_, i) => keep[i]);
  return out;
}

const splitRow = line => {
  const l = line.trim().replace(/^\|/, "").replace(/(?<!\\)\|$/, "");
  const cells = [];
  let cur = "", code = false;
  for (let i = 0; i < l.length; i++) {
    if (l[i] === "\\" && l[i + 1] === "|") { cur += "|"; i++; continue; }
    if (l[i] === "`") code = !code;
    if (l[i] === "|" && !code) { cells.push(cur.trim()); cur = ""; } else cur += l[i];
  }
  return [...cells, cur.trim()];
};

// A line that ends a paragraph (a list may interrupt one only as a bullet or as "1.").
const interrupts = l => HEADING.test(l) || FENCE.test(l) || /^ {0,3}>/.test(l) || HR.test(l) || BLOCK_TAG.test(l) ||
  (LI.test(l) && LI.exec(l)[4].trim() !== "" && (/^[-*+]$/.test(LI.exec(l)[2]) || /^1[.)]$/.test(LI.exec(l)[2])));

export function blocks(lines, ctx, tight = false) {
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    let m;
    if (!line.trim()) { i++; continue; }
    if ((m = line.match(FENCE))) {
      const [, ind, fence, lang] = m, body = [];
      for (i++; i < lines.length && !new RegExp(`^ {0,3}${fence[0] === "`" ? "`" : "~"}{${fence.length},}\\s*$`).test(lines[i]); i++)
        body.push(lines[i].replace(new RegExp(`^ {0,${ind.length}}`), ""));
      i++;
      out.push(`<pre tabindex="0"><code${lang ? ` class="language-${esc(lang)}"` : ""}>${esc(body.join("\n"))}</code></pre>`);
      continue;
    }
    if ((m = line.match(HEADING))) {
      const level = Math.min(6, Math.max(1, m[1].length + ctx.shift)), html = inline(m[2] ?? "", ctx);
      let id = slug(text(html));
      const n = ctx.ids.get(id) ?? 0;
      ctx.ids.set(id, n + 1);
      if (n) id = `${id}-${n}`;
      ctx.headings.push({level, id, html});
      out.push(`<h${level} id="${esc(id)}">${html}</h${level}>`);
      i++; continue;
    }
    if (HR.test(line)) { out.push("<hr>"); i++; continue; }
    if (/^ {0,3}>/.test(line)) {
      const body = [];
      for (; i < lines.length && lines[i].trim() && (/^ {0,3}>/.test(lines[i]) || !interrupts(lines[i])); i++) body.push(lines[i].replace(/^ {0,3}> ?/, ""));
      out.push(`<blockquote>\n${blocks(body, ctx)}\n</blockquote>`);
      continue;
    }
    if (line.includes("|") && i + 1 < lines.length && DELIM.test(lines[i + 1]) && lines[i + 1].includes("-")) {
      const head = splitRow(line), align = splitRow(lines[i + 1]).map(c => c.startsWith(":") && c.endsWith(":") ? "center" : c.endsWith(":") ? "right" : c.startsWith(":") ? "left" : null);
      const cell = (tag, c, k) => `<${tag}${align[k] ? ` style="text-align:${align[k]}"` : ""}>${inline(c, ctx)}</${tag}>`;
      const rows = [];
      for (i += 2; i < lines.length && lines[i].trim() && lines[i].includes("|") && !interrupts(lines[i]); i++) rows.push(splitRow(lines[i]));
      out.push(`<div class="scroll" tabindex="0"><table>\n<thead><tr>${head.map((c, k) => cell("th", c, k)).join("")}</tr></thead>\n<tbody>\n` +
        rows.map(r => `<tr>${head.map((_, k) => cell("td", r[k] ?? "", k)).join("")}</tr>`).join("\n") + "\n</tbody></table></div>");
      continue;
    }
    if (LI.test(line) && !HR.test(line)) { i = list(lines, i, ctx, out); continue; }
    if (HTML_START.test(line)) {
      const body = [];
      for (; i < lines.length && lines[i].trim(); i++) body.push(lines[i]);
      out.push(body.join("\n").replace(/<[a-zA-Z][^>]*>/g, t => cleanTag(t, ctx))
        .replace(/(<code>)([\s\S]*?)(<\/code>)/g, (_, a, c, b) => a + esc(unesc(c)) + b));
      continue;
    }
    const para = [line.trim()];
    for (i++; i < lines.length && lines[i].trim() && !interrupts(lines[i]); i++) para.push(lines[i].replace(/^\s+/, ""));
    const html = inline(para.join("\n"), ctx);
    out.push(tight ? html : `<p>${html}</p>`);
  }
  return out.join("\n");
}

function list(lines, i, ctx, out) {
  const first = LI.exec(lines[i]), ordered = /\d/.test(first[2]), base = first[1].length, items = [];
  let loose = false;
  while (i < lines.length) {
    const m = LI.exec(lines[i]);
    if (!m || HR.test(lines[i]) || m[1].length < base || m[1].length > base + 3 || /\d/.test(m[2]) !== ordered) break;
    const pad = m[3].length > 4 || !m[3].length ? 1 : m[3].length, indent = m[1].length + m[2].length + pad;
    const body = [m[3].length > 4 ? m[3].slice(1) + m[4] : m[4]];
    for (i++; i < lines.length; i++) {
      const l = lines[i].replace(/\t/g, "    ");
      if (!l.trim()) { body.push(""); continue; }
      if (l.match(/^ */)[0].length >= indent) { body.push(l.slice(indent)); continue; }
      if (body.at(-1).trim() && !LI.test(l) && !interrupts(l)) { body.push(l.trim()); continue; }   // lazy continuation
      break;
    }
    let trailing = 0;
    while (body.length > 1 && !body.at(-1).trim()) { body.pop(); trailing++; }
    if (body.some(l => !l.trim())) loose = true;
    items.push(body);
    const next = i < lines.length ? LI.exec(lines[i]) : null;
    const continues = next && !HR.test(lines[i]) && next[1].length >= base && next[1].length <= base + 3 && /\d/.test(next[2]) === ordered;
    if (!continues) break;
    if (trailing) loose = true;
  }
  const start = ordered ? parseInt(first[2], 10) : 1, tag = ordered ? "ol" : "ul";
  out.push(`<${tag}${ordered && start !== 1 ? ` start="${start}"` : ""}>\n${items.map(b => `<li>${blocks(b, ctx, !loose)}</li>`).join("\n")}\n</${tag}>`);
  return i;
}

// ---------------------------------------------------------------------------------------------
// Links: a doc (or an anchor in one) goes to its page on the site, anything else in the repo to GitHub.
function linker(file, page) {
  return url => {
    if (/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(url)) return url;
    const [path, hash = ""] = url.split("#");
    const target = path ? posix.normalize(posix.join(posix.dirname(file), path)).replace(/^\.\//, "") : file;
    if (target in DOC_PAGE) return DOC_PAGE[target] === page.path && page.full ? `#${hash}` : `${BASE}${DOC_PAGE[target]}${hash ? `#${hash}` : ""}`;
    if (target.startsWith("assets/")) return `${BASE}${target}`;
    const dir = existsSync(join(ROOT, target)) && statSync(join(ROOT, target)).isDirectory();
    return `${REPO}/${dir ? "tree" : "blob"}/main/${target}${hash ? `#${hash}` : ""}`;
  };
}

const read = file => readFileSync(join(ROOT, file), "utf8").replace(/\r\n?/g, "\n");
// The lines of one section: the heading line to the next heading of the same or a higher level.
export function section(file, heading) {
  const lines = read(file).split("\n");
  let fenced = false, start = -1, level = 0;
  for (let i = 0; i < lines.length; i++) {
    if (FENCE.test(lines[i])) fenced = !fenced;
    if (fenced) continue;
    const m = lines[i].match(HEADING);
    if (!m) continue;
    if (start < 0 && (m[2] ?? "").trim() === heading) { start = i; level = m[1].length; }
    else if (start >= 0 && m[1].length <= level) return {lines: lines.slice(start, i), level};
  }
  if (start < 0) throw new Error(`${file}: no heading "${heading}"`);
  return {lines: lines.slice(start), level};
}
// One paragraph, found by how it starts (for a point made inside a longer section).
function paragraph(file, prefix) {
  const lines = read(file).split("\n"), i = lines.findIndex(l => l.startsWith(prefix));
  if (i < 0) throw new Error(`${file}: no paragraph starting "${prefix}"`);
  const end = lines.findIndex((l, k) => k > i && !l.trim());
  return lines.slice(i, end < 0 ? undefined : end);
}

// ---------------------------------------------------------------------------------------------
// Pages. Intent pages reuse doc sections; the intro is a short summary of those sections.
const INSTALL = `<div class="install"><p><strong>Install:</strong> <code>npx @ursuciprian/reflex setup</code> starts with local rules in shadow mode, no account or key.
Plugins for Claude Code, Codex CLI and opencode: <a href="${BASE}setup/">setup guide</a>.</p></div>`;

export const PAGES = [
  {path: "", file: "README.md", full: true, skipFirst: true, nav: "Home",
   title: "Reflex: guardrails for Claude Code, Codex CLI and AI coding agents",
   h1: "Reflex: a pre-execution risk gate for AI coding agents",
   description: "Open-source pre-execution gate and prompt injection guard for Claude Code, Codex CLI, opencode and pi, with terraform checks, change freezes and audit export.",
   intro: "Reflex hooks into your coding agent and decides, for every shell command, whether it runs, needs a human's approval, or is blocked. It also scans what the agent reads for prompt injection. It starts keyless, with local rules in shadow mode."},
  {path: "claude-code-hooks/", title: "Claude Code hooks for production safety", h1: "Claude Code hooks for production safety",
   description: "A Claude Code PreToolUse hook that checks each Bash command before it runs and denies destructive production changes, using the AWS profile and kube context.",
   intro: "Reflex installs as a Claude Code plugin or through its setup command and adds a PreToolUse hook that checks every Bash command before it runs. Its deterministic rules block destructive production operations and force pushes to main, and it knows the AWS profile, kube context, Terraform workspace and git branch a command runs in.",
   sources: [["docs/FAQ.md", "How do I stop Claude Code from running dangerous commands?"], ["docs/FAQ.md", "How do I install Reflex as a Claude Code plugin?"],
     ["docs/SETUP.md", "Claude Code plugin"], ["README.md", "Supported agents: Claude Code hooks, Codex hooks and more"]],
   related: ["claude-code-permissions/", "kubectl-delete/", "terraform-guardrails/", "prompt-injection/"]},
  {path: "terraform-guardrails/", title: "Terraform guardrails for AI coding agents", h1: "Terraform guardrails for AI coding agents",
   description: "Stop an AI coding agent from destroying infrastructure: terraform apply asks for a saved plan, and a plan that deletes or replaces resources is denied.",
   intro: "An agent's terraform apply without a saved plan asks for terraform plan -out=tfplan. With infra.terraform_show on and a provider plugin cache, Reflex reads the saved plan with terraform show -json and denies a plan that deletes or replaces anything. terraform destroy asks, and is denied in production.",
   sources: [["docs/FAQ.md", "How do I stop an AI agent from destroying infrastructure with terraform apply?"],
     ["docs/GUIDE.md", "Plan-aware terraform gate: stop AI agents from destroying infrastructure"], ["README.md", "Terraform apply against prod"]],
   related: ["kubectl-delete/", "change-freeze/", "soc2-audit-log/", "claude-code-hooks/"]},
  {path: "kubectl-delete/", title: "Stop AI agents from running kubectl delete in production", h1: "Stop AI agents from running kubectl delete",
   description: "Reflex judges kubectl with the kube context, AWS profile and working directory, so kubectl delete asks in a dev context and is denied in a prod one.",
   intro: "The same kubectl delete asks in a dev context and is denied in a production one: the kube context, AWS profile, Terraform workspace, git branch and paths such as envs/prod are part of every decision. A team policy can name your production clusters, and the optional infra.kubectl_diff setting flags deletes of namespaces, PVCs, statefulsets and CRDs.",
   sources: [["README.md", "Infra guardrails: terraform, kubectl, AWS and change management"], ["README.md", "kubectl delete in a prod context"],
     {file: "docs/GUIDE.md", para: "**kubectl delete guardrail (optional).**"}, ["docs/FAQ.md", "How do I share Reflex rules with my team, like Claude Code team settings?"]],
   related: ["terraform-guardrails/", "change-freeze/", "claude-code-hooks/", "codex-cli-guardrails/"]},
  {path: "prompt-injection/", title: "Prompt injection protection for coding agents", h1: "Prompt injection protection for coding agents",
   description: "The Reflex injection guard scans web pages, MCP results and network command output for text written to steer a coding agent, then warns or removes it.",
   intro: "The gate judges what an agent runs; the injection guard judges what it reads first. After a web fetch, an MCP call, a read of a file outside the project or a network command, it scans the result for text written to steer the agent and returns pass, warn or block. It is a filter: an injection written as ordinary prose can pass the local detectors.",
   sources: [["docs/FAQ.md", "Does Reflex protect coding agents against prompt injection?"], ["README.md", "Prompt injection guard for coding agents"],
     ["README.md", "A prompt injection in a fetched README"], ["docs/GUIDE.md", "Injection guard"]],
   related: ["claude-code-hooks/", "codex-cli-guardrails/", "jev/", "faq/"]},
  {path: "codex-cli-guardrails/", title: "Codex CLI guardrails: pre-execution hooks for Codex", h1: "Codex CLI guardrails",
   description: "Reflex adds Codex CLI hooks that judge each Bash command inside the Codex sandbox and approval policy, and scan Bash and MCP results for prompt injection.",
   intro: "Reflex adds Codex hooks that judge each Bash command inside whatever sandbox mode and approval policy Codex runs with; those stay in charge. Codex hooks cannot show a prompt, so a Reflex ask blocks with a reason and the human runs the exact command with reflex run in their own terminal.",
   sources: [["docs/FAQ.md", "What guardrails can I add to Codex CLI, and how does Reflex work with the Codex sandbox?"], ["docs/FAQ.md", "How do I install Reflex as a Codex CLI plugin?"],
     ["docs/SETUP.md", "Codex CLI plugin"]],
   related: ["claude-code-hooks/", "prompt-injection/", "claude-code-permissions/", "terraform-guardrails/"]},
  {path: "soc2-audit-log/", title: "SOC 2 audit log for AI agent commands", h1: "SOC 2 audit log for AI agent commands",
   description: "reflex audit exports one row per AI agent command decision as csv, json or jsonl: change management evidence for SOC 2 and ISO 27001.",
   intro: "reflex audit exports one row per decision the gate logged: which agent ran what, where, in which environment tier, what Reflex decided and who approved it. It reads Reflex's local logs, so it is evidence for a change management control, not tamper-proof storage. A webhook can post redacted decisions off the machine.",
   sources: [["docs/FAQ.md", "How do I audit AI agent commands for SOC 2 or ISO 27001?"], ["docs/GUIDE.md", "Audit log for AI agent commands (SOC 2)"]],
   related: ["change-freeze/", "terraform-guardrails/", "kubectl-delete/", "faq/"]},
  {path: "change-freeze/", title: "Change freeze for AI coding agents", h1: "Change freeze for AI coding agents",
   description: "Set a deploy freeze or change window for AI coding agents: during it, production commands that are not read-only ask a human or are denied.",
   intro: "During a change window you define, a command that is not read-only and touches production asks a human or is denied. Windows go in your own config.json or in the team policy, work in shadow and enforce mode, and can only tighten.",
   sources: [["docs/FAQ.md", "How do I set a deploy freeze or change window for AI coding agents?"], ["docs/GUIDE.md", "Change freeze for AI coding agents"]],
   related: ["soc2-audit-log/", "terraform-guardrails/", "kubectl-delete/", "claude-code-hooks/"]},
  {path: "jev/", title: "TypeSafe Jev (System One) as a pre-execution gate", h1: "Jev (TypeSafe System One) as a pre-execution gate",
   description: "How Reflex uses TypeSafe Jev, a System One model, to judge shell commands the local rules do not settle, with your policy turning answers into pass, ask, deny.",
   intro: "Rules settle what they cover without any API call. For the rest, Reflex can send one request to TypeSafe Jev, a small System One model that answers typed questions about the command, and your policy.json turns the answers into pass, ask or deny. The local engine needs no key; Jev is used after reflex setup --engine jev, or when a TypeSafe key is present.",
   sources: [["docs/FAQ.md", "What is TypeSafe Jev (System One)?"], ["docs/FAQ.md", "Jev vs Laya: which engine should I use?"],
     ["README.md", "Engines: local rules and TypeSafe Jev (System One)"], ["docs/GUIDE.md", "Local and hosted operation"],
     ["docs/SETUP.md", "1. Start locally, or enable hosted classification"]],
   related: ["claude-code-hooks/", "prompt-injection/", "claude-code-permissions/", "faq/"]},
  {path: "claude-code-permissions/", title: "Reflex vs Claude Code permissions and auto mode", h1: "Reflex vs Claude Code permissions and auto mode",
   description: "How Reflex compares with Claude Code permission prompts, allowlists, running with prompts off, containers and Codex sandbox modes.",
   intro: "Claude Code's permission rules match tools and command prefixes, and its permission modes decide how much it asks. Reflex is a hook that judges each shell command by what it does and where it points. By default it only emits ask or deny and leaves pass to your permission settings, so your allowlist keeps working. It gates shell commands, not file edits or MCP calls.",
   sources: [["docs/FAQ.md", "How is Reflex different from Claude Code permission prompts and allowlists?"], ["docs/FAQ.md", "Can I use Reflex with --dangerously-skip-permissions?"],
     ["docs/FAQ.md", "Do I still need a devcontainer or a sandbox if I use Reflex?"], ["README.md", "Compared with other AI coding agent guardrails"]],
   related: ["claude-code-hooks/", "codex-cli-guardrails/", "jev/", "faq/"]},
  {path: "faq/", file: "docs/FAQ.md", full: true, skipFirst: true, faq: true, nav: "FAQ", title: "Reflex FAQ: guardrails and command approval for AI coding agents", h1: "Reflex FAQ",
   description: "Answers about Reflex: installing it in Claude Code, Codex CLI and opencode, terraform and kubectl guardrails, keys, cost, latency, data and audits.",
   intro: "Answers to the questions people ask about Reflex, each checked against the code and the other docs.",
   related: ["claude-code-hooks/", "claude-code-permissions/", "terraform-guardrails/", "setup/"]},
  {path: "guide/", file: "docs/GUIDE.md", full: true, skipFirst: true, nav: "Guide", title: "Reflex guide: command gate, injection guard, autonomous agents", h1: "Reflex guide",
   description: "How Reflex decides a command, rolling it out, the team policy, the terraform gate, change freezes, the audit log, the injection guard and autonomous agents.",
   intro: "How the command gate, the prompt injection guard and the autonomous agent profile work, and how to test, tune and roll them out.",
   related: ["setup/", "faq/", "terraform-guardrails/", "prompt-injection/"]},
  {path: "setup/", file: "docs/SETUP.md", full: true, skipFirst: true, nav: "Setup", title: "Reflex setup for Claude Code, Codex CLI, opencode, pi and Hermes", h1: "Reflex setup",
   description: "Install Reflex as a Claude Code, Codex CLI or opencode plugin, or with npx; start in shadow mode, verify, switch to enforce, and run it in GitHub Actions.",
   intro: "Install the Reflex hooks, start in shadow mode, verify them in a real session and switch to enforce.",
   related: ["guide/", "faq/", "claude-code-hooks/", "codex-cli-guardrails/"]},
];

// ---------------------------------------------------------------------------------------------
const CSS = `:root{color-scheme:light dark;--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--code:#f3f5f7;--link:#0550ae;--accent:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9da7b3;--line:#30363d;--code:#161b22;--link:#6cb6ff;--accent:#161b22}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
a{color:var(--link)}a:focus-visible,pre:focus-visible,.scroll:focus-visible{outline:2px solid var(--link);outline-offset:2px}
.skip{position:absolute;left:-999px}.skip:focus{left:8px;top:8px;background:var(--bg);padding:4px 8px;z-index:1}
header,main,footer{max-width:52rem;margin:0 auto;padding:0 16px}
header{display:flex;flex-wrap:wrap;gap:4px 16px;align-items:center;padding-top:12px;padding-bottom:12px;border-bottom:1px solid var(--line)}
header .brand{font-weight:700;text-decoration:none;color:var(--fg);margin-right:auto}
header nav ul{display:flex;flex-wrap:wrap;gap:4px 14px;list-style:none;margin:0;padding:0}
main{padding-top:8px;padding-bottom:32px}.lead{font-size:1.1rem;color:var(--muted)}
h1{font-size:1.9rem;line-height:1.25;margin:1.2rem 0 .6rem}h2{margin-top:2rem;padding-bottom:.2rem;border-bottom:1px solid var(--line)}
h1,h2,h3,h4{scroll-margin-top:8px}
code,pre{font:.9em/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code{background:var(--code);padding:.1em .3em;border-radius:4px;overflow-wrap:anywhere}
pre{background:var(--code);padding:12px;border-radius:6px;overflow-x:auto}pre code{padding:0;background:none;overflow-wrap:normal}
.scroll{overflow-x:auto;margin:1rem 0}table{border-collapse:collapse;font-size:.93rem}th,td{border:1px solid var(--line);padding:6px 10px;vertical-align:top;text-align:left}
th{background:var(--accent)}img{max-width:100%;height:auto}blockquote{margin:1rem 0;padding:0 1rem;border-left:4px solid var(--line);color:var(--muted)}
details{margin:1rem 0;border:1px solid var(--line);border-radius:6px;padding:8px 12px}summary{cursor:pointer}
.install{background:var(--accent);border:1px solid var(--line);border-radius:6px;padding:4px 14px;margin:1.2rem 0}
.related{border-top:1px solid var(--line);margin-top:2.5rem}footer{border-top:1px solid var(--line);color:var(--muted);font-size:.9rem;padding-top:12px;padding-bottom:24px}`;

const url = p => SITE + p.path;
const ldApp = {"@context": "https://schema.org", "@type": "SoftwareApplication", name: "Reflex", applicationCategory: "DeveloperApplication",
  operatingSystem: "macOS, Linux, Windows (WSL)", softwareVersion: pkg.version, license: "https://opensource.org/licenses/MIT", url: SITE,
  downloadUrl: "https://www.npmjs.com/package/@ursuciprian/reflex", sameAs: [REPO], author: {"@type": "Person", name: pkg.author},
  offers: {"@type": "Offer", price: "0", priceCurrency: "USD"}, description: pkg.description};
const jsonld = o => `<script type="application/ld+json">${JSON.stringify(o).replace(/</g, "\\u003c")}</script>`;

function render(page) {
  const ctx = {shift: 0, ids: new Map(), headings: []};
  let body;
  if (page.full) {
    const lines = read(page.file).split("\n");
    // the README line that links to this site is left out of the site itself
    body = blocks((page.skipFirst ? lines.slice(1) : lines).filter(l => !l.startsWith("Documentation website: ")), {...ctx, link: linker(page.file, page)});
  } else {
    body = page.sources.map(s => {
      const c = {...ctx, link: linker(s.file ?? s[0], page)};
      if (s.para) return blocks(paragraph(s.file, s.para), c);
      const {lines, level} = section(s[0], s[1]);
      return blocks(lines, {...c, shift: 2 - level});
    }).join("\n");
  }
  const byPath = Object.fromEntries(PAGES.map(p => [p.path, p]));
  const related = (page.related ?? []).map(p => `<li><a href="${BASE}${p}">${esc(byPath[p].h1)}</a></li>`).join("\n");
  const ld = [ldApp];
  if (page.faq) ld.push({"@context": "https://schema.org", "@type": "FAQPage", mainEntity: faqEntries()});
  const nav = PAGES.filter(p => p.nav).map(p => `<li><a href="${BASE}${p.path}"${p === page ? ' aria-current="page"' : ""}>${p.nav}</a></li>`).join("");
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(page.title)}</title>
<meta name="description" content="${esc(page.description)}">
<link rel="canonical" href="${url(page)}">
<link rel="icon" href="${BASE}assets/logo.svg" type="image/svg+xml">
<link rel="stylesheet" href="${BASE}style.css">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Reflex">
<meta property="og:title" content="${esc(page.title)}">
<meta property="og:description" content="${esc(page.description)}">
<meta property="og:url" content="${url(page)}">
<meta property="og:image" content="${SITE}assets/social-preview.png">
<meta property="og:image:width" content="1280">
<meta property="og:image:height" content="640">
<meta property="og:image:alt" content="Reflex, a pre-execution risk gate for AI coding agents">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(page.title)}">
<meta name="twitter:description" content="${esc(page.description)}">
<meta name="twitter:image" content="${SITE}assets/social-preview.png">
${ld.map(jsonld).join("\n")}
</head>
<body>
<a class="skip" href="#content">Skip to content</a>
<header>
<a class="brand" href="${BASE}">Reflex</a>
<nav aria-label="Main"><ul>${nav}<li><a href="${REPO}">GitHub</a></li></ul></nav>
</header>
<main id="content">
<h1>${esc(page.h1)}</h1>
<p class="lead">${esc(page.intro)}</p>
${INSTALL}
${body}
${related ? `<section class="related" aria-labelledby="related"><h2 id="related">Related pages</h2>\n<ul>\n${related}\n</ul></section>` : ""}
</main>
<footer><p>Reflex ${esc(pkg.version)}, MIT licensed. Source and issues on <a href="${REPO}">GitHub</a>; package <a href="https://www.npmjs.com/package/@ursuciprian/reflex">@ursuciprian/reflex</a> on npm. This page is built from the repository docs.</p></footer>
</body>
</html>
`;
}

export function faqEntries() {
  const lines = read("docs/FAQ.md").split("\n"), out = [];
  for (const l of lines) {
    const m = l.match(/^## (.+)$/);
    if (!m) continue;
    const {lines: sec} = section("docs/FAQ.md", m[1]);
    const ctx = {shift: 0, ids: new Map(), headings: [], link: linker("docs/FAQ.md", PAGES.find(p => p.faq))};
    out.push({"@type": "Question", name: text(inline(m[1], ctx)), acceptedAnswer: {"@type": "Answer", text: text(blocks(sec.slice(1), ctx))}});
  }
  return out;
}

export function build(out = join(ROOT, "site/dist")) {
  // only an earlier build (it has a sitemap.xml) or an empty directory is replaced, so --out . cannot delete a checkout
  if (existsSync(out) && readdirSync(out).length && !existsSync(join(out, "sitemap.xml"))) throw new Error(`${out} is not empty and holds no earlier build; refusing to replace it`);
  rmSync(out, {recursive: true, force: true});
  mkdirSync(out, {recursive: true});
  for (const p of PAGES) {
    mkdirSync(join(out, p.path), {recursive: true});
    writeFileSync(join(out, p.path, "index.html"), render(p));
  }
  writeFileSync(join(out, "style.css"), CSS + "\n");
  cpSync(join(ROOT, "assets"), join(out, "assets"), {recursive: true});
  for (const f of ["llms.txt", "llms-full.txt"]) cpSync(join(ROOT, f), join(out, f));
  // crawlers read robots.txt at a host root only: on a project site (/reflex/) it takes effect with a custom domain
  writeFileSync(join(out, "robots.txt"), `User-agent: *\nAllow: /\n\nSitemap: ${SITE}sitemap.xml\n`);
  writeFileSync(join(out, "sitemap.xml"), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
    PAGES.map(p => `  <url><loc>${url(p)}</loc></url>`).join("\n") + "\n</urlset>\n");
  return out;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const i = process.argv.indexOf("--out"), dir = build(i > -1 ? process.argv[i + 1] : undefined);
  console.log(`site: ${PAGES.length} pages in ${dir}`);
}
