/**
 * pi Bitwarden extension — deliver vault secrets to processes, not to the LLM.
 *
 * Security model
 * ==============
 * - Master password: prompted via Zenity (desktop) or pi TUI input. Lives in
 *   memory only for the duration of one `bw unlock` call, passed via env var
 *   (never argv). The session key (BW_SESSION) stays in this process's memory:
 *   never on disk, never in the bash environment, never in logs or results.
 * - bw_inject: fetches a secret and injects it as an env var into bash tool
 *   child processes (spawnHook). The model never sees the value. A tool_result
 *   scrubber additionally replaces every active secret (and its base64 form)
 *   in ALL tool results before they reach the model (catches `echo $VAR`).
 * - bw_clipboard: copies a secret to the system clipboard, auto-cleared.
 * - bw_reveal (optional, per-call confirmation): returns a secret in plain
 *   text. The value then transits the LLM provider and the session file —
 *   that is inherent, hence every reveal needs explicit approval.
 * - Auto-lock: configurable idle timeout (config.json, default: session-lifetime,
 *   i.e. unlock once per pi session); always on /bw lock, on /new //fork session
 *   switch, and on pi exit. Locking drops the session key and all injected vars.
 * - Audit log: ~/.bw/pi-extension/audit.log (timestamps, item names, env var
 *   names, allow/deny — never secret values).
 * - Config: ~/.bw/pi-extension/config.json (autoLockMinutes, keepOnResume,
 *   clipboardClearSeconds, allowReveal, maxInjectedEnv).
 *
 * Requires: bitwarden CLI (`bw`), logged in (`bw login`).
 * Replaces mcp__bitwarden (removed); browser filling works via agent-browser:
 *   agent-browser fill @ref "$VAR"   (value never enters the conversation)
 */

import { spawn } from "node:child_process";
import { readFileSync, promises as fs } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

// ---------------------------------------------------------------------------
// Configuration (defaults overridable via ~/.bw/pi-extension/config.json)
// ---------------------------------------------------------------------------
const STATE_DIR = path.join(homedir(), ".bw", "pi-extension");
const CONFIG_PATH = path.join(STATE_DIR, "config.json");

const DEFAULTS = {
	/** Idle minutes before the vault session and injected secrets drop.
	 *  0 = unlock lasts for the whole pi session (lock only on /bw lock or exit). */
	autoLockMinutes: 0,
	/** Keep the unlock state when switching sessions with /resume in the same pi process. */
	keepOnResume: true,
	/** Clipboard auto-clear delay. */
	clipboardClearSeconds: 30,
	/** Allow bw_reveal (plain-text secret to the model, per-call confirmation). */
	allowReveal: true,
	/** Upper bound on concurrently injected env vars. */
	maxInjectedEnv: 12,
};

function loadConfig(): typeof DEFAULTS {
	try {
		const raw = JSON.parse(readFileSync(CONFIG_PATH, "utf-8"));
		return { ...DEFAULTS, ...raw };
	} catch {
		return { ...DEFAULTS };
	}
}

const CONFIG = loadConfig();
/** 0 = no idle lock (session-lifetime unlock). */
const autoLockMs = CONFIG.autoLockMinutes > 0 ? CONFIG.autoLockMinutes * 60_000 : 0;
const BW_TIMEOUT_MS = 120_000;

/** Env names the model may never claim (shell/loader injection vectors + Bitwarden internals). */
const ENV_BLOCKLIST =
	/^(PATH|HOME|SHELL|USER|LOGNAME|PWD|OLDPWD|IFS|PS1|PS2|PROMPT_COMMAND|BASH_ENV|ENV|SHELLOPTS|BASHOPTS|LD_.+|DYLD_.+|PYTHONPATH|PYTHONSTARTUP|PERL5OPT|RUBYOPT|NODE_OPTIONS|NODE_PATH|GIT_CONFIG|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_SSH|GIT_SSH_COMMAND|GIT_ASKPASS|SSH_AUTH_SOCK|SSL_CERT_FILE|REQUESTS_CA_BUNDLE|CURL_HOME|CURL_CA_BUNDLE|http_proxy|https_proxy|all_proxy|no_proxy|PI_.+|BW_.+)$/i;

const FIELD_RE = /^(password|totp|notes|field:[\w.\- ]{1,64})$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const BW_LOGIN_HINT =
	"Bitwarden CLI is not logged in. Run `bw login` in a terminal first " +
	"(and `bw config --server <url>` if self-hosted), then retry. " +
	"You can check with /bw status.";

// ---------------------------------------------------------------------------
// State (memory only)
// ---------------------------------------------------------------------------
let sessionKey: string | undefined;
let lastActivity = 0;
let lockTimer: NodeJS.Timeout | undefined;
let unlockInFlight: Promise<string> | undefined;
let itemsCache: { at: number; items: any[] } | undefined;

/** Injected secrets: ENV -> { value, item, field, at }. Values never reach the model. */
const injected = new Map<string, { value: string; item: string; field: string; at: number }>();

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function hasDisplay(): boolean {
	return !!(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);
}

function safeStatus(ctx: ExtensionContext | undefined, text: string | undefined): void {
	try {
		ctx?.ui.setStatus("bitwarden", text);
	} catch {
		/* runner may be inactive */
	}
}

function tail(s: string, n = 200): string {
	const t = s.trim();
	if (!t) return "";
	return t.length > n ? t.slice(-n) : t;
}

function exec(
	cmd: string,
	args: string[],
	opts: { env?: Record<string, string>; timeout?: number; input?: string } = {},
): Promise<{ stdout: string; stderr: string; code: number }> {
	return new Promise((resolve, reject) => {
		const child = spawn(cmd, args, {
			env: opts.env ? { ...process.env, ...opts.env } : process.env,
			stdio: ["pipe", "pipe", "pipe"],
		});
		let out = "";
		let err = "";
		let settled = false;
		const timer = setTimeout(() => {
			if (settled) return;
			settled = true;
			child.kill("SIGKILL");
			reject(new Error(`${cmd} timed out after ${opts.timeout ?? BW_TIMEOUT_MS}ms`));
		}, opts.timeout ?? BW_TIMEOUT_MS);
		child.stdout?.on("data", (d) => (out += d));
		child.stderr?.on("data", (d) => (err += d));
		child.on("error", (e) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			reject(e);
		});
		child.on("close", (code) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve({ stdout: out, stderr: err, code: code ?? -1 });
		});
		if (opts.input !== undefined) child.stdin?.write(opts.input);
		child.stdin?.end();
	});
}

async function audit(event: string, detail: string): Promise<void> {
	try {
		await fs.mkdir(STATE_DIR, { recursive: true });
		const line = `${new Date().toISOString()} ${event} ${detail}\n`;
		await fs.appendFile(path.join(STATE_DIR, "audit.log"), line);
	} catch {
		/* best-effort */
	}
}

// ---------------------------------------------------------------------------
// Bitwarden CLI plumbing (secrets only ever travel via env vars / pipes)
// ---------------------------------------------------------------------------
let bwBin: string | undefined;

async function resolveBw(): Promise<string> {
	if (bwBin) return bwBin;
	try {
		await exec("bw", ["--version"], { timeout: 20_000 });
		bwBin = "bw";
		return bwBin;
	} catch {
		/* fall through to nvm scan */
	}
	try {
		const nvmDir = path.join(homedir(), ".nvm", "versions", "node");
		const versions = (await fs.readdir(nvmDir).catch(() => [] as string[]))
			.filter((v) => /^\d+\.\d+\.\d+$/.test(v))
			.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
			.reverse();
		for (const v of versions) {
			const p = path.join(nvmDir, v, "bin", "bw");
			if (await fs.access(p).then(() => true, () => false)) {
				bwBin = p;
				return bwBin;
			}
		}
	} catch {
		/* ignore */
	}
	throw new Error("Bitwarden CLI (`bw`) not found in PATH or ~/.nvm. Install it, `bw login`, and retry.");
}

async function runBw(
	args: string[],
	opts: { session?: string; extraEnv?: Record<string, string> } = {},
): Promise<string> {
	const bin = await resolveBw();
	const env: Record<string, string> = { ...opts.extraEnv };
	if (opts.session) env.BW_SESSION = opts.session;
	const r = await exec(bin, [...args, "--nointeraction"], { env });
	if (r.code !== 0) {
		const hint = tail(r.stderr) || `exit ${r.code}`;
		// Never include stdout in errors — some commands print secrets on success-ish paths.
		throw new Error(`bw ${args.slice(0, 2).join(" ")} failed: ${hint}`);
	}
	return r.stdout;
}

async function runBwJson(args: string[], session?: string): Promise<any> {
	return JSON.parse(await runBw(args, { session }));
}

let statusCache: { at: number; json: any } | undefined;

async function bwStatus(session?: string): Promise<any> {
	// `bw status` with a stale BW_SESSION exits non-zero; strip env session for the probe.
	if (session) {
		const r = await runBw(["status"], { session });
		return JSON.parse(r);
	}
	if (statusCache && Date.now() - statusCache.at < 3000) return statusCache.json;
	const json = await runBwJson(["status"]);
	statusCache = { at: Date.now(), json };
	return json;
}

async function askMasterPassword(ctx: ExtensionContext | undefined, reason: string): Promise<string> {
	if (hasDisplay()) {
		try {
			const r = await exec(
				"zenity",
				["--password", `--title=pi · Bitwarden master password — ${reason}`],
				{ timeout: 10 * 60_000 },
			);
			if (r.code !== 0) throw new Error("cancelled");
			const pw = r.stdout.replace(/[\r\n]+$/, "");
			if (!pw) throw new Error("cancelled");
			return pw;
		} catch (e: any) {
			if (e?.message === "cancelled") throw new Error("Master password prompt cancelled.");
			// zenity missing/broken → fall through to TUI input
		}
	}
	if (ctx?.hasUI) {
		const pw = await ctx.ui.input(
			"Bitwarden master password (visible input — desktop prompt unavailable)",
			reason,
		);
		if (!pw) throw new Error("Master password prompt cancelled.");
		return pw;
	}
	throw new Error(
		"No way to prompt for the master password (no TUI, no desktop). Run /bw unlock in an interactive pi session.",
	);
}

async function confirmAction(
	ctx: ExtensionContext | undefined,
	title: string,
	message: string,
): Promise<boolean> {
	if (ctx?.hasUI) {
		const ok = await ctx.ui.confirm(title, message);
		return ok === true;
	}
	if (hasDisplay()) {
		try {
			const r = await exec("zenity", ["--question", `--title=${title}`, "--text", message], {
				timeout: 10 * 60_000,
			});
			if (process.env.BW_MOCK_DIR) {
				try { await fs.appendFile(`${process.env.BW_MOCK_DIR}/confirm.log`, `zenity code=${r.code} stderr=${tail(r.stderr, 40)}\n`); } catch {}
			}
			return r.code === 0;
		} catch {
			return false;
		}
	}
	return false;
}

function startAutoLock(): void {
	lastActivity = Date.now();
	if (lockTimer || !autoLockMs) return;
	lockTimer = setInterval(() => {
		if (sessionKey && autoLockMs && Date.now() - lastActivity > autoLockMs) {
			void lock("auto-idle");
		}
	}, 30_000);
	lockTimer.unref?.();
}

async function lock(reason: string): Promise<void> {
	const hadSession = !!sessionKey;
	sessionKey = undefined;
	itemsCache = undefined;
	injected.clear();
	if (lockTimer) {
		clearInterval(lockTimer);
		lockTimer = undefined;
	}
	if (hadSession) {
		await audit("lock", `reason=${reason}`);
		try {
			const bin = await resolveBw();
			await exec(bin, ["lock", "--nointeraction"], { timeout: 15_000 });
		} catch {
			/* best-effort; dropping our session key is what matters */
		}
	}
}

function touchActivity(): void {
	lastActivity = Date.now();
}

async function ensureUnlocked(ctx: ExtensionContext | undefined): Promise<string> {
	touchActivity();
	if (sessionKey) {
		try {
			const st = await bwStatus(sessionKey);
			if (st?.status === "unlocked") return sessionKey;
		} catch {
			/* stale session key */
		}
		sessionKey = undefined;
	}
	if (unlockInFlight) return unlockInFlight;

	unlockInFlight = (async () => {
		const st = await bwStatus(); // no session env
		if (st?.status === "unauthenticated") throw new Error(BW_LOGIN_HINT);

		const pw = await askMasterPassword(ctx, "unlock vault");
		const bin = await resolveBw();
		const r = await exec(bin, ["unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"], {
			env: { BW_MASTER_PASSWORD: pw },
			timeout: 60_000,
		});
		if (r.code !== 0) {
			await audit("unlock", "deny=bad-password");
			throw new Error(`Unlock failed (wrong master password or CLI error). ${tail(r.stderr, 120)}`);
		}
		const key = r.stdout.replace(/[\r\n]+$/, "");
		if (!key) throw new Error("Unlock failed: empty session key.");
		const verify = await bwStatus(key);
		if (verify?.status !== "unlocked") throw new Error("Unlock failed: session key not accepted.");
		sessionKey = key;
		startAutoLock();
		await audit("unlock", "ok");
		try {
			await runBw(["sync"], { session: key }); // fresh data, same policy as bw-mcp
		} catch {
			/* offline ok — cached vault */
		}
		return key;
	})().finally(() => {
		unlockInFlight = undefined;
	});
	return unlockInFlight;
}

async function listItems(session: string): Promise<any[]> {
	if (itemsCache && Date.now() - itemsCache.at < 5 * 60_000) return itemsCache.items;
	const items = await runBwJson(["list", "items"], session);
	itemsCache = { at: Date.now(), items };
	return items;
}

async function resolveItem(session: string, ref: string): Promise<any> {
	if (UUID_RE.test(ref)) {
		try {
			return await runBwJson(["get", "item", ref], session);
		} catch {
			throw new Error(`No Bitwarden item with id ${ref}.`);
		}
	}
	const items = await listItems(session);
	const lower = ref.toLowerCase();
	let hits = items.filter((i: any) => (i?.name ?? "").toLowerCase() === lower);
	if (hits.length !== 1) hits = items.filter((i: any) => (i?.name ?? "").toLowerCase().includes(lower));
	if (hits.length === 1) return hits[0];
	const candidates = hits.length > 1 ? hits : items.slice(0, 20);
	const list = candidates
		.slice(0, 10)
		.map((i: any) => `- ${i?.name ?? "?"} | user: ${i?.login?.username ?? "-"} | id: ${i?.id}`)
		.join("\n");
	throw new Error(
		hits.length > 1
			? `Multiple Bitwarden items match "${ref}". Specify by id:\n${list}`
			: `No Bitwarden item matches "${ref}". Closest items:\n${list}`,
	);
}

function extractSecret(item: any, field: string): string {
	let v: string | undefined;
	if (field === "password") v = item?.login?.password;
	else if (field === "totp") v = item?.login?.totp; // TOTP seed, not the rotating code
	else if (field === "notes") v = item?.notes;
	else if (field.startsWith("field:")) {
		const name = field.slice(6);
		const f = (item?.fields ?? []).find((f: any) => f?.name === name);
		v = f?.value;
	}
	if (typeof v !== "string" || v.length === 0) {
		throw new Error(`Field "${field}" is empty or missing on item "${item?.name ?? "?"}".`);
	}
	return v;
}

async function fetchSecret(
	ctx: ExtensionContext | undefined,
	itemRef: string,
	field: string,
): Promise<{ value: string; itemId: string; itemName: string }> {
	const session = await ensureUnlocked(ctx);
	const item = await resolveItem(session, itemRef);
	return {
		value: extractSecret(item, field),
		itemId: item?.id ?? "?",
		itemName: item?.name ?? "?",
	};
}

function normalizeEnvName(raw: string): string {
	const name = raw.trim().toUpperCase();
	if (!/^[A-Z_][A-Z0-9_]*$/.test(name)) {
		throw new Error(`Invalid env var name "${raw}". Use letters, digits, underscores; must not start with a digit.`);
	}
	if (ENV_BLOCKLIST.test(name)) {
		throw new Error(`Env var name "${name}" is blocked (shell/loader/Bitwarden internals). Pick a specific name like MYAPP_TOKEN.`);
	}
	return name;
}

function injectedListText(): string {
	if (injected.size === 0) return "(none)";
	return [...injected.entries()].map(([env, r]) => `$${env} ← "${r.item}" (${r.field})`).join(", ");
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------
async function copyToClipboard(value: string): Promise<void> {
	// wl-copy/xclip stay alive to own the selection, so we must NOT wait for exit.
	const copy = (cmd: string, args: string[]) =>
		new Promise<void>((resolve, reject) => {
			const child = spawn(cmd, args, { stdio: ["pipe", "ignore", "ignore"], detached: true });
			let settled = false;
			child.on("error", (e) => {
				if (!settled) {
					settled = true;
					reject(e);
				}
			});
			child.stdin?.on("error", () => {}); // EPIPE if the child dies early
			child.stdin?.write(value, (err) => {
				if (err) {
					if (!settled) {
						settled = true;
						reject(err);
					}
					return;
				}
				child.stdin?.end();
				setTimeout(() => {
					if (!settled) {
						settled = true;
						child.unref();
						resolve();
					}
				}, 500);
			});
		});
	if (process.env.WAYLAND_DISPLAY) return copy("wl-copy", []);
	if (process.env.DISPLAY) return copy("xclip", ["-selection", "clipboard"]);
	throw new Error("No clipboard available (need Wayland or X11).");
}

async function clearClipboard(): Promise<void> {
	try {
		if (process.env.WAYLAND_DISPLAY) await exec("wl-copy", ["-c"], { timeout: 5000 });
		else if (process.env.DISPLAY) await exec("xclip", ["-selection", "clipboard", "/dev/null"], { timeout: 5000, input: "" });
	} catch {
		/* best-effort */
	}
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------
export default function (pi: ExtensionAPI) {
	// --- Override the bash tool: inject active secrets into child env only ---
	const bashTool = createBashTool(process.cwd(), {
		spawnHook: ({ command, cwd, env }) => {
			if (injected.size > 0) {
				for (const [name, rec] of injected) env[name] = rec.value;
			}
			return { command, cwd, env };
		},
	});
	pi.registerTool({ ...bashTool } as any);

	// --- bw_list: vault map without secrets ---
	pi.registerTool({
		name: "bw_list",
		label: "Bitwarden list",
		description:
			"List Bitwarden vault items: name, username, URI, id, folder. NEVER returns passwords, TOTP, notes or field values. " +
			"First use in a session prompts for the master password (unlock). Use it to find item names/ids before bw_inject.",
		promptSnippet: "List Bitwarden items (no secrets)",
		promptGuidelines: [
			"Use bw_list to find Bitwarden item names/ids, then bw_inject to pass a credential to a bash command.",
		],
		parameters: Type.Object({
			search: Type.Optional(Type.String({ description: "Optional substring filter on item name" })),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const session = await ensureUnlocked(ctx);
			let items = await listItems(session);
			if (params.search) {
				const q = params.search.toLowerCase();
				items = items.filter((i: any) => (i?.name ?? "").toLowerCase().includes(q));
			}
			const lines = items.slice(0, 60).map(
				(i: any) =>
					`${i?.name ?? "?"} | user: ${i?.login?.username ?? "-"} | uri: ${i?.login?.uris?.[0]?.uri ?? "-"} | id: ${i?.id}`,
			);
			const text =
				`${items.length} item(s)${params.search ? ` matching "${params.search}"` : ""}:\n` +
				lines.join("\n") +
				(items.length > 60 ? `\n... and ${items.length - 60} more (use search)` : "");
			return { content: [{ type: "text", text }], details: { count: items.length } };
		},
	});

	// --- bw_inject: secret -> bash env, model never sees the value ---
	pi.registerTool({
		name: "bw_inject",
		label: "Bitwarden inject",
		description:
			"Fetch a Bitwarden secret and inject it as an environment variable into bash tool commands. " +
			"The VALUE IS NEVER SHOWN to you nor stored in the conversation; reference it as $VAR in later bash commands. " +
			"Requires user confirmation per injection. Use when a command needs a credential (API token, docker login, git push, ...). " +
			"Browser filling: agent-browser fill @ref \"$VAR\" types it into a form without the value entering the conversation. " +
			"Prefer this over bw_reveal. field: 'password' (default) | 'totp' (seed) | 'notes' | 'field:<customFieldName>'.",
		promptSnippet: "Pass a Bitwarden secret to bash via env var (value hidden from model)",
		promptGuidelines: [
			"Use bw_inject when a bash command needs a Bitwarden credential; never ask the user to paste secrets into chat.",
			"To fill a browser login with agent-browser: bw_inject the secret, then run agent-browser fill @ref \"$VAR\" — the value stays out of the conversation.",
			"For repeated browser logins, import once with: printenv $VAR | agent-browser auth save <name> --username <user> --password-stdin — afterwards agent-browser auth login <name> needs no secret.",
		],
		parameters: Type.Object({
			item: Type.String({ description: "Item name or id (see bw_list)" }),
			field: Type.Optional(
				Type.String({
					description: "password | totp | notes | field:<customFieldName> (default: password)",
				}),
			),
			env: Type.String({ description: "Env var name for bash commands, e.g. MYAPP_TOKEN" }),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const field = (params.field ?? "password").trim();
			if (!FIELD_RE.test(field)) {
				throw new Error(`Invalid field "${field}". Use password | totp | notes | field:<name>.`);
			}
			const envName = normalizeEnvName(params.env);
			if (!injected.has(envName) && injected.size >= CONFIG.maxInjectedEnv) {
				throw new Error(`Too many injected vars (max ${CONFIG.maxInjectedEnv}). Run /bw clear to drop some.`);
			}

			const replaced = injected.get(envName);
			const ok = await confirmAction(
				ctx,
				"Bitwarden: inject secret into AI bash environment",
				`Item:   ${params.item}\nField:  ${field}\nEnv:    $${envName}` +
					(replaced ? `\n\nReplaces current injection: "${replaced.item}" (${replaced.field})` : "") +
					`\n\nCommands run by the AI in this pi session will see $${envName}.` +
					`\nThe value itself is never shown to the AI nor stored in the chat.` +
					`\nDropped on ` +
					(autoLockMs ? `idle lock (${Math.round(autoLockMs / 60000)} min) or /bw lock` : `/bw lock or session end`) +
					`.` +
					`\n\nAllow?`,
			);
			if (!ok) {
				await audit("inject", `deny env=${envName} item="${params.item}" field=${field}`);
				throw new Error("User declined the injection.");
			}

			const { value, itemId, itemName } = await fetchSecret(ctx, params.item, field);
			injected.set(envName, { value, item: itemName, field, at: Date.now() });
			await audit("inject", `allow env=${envName} item="${itemName}" (${itemId}) field=${field}`);
			safeStatus(ctx, `🔓 bw: ${injected.size} env var(s)`);

			return {
				content: [
					{
						type: "text",
						text:
							`Injected $${envName} (item "${itemName}", field ${field}) into the bash environment. ` +
							`Use $${envName} in bash commands. Do NOT try to print, echo, or exfiltrate it — output is scrubbed. ` +
							`Active injected vars: ${injectedListText()}`,
					},
				],
				details: { env: envName, item: itemName, field },
			};
		},
	});

	// --- bw_clipboard: secret -> clipboard, auto-cleared ---
	pi.registerTool({
		name: "bw_clipboard",
		label: "Bitwarden clipboard",
		description:
			"Copy a Bitwarden secret to the system clipboard; auto-cleared after " +
			CONFIG.clipboardClearSeconds +
			"s. The value never enters the conversation. Requires user confirmation. " +
			"field: 'password' (default) | 'totp' (seed) | 'notes' | 'field:<customFieldName>'.",
		promptSnippet: "Copy a Bitwarden secret to clipboard (auto-clear)",
		parameters: Type.Object({
			item: Type.String({ description: "Item name or id (see bw_list)" }),
			field: Type.Optional(
				Type.String({ description: "password | totp | notes | field:<name> (default: password)" }),
			),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			const field = (params.field ?? "password").trim();
			if (!FIELD_RE.test(field)) throw new Error(`Invalid field "${field}".`);
			const ok = await confirmAction(
				ctx,
				"Bitwarden: copy secret to clipboard",
				`Item:   ${params.item}\nField:  ${field}\n\nThe value is copied to the system clipboard and cleared after ${CONFIG.clipboardClearSeconds}s. It never enters the chat.\n\nAllow?`,
			);
			if (!ok) {
				await audit("clipboard", `deny item="${params.item}" field=${field}`);
				throw new Error("User declined.");
			}
			const { value, itemName } = await fetchSecret(ctx, params.item, field);
			await copyToClipboard(value);
			await audit("clipboard", `allow item="${itemName}" field=${field}`);
			const t = setTimeout(() => void clearClipboard(), CONFIG.clipboardClearSeconds * 1000);
			t.unref?.();
			return {
				content: [{ type: "text", text: `Copied "${itemName}" (${field}) to clipboard. Clears in ${CONFIG.clipboardClearSeconds}s.` }],
				details: { item: itemName, field },
			};
		},
	});

	// --- bw_reveal: plain text to the model, per-call confirmation ---
	pi.registerTool({
		name: "bw_reveal",
		label: "Bitwarden reveal (danger)",
		description:
			"Return a Bitwarden secret in PLAIN TEXT. DANGEROUS: the value will be sent to the LLM provider and stored in the session file. " +
			"Requires explicit user confirmation every single call. Only use when bw_inject / bw_clipboard genuinely cannot do the job. " +
			"field: 'password' (default) | 'totp' (seed) | 'notes' | 'field:<customFieldName>'.",
		promptSnippet: "Reveal a Bitwarden secret in plain text (per-call approval)",
		promptGuidelines: [
			"Use bw_reveal only as a last resort; prefer bw_inject (bash env) or bw_clipboard which keep the value out of the conversation.",
		],
		parameters: Type.Object({
			item: Type.String({ description: "Item name or id (see bw_list)" }),
			field: Type.Optional(
				Type.String({ description: "password | totp | notes | field:<name> (default: password)" }),
			),
			reason: Type.String({ description: "Why the plain-text value is needed (shown to the user)" }),
		}),
		async execute(_id, params, _signal, _onUpdate, ctx) {
			if (!CONFIG.allowReveal) throw new Error("bw_reveal is disabled in this installation (CONFIG.allowReveal).");
			const field = (params.field ?? "password").trim();
			if (!FIELD_RE.test(field)) throw new Error(`Invalid field "${field}".`);
			const provider = ctx?.model?.provider ?? "the LLM provider";
			const ok = await confirmAction(
				ctx,
				"⚠️ Bitwarden: reveal secret IN PLAIN TEXT",
				`Item:   ${params.item}\nField:  ${field}\nReason: ${params.reason}\n\n` +
					`The value will be shown to the AI, sent to ${provider}, and stored in the pi session file.\n` +
					`bw_inject (env var) or bw_clipboard usually suffice.\n\nAllow?`,
			);
			if (!ok) {
				await audit("reveal", `deny item="${params.item}" field=${field}`);
				throw new Error("User declined the reveal.");
			}
			const { value, itemName } = await fetchSecret(ctx, params.item, field);
			await audit("reveal", `allow item="${itemName}" field=${field}`);
			return {
				content: [{ type: "text", text: `${itemName} (${field}):\n<secret>${value}</secret>` }],
				details: { item: itemName, field },
			};
		},
	});

	// --- Scrubber: active secrets never reach the model via tool results ---
	pi.on("tool_result", async (event) => {
		if (event.toolName === "bw_reveal") return undefined; // intentional
		if (injected.size === 0) return undefined;
		let changed = false;
		const content = event.content.map((block: any) => {
			if (block?.type !== "text" || typeof block.text !== "string") return block;
			let text = block.text;
			for (const [envName, rec] of injected) {
				const v = rec.value;
				if (v.length >= 6 && text.includes(v)) {
					text = text.split(v).join(`[BW_SCRUBBED:${envName}]`);
					changed = true;
				}
				const b64 = v.length >= 16 ? Buffer.from(v, "utf-8").toString("base64") : "";
				if (b64 && text.includes(b64)) {
					text = text.split(b64).join(`[BW_SCRUBBED-B64:${envName}]`);
					changed = true;
				}
			}
			return changed ? { ...block, text } : block;
		});
		// Replacing content drops structuredContent (fine — it may hold raw output).
		return changed ? { content } : undefined;
	});

	// --- /bw command ---
	pi.registerCommand("bw", {
		description: "Bitwarden: status | unlock | lock | clear",
		handler: async (args: string, ctx) => {
			const sub = (args ?? "status").trim().split(/\s+/)[0] || "status";
			if (sub === "lock") {
				await lock("user");
				safeStatus(ctx, undefined);
				ctx.ui.notify("Bitwarden: locked (session key + injected env dropped)", "info");
				return;
			}
			if (sub === "clear") {
				injected.clear();
				safeStatus(ctx, sessionKey ? `🔓 bw: 0 env var(s)` : undefined);
				ctx.ui.notify("Bitwarden: injected env vars cleared", "info");
				return;
			}
			if (sub === "unlock") {
				try {
					await ensureUnlocked(ctx);
					safeStatus(ctx, "🔓 bw: 0 env var(s)");
					ctx.ui.notify("Bitwarden: unlocked", "info");
				} catch (e: any) {
					ctx.ui.notify(`Bitwarden unlock failed: ${e?.message ?? e}`, "error");
				}
				return;
			}
			// status
			let cli = "unknown";
			try {
				const st = await bwStatus();
				cli = st?.status ?? "unknown";
			} catch (e: any) {
				cli = `error: ${tail(e?.message ?? String(e), 80)}`;
			}
			const ttl = sessionKey && autoLockMs ? Math.max(0, Math.round((autoLockMs - (Date.now() - lastActivity)) / 60000)) : 0;
			ctx.ui.notify(
				`bw CLI: ${cli}\n` +
					`extension: ${sessionKey ? (autoLockMs ? `unlocked (auto-lock in ${ttl} min)` : "unlocked (session-lifetime)") : "locked"}\n` +
					`injected env: ${injectedListText()}\n` +
					`bw_reveal: ${CONFIG.allowReveal ? "enabled" : "disabled"}`,
				"info",
			);
		},
	});

	// --- Lifecycle ---
	pi.on("session_start", async (event, ctx) => {
		if (event.reason === "startup" || event.reason === "reload") return;
		if (event.reason === "resume" && CONFIG.keepOnResume) return; // same process: keep unlock
		// /new //fork: don't inherit secrets into a fresh session
		await lock(`session-${event.reason}`);
		safeStatus(ctx, undefined);
	});

	pi.on("session_shutdown", async (event) => {
		if (event.reason === "resume" && CONFIG.keepOnResume) return; // same process: keep unlock
		await lock(`session-${event.reason}`);
	});
}
