/**
 * The account scan in everyday words, for people who just want to know "is my wallet safe?".
 * Turns a ScanResult into a traffic light, a one-line headline and a few plain sentences, each
 * saying what it means for the money and what to do. No jargon: no "full-access key", "INV-3" or
 * "allowance". Pure; tested against the real findings the scan produces.
 */
import { fmtNear } from "../near/keys.js";
import type { Finding, ScanResult } from "./scan.js";

export type Light = "green" | "yellow" | "red" | "missing";

export interface Everyday {
  light: Light;
  headline: string;
  /** Plain sentences, most important first. */
  points: string[];
  /** Balance in NEAR, when the account exists. */
  balance?: string;
  /** Always shown: what this check cannot see. */
  limits: string;
}

export const EVERYDAY_LIMITS =
  "This check reads public blockchain data only. It cannot see your seed phrase or tell if someone stole it: never share it with anyone. No real app, wallet or support person will ask for it.";

const short = (pk: string) => (pk.length > 22 ? `${pk.slice(0, 14)}…${pk.slice(-4)}` : pk);

/** One finding in everyday words, or undefined when it is not worth a regular user's attention. */
function plain(f: Finding): string | undefined {
  let m: RegExpExecArray | null;
  if ((m = /^Looks like (\S+) \((.+)\), but is a different account/.exec(f.title)))
    return `This name imitates ${m[1]} (${m[2]}), but it is a different account. If someone asked you to send money here, it is very likely a scam.`;
  if ((m = /^Starts like (\S+), but it is not/.exec(f.title))) {
    const owner = /sub-account of (\S+?):/.exec(f.detail)?.[1];
    return `This is not ${m[1]}${owner ? `: it belongs to whoever owns ${owner}` : ""}. The name is made to look like ${m[1]}. Do not send money here unless you are sure.`;
  }
  if ((m = /^(\d+) full-access keys/.exec(f.title)))
    return `${m[1]} different keys can each take all the money in this account. If you do not recognise every one of them, remove the extra ones in your wallet's security settings, or move your money to a new account.`;
  if (/^Runs a contract but still has a full-access key/.test(f.title))
    return "This account runs a program that is supposed to protect the money, but someone with a key can still override it and take everything.";
  if (/^No full-access key and no contract/.test(f.title)) return "No key can move the money in this account. If this is your wallet, you may have lost access to it.";
  if (/can call (admin methods|any method of this account's contract)/.test(f.title))
    return "An app or AI-agent key on this account can change who controls the account, not just make payments. That key should only be able to pay.";
  if ((m = /^App key for a look-alike account: (\S+)/.exec(f.title)))
    return `You connected this account to ${m[1]}, a fake copy of a well-known app. Remove that app's access in your wallet now, and do not approve anything it asks.`;
  if ((m = /^(\d+) app keys? with unlimited gas allowance/.exec(f.title)))
    return `${m[1] === "1" ? "A connected app" : `${m[1]} connected apps`} can keep spending your NEAR on network fees without asking. ${m[1] === "1" ? "It cannot" : "They cannot"} send your money away, but remove the apps you no longer use in your wallet's connected-apps settings.`;
  if ((m = /^(\d+) app sign-in keys/.exec(f.title))) return `This account is connected to ${m[1]} apps. Removing the ones you no longer use makes it safer.`;
  if (/^Audited wallet guard: \d+\/\d+ safety invariants broken/.test(f.title))
    return "This account runs wallet-protection code that failed AgentFuzz's safety tests. Do not trust it with money.";
  if (/^Audited wallet guard, not fully exercised/.test(f.title)) return "This account's wallet-protection code was only partly tested.";
  if (/^Does not exist on/.test(f.title)) return undefined; // handled by the headline
  if (f.severity === "danger" || f.severity === "warn") return f.title;
  return undefined;
}

export function everydaySummary(r: ScanResult): Everyday {
  const balance = r.balance ? fmtNear(BigInt(r.balance.total)) : undefined;
  const problems = r.findings.filter((f) => f.severity === "danger" || f.severity === "warn");
  const points = [...new Set(r.findings.map(plain).filter((p): p is string => !!p))];

  if (!r.exists) {
    const scam = r.findings.some((f) => f.severity === "danger");
    return {
      light: scam ? "red" : "missing",
      headline: scam ? "Warning: this name looks like a scam" : `We could not find ${r.accountId} on ${r.network}`,
      points: [...points, `There is no account called ${r.accountId} on NEAR ${r.network}. Check the spelling. Mainnet names usually end in .near, testnet names in .testnet.`],
      limits: EVERYDAY_LIMITS,
    };
  }

  const light: Light = r.verdict === "danger" ? "red" : r.verdict === "warn" ? "yellow" : "green";
  const full = r.keys.filter((k) => k.kind === "full-access");
  const reassurance: string[] = [];
  const known = r.findings.find((f) => f.title.startsWith("Known account: "));
  if (known) reassurance.push(`This is the real ${known.title.slice("Known account: ".length)} account.`);
  // A look-alike name is someone else's account (likely a scammer's): no "only you control it".
  const impostor = r.findings.some((f) => f.area === "name" && f.severity === "danger");
  if (full.length === 1 && !r.codeHash && !impostor)
    reassurance.push(`Only one key can move the money: ${short(full[0].publicKey)}. Check that it matches the key shown in your wallet's security settings. If it does, only you control this account.`);
  if (full.length === 0 && r.codeHash && light !== "red") reassurance.push("No key can take the money: only the account's own program can move it.");
  if (r.audit && r.audit.broken === 0 && r.audit.held === r.audit.total) reassurance.push("Its wallet-protection code passed all of AgentFuzz's safety tests.");
  const apps = r.keys.filter((k) => k.kind === "function-call").length;
  if (light === "green" && apps) reassurance.push(`It is connected to ${apps} app${apps > 1 ? "s" : ""}. Apps can call their own contract for you but cannot send your NEAR away.`);

  const headline =
    light === "red"
      ? "Warning: problems found"
      : light === "yellow"
        ? `${problems.length === 1 ? "One thing" : `${problems.length} things`} to check`
        : "No problems found";
  return { light, headline, points: light === "green" ? reassurance : [...points, ...reassurance], balance, limits: EVERYDAY_LIMITS };
}
