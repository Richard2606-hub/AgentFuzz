#!/usr/bin/env node
// Create a NEAR testnet account through the public testnet faucet helper and store its
// credentials in .env (gitignored). Testnet tokens have no value.
//
//   node scripts/create-testnet-account.mjs <name>.testnet
//
// Equivalent near-cli-rs command:
//   near account create-account sponsor-by-faucet-service <name>.testnet autogenerate-new-keypair save-to-keychain network-config testnet create
import { generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const accountId = process.argv[2];
if (!accountId || !/^[a-z0-9_-]{2,48}\.testnet$/.test(accountId)) {
  console.error("usage: node scripts/create-testnet-account.mjs <name>.testnet");
  process.exit(1);
}

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let s = "";
  while (n > 0n) {
    s = ALPHABET[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s;
}

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
const pk = `ed25519:${b58(pub)}`;
const sk = `ed25519:${b58(Buffer.concat([seed, pub]))}`;

const res = await fetch("https://helper.nearprotocol.com/account", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ newAccountId: accountId, newAccountPublicKey: pk }),
});
const text = await res.text();
if (!res.ok) {
  console.error(`faucet helper refused (${res.status}): ${text.slice(0, 300)}`);
  process.exit(1);
}

const envPath = join(root, ".env");
let env = existsSync(envPath) ? readFileSync(envPath, "utf8") : readFileSync(join(root, ".env.example"), "utf8");
const set = (k, v) => {
  const re = new RegExp(`^${k}=.*$`, "m");
  env = re.test(env) ? env.replace(re, `${k}=${v}`) : `${env.trimEnd()}\n${k}=${v}\n`;
};
set("NEAR_ACCOUNT_ID", accountId);
set("NEAR_PRIVATE_KEY", sk);
set("SCOREBOARD_CONTRACT_ID", `scoreboard.${accountId}`);
writeFileSync(envPath, env);
console.log(`created ${accountId} (public key ${pk}); credentials written to .env`);
console.log(`explorer: https://testnet.nearblocks.io/address/${accountId}`);
