#!/usr/bin/env node
// Launcher: run the TypeScript CLI through tsx without a build step.
import { register } from "tsx/esm/api";

register();
await import("../src/cli.ts");
