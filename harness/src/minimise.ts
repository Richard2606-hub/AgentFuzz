/**
 * Post-shrink minimisation (generator v2+).
 *
 * fast-check's shrinker stops at a local minimum: it often leaves irrelevant pays inside a
 * same-block burst, or steps it never retried after a later shrink. This pass removes whole
 * steps and single pays from bursts (a burst of one becomes a plain pay) until no removal keeps
 * the invariant broken. Deterministic: candidates are tried in a fixed order.
 */
import type { Step } from "./attacks/steps.js";

/** Every sequence that is `steps` with one step removed or one burst pay removed, smallest first. */
export function reductions(steps: Step[]): Step[][] {
  const out: Step[][] = [];
  for (let i = 0; i < steps.length; i++) out.push([...steps.slice(0, i), ...steps.slice(i + 1)]);
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    if (s.k !== "burst") continue;
    for (let j = 0; j < s.pays.length; j++) {
      const pays = [...s.pays.slice(0, j), ...s.pays.slice(j + 1)];
      const replaced: Step = pays.length === 1 ? { k: "pay", ...pays[0] } : { k: "burst", pays };
      out.push([...steps.slice(0, i), replaced, ...steps.slice(i + 1)]);
    }
  }
  return out;
}

/**
 * Greedily apply reductions while `stillFails` holds. Returns the minimised sequence and how many
 * reductions were applied.
 */
export async function minimise(steps: Step[], stillFails: (s: Step[]) => Promise<boolean>, maxEvals = 400): Promise<{ steps: Step[]; applied: number }> {
  let current = steps;
  let applied = 0;
  let evals = 0;
  let progress = true;
  while (progress && evals < maxEvals) {
    progress = false;
    for (const cand of reductions(current)) {
      if (++evals > maxEvals) break;
      if (await stillFails(cand)) {
        current = cand;
        applied++;
        progress = true;
        break;
      }
    }
  }
  return { steps: current, applied };
}
