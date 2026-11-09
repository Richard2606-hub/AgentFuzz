/** Terminal output helpers (no dependencies; colours disabled when not a TTY or NO_COLOR). */
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const wrap = (code: number) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);

export const c = {
  bold: wrap(1),
  dim: wrap(2),
  red: wrap(31),
  green: wrap(32),
  yellow: wrap(33),
  blue: wrap(34),
  magenta: wrap(35),
  cyan: wrap(36),
};

export function statusBadge(status: string): string {
  switch (status) {
    case "broken":
      return c.red(c.bold("BROKEN"));
    case "held":
      return c.green(c.bold("HELD"));
    case "not-exercised":
      return c.yellow("NOT EXERCISED");
    default:
      return c.dim(status.toUpperCase());
  }
}
