import { gzipSync } from "node:zlib";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const limit = 250 * 1024;
const dist = join(process.cwd(), "dist");

function collect(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      out.push(...collect(p));
      continue;
    }
    if (/\.(html|js|css)$/i.test(name)) {
      out.push(p);
    }
  }
  return out;
}

const files = collect(dist);
if (files.length === 0) {
  console.error("size-gate: no html/js/css in dist");
  process.exit(1);
}
let total = 0;
for (const f of files) {
  total += gzipSync(readFileSync(f)).length;
}
console.log(`web gzip html+js+css = ${total} bytes (limit ${limit})`);
if (total > limit) {
  process.exit(1);
}
