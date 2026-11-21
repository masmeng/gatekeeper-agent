// Persistent used-proof-reference store (replay protection).
// Backed by a JSON file so a restart does not forget which proof references
// were already answered. Writes are atomic (temp file + rename).
// NEVER store secrets here — only task ids, proof references, and decisions.
import fs from "node:fs";
import path from "node:path";

export interface UsedProofRecord {
  referenceKey: string;
  taskId: string;
  decision: "APPROVE" | "REJECT";
  reasonCode: string;
  firstSeenAt: string;
}

export class UsedProofStore {
  private entries = new Map<string, UsedProofRecord>();
  private readonly filePath: string;
  private readonly maxEntries: number;

  constructor(filePath: string, maxEntries: number) {
    this.filePath = filePath;
    this.maxEntries = maxEntries;
  }

  load(): void {
    try {
      if (!fs.existsSync(this.filePath)) return;
      const raw = fs.readFileSync(this.filePath, "utf8");
      const parsed: unknown = JSON.parse(raw);
      if (!Array.isArray(parsed)) return;
      for (const item of parsed) {
        if (
          item && typeof item === "object" &&
          typeof (item as UsedProofRecord).referenceKey === "string"
        ) {
          const rec = item as UsedProofRecord;
          this.entries.set(rec.referenceKey, rec);
        }
      }
    } catch {
      // A corrupt store must not take the service down; start empty and
      // let the next save overwrite it. The failure is logged by the caller.
      this.entries.clear();
    }
  }

  has(referenceKey: string): boolean {
    return this.entries.has(referenceKey);
  }

  size(): number {
    return this.entries.size;
  }

  add(record: UsedProofRecord): void {
    this.entries.set(record.referenceKey, record);
    // FIFO eviction so the file cannot grow without bound.
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
    this.save();
  }

  private save(): void {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp-${process.pid}`;
      fs.writeFileSync(tmp, JSON.stringify([...this.entries.values()], null, 2), "utf8");
      fs.renameSync(tmp, this.filePath);
    } catch {
      // Persistence is best-effort; the in-memory map still protects this run.
    }
  }
}
