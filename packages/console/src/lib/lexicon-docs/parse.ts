import type {
  LexiconDocsEntry,
  LexiconDocsSection,
  LexiconFieldRow,
  LexiconPrimaryType,
} from "./types";

import { LEXICON_DOCS_SECTIONS } from "./types";

function sectionForNsid(
  nsid: string,
  type: Extract<LexiconPrimaryType, "record" | "defs">,
): LexiconDocsSection {
  if (type === "defs") {
    return "Shared definitions";
  }
  if (nsid.startsWith("dev.cocore.account.")) {
    return "Account records";
  }
  if (nsid.startsWith("dev.cocore.app.")) {
    return "App records";
  }
  return "Compute records";
}

function formatFieldType(prop: unknown): string {
  if (!prop || typeof prop !== "object") {
    return "unknown";
  }
  const schema = prop as Record<string, unknown>;
  if (schema.type === "array" && schema.items) {
    const items = schema.items as Record<string, unknown>;
    if (items.type === "ref") {
      return `${String(items.ref)}[]`;
    }
    if (items.type === "string" && items.format) {
      return `${String(items.format)}[]`;
    }
    return `${String(items.type ?? "unknown")}[]`;
  }
  if (schema.type === "ref") {
    return String(schema.ref);
  }
  if (schema.type === "union") {
    const refs = (schema.refs as Array<string> | undefined) ?? [];
    return refs.length > 0 ? `union(${refs.join(" | ")})` : "union";
  }
  if (schema.format) {
    return `${String(schema.type)} · ${String(schema.format)}`;
  }
  return String(schema.type ?? "unknown");
}

function extractFields(
  schema: { properties?: Record<string, unknown>; required?: Array<string> } | undefined,
): Array<LexiconFieldRow> {
  if (!schema?.properties) {
    return [];
  }
  const required = new Set(schema.required ?? []);
  return Object.entries(schema.properties).map(([name, prop]) => {
    const field = prop as Record<string, unknown>;
    return {
      name,
      type: formatFieldType(prop),
      required: required.has(name),
      description: typeof field.description === "string" ? field.description : undefined,
    };
  });
}

function parseSecondaryDefs(
  id: string,
  defs: Record<string, unknown>,
  json: string,
): LexiconDocsEntry {
  const defNames = Object.keys(defs);
  return {
    id,
    section: "Shared definitions",
    primaryType: "defs",
    description: `${defNames.length} shared schema definitions for AppView responses and unions.`,
    fields: defNames.map((name) => ({
      name,
      type: String((defs[name] as Record<string, unknown>)?.type ?? "unknown"),
      required: false,
    })),
    json,
  };
}

export function parseLexiconDocument(raw: unknown): LexiconDocsEntry | null {
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const doc = raw as { id?: string; defs?: Record<string, unknown> };
  if (!doc.id || !doc.defs) {
    return null;
  }

  const json = JSON.stringify(raw, null, 2);
  const main = doc.defs.main as Record<string, unknown> | undefined;

  if (!main) {
    return parseSecondaryDefs(doc.id, doc.defs, json);
  }

  const type = main.type as LexiconPrimaryType;
  if (type === "query" || type === "procedure") {
    return null;
  }
  if (type !== "record" && type !== "defs") {
    return null;
  }

  let fields: Array<LexiconFieldRow> = [];
  let recordKey: string | undefined;

  if (type === "record") {
    recordKey = typeof main.key === "string" ? main.key : undefined;
    fields = extractFields(
      main.record as {
        properties?: Record<string, unknown>;
        required?: Array<string>;
      },
    );
  }

  return {
    id: doc.id,
    section: sectionForNsid(doc.id, type),
    primaryType: type,
    description: typeof main.description === "string" ? main.description : undefined,
    recordKey,
    fields,
    json,
  };
}

const SECTION_ORDER = new Map(LEXICON_DOCS_SECTIONS.map((section, index) => [section, index]));

export function sortLexiconDocsEntries(entries: Array<LexiconDocsEntry>): Array<LexiconDocsEntry> {
  return entries.toSorted((left, right) => {
    const sectionDelta =
      (SECTION_ORDER.get(left.section) ?? 0) - (SECTION_ORDER.get(right.section) ?? 0);
    if (sectionDelta !== 0) {
      return sectionDelta;
    }
    return left.id.localeCompare(right.id);
  });
}
