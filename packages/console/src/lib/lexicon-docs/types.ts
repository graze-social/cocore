export type LexiconPrimaryType = "query" | "procedure" | "record" | "defs";

export type LexiconFieldRow = {
  name: string;
  type: string;
  required: boolean;
  description?: string;
};

export type LexiconDocsEntry = {
  id: string;
  section: LexiconDocsSection;
  primaryType: LexiconPrimaryType;
  description?: string;
  recordKey?: string;
  fields: Array<LexiconFieldRow>;
  json: string;
};

export const LEXICON_DOCS_SECTIONS = [
  "Shared definitions",
  "Compute records",
  "Account records",
  "App records",
] as const;

export type LexiconDocsSection = (typeof LEXICON_DOCS_SECTIONS)[number];

/** Repo records + shared defs only — XRPC query/procedure schemas live on /docs/api. */
export function isLexiconDocsListedEntry(entry: Pick<LexiconDocsEntry, "primaryType">): boolean {
  return entry.primaryType === "record" || entry.primaryType === "defs";
}

export type LexiconDocsPageData = {
  entries: Array<LexiconDocsEntry>;
};
