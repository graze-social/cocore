import { describe, expect, it } from "vitest";

import { compareVersions, meetsMinVersion } from "./version.ts";

describe("compareVersions", () => {
  it("orders by numeric component", () => {
    expect(compareVersions("0.9.31", "0.9.32")).toBe(-1);
    expect(compareVersions("0.9.32", "0.9.31")).toBe(1);
    expect(compareVersions("0.10.0", "0.9.99")).toBe(1);
    expect(compareVersions("1.0.0", "0.9.99")).toBe(1);
  });

  it("treats missing trailing components as 0", () => {
    expect(compareVersions("0.9", "0.9.0")).toBe(0);
    expect(compareVersions("0.9.1", "0.9")).toBe(1);
  });

  it("tolerates a leading v and pre-release/build suffix", () => {
    expect(compareVersions("v0.9.32", "0.9.32")).toBe(0);
    expect(compareVersions("0.9.32-rc.1", "0.9.32")).toBe(0);
    expect(compareVersions("0.9.32+abc", "0.9.32")).toBe(0);
  });
});

describe("meetsMinVersion", () => {
  it("is fail-closed on a missing version", () => {
    expect(meetsMinVersion(undefined, "0.9.32")).toBe(false);
    expect(meetsMinVersion(null, "0.9.32")).toBe(false);
    expect(meetsMinVersion("", "0.9.32")).toBe(false);
  });

  it("passes at or above the floor, fails below", () => {
    expect(meetsMinVersion("0.9.32", "0.9.32")).toBe(true);
    expect(meetsMinVersion("0.9.33", "0.9.32")).toBe(true);
    expect(meetsMinVersion("0.9.31", "0.9.32")).toBe(false);
  });
});
