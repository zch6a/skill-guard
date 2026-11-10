/**
 * Rules, split by what they read:
 *   rules/catalog.ts    ids, titles, severities, why and fix (the docs are generated from it)
 *   rules/context.ts    how a match's surroundings (docs, tests, warnings, quotes, fences) change its severity
 *   rules/patterns.ts   the regular expressions
 *   rules/text.ts       rules over text units (instructions, code, commands)
 *   rules/mcp.ts        MCP server definitions
 *   rules/structure.ts  hooks, package.json scripts, skill metadata, bundled binaries
 */
export { RULES, RULE_BY_ID } from './rules/catalog.ts';
export { isTestPath } from './rules/context.ts';
export { scanUnit, talksToNetwork } from './rules/text.ts';
export { scanMcp, splitPackage } from './rules/mcp.ts';
export { isBinaryAsset, scanHook, scanOutsideLinks, scanPackageJson, scanSettings, scanSkillMeta } from './rules/structure.ts';
