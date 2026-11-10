/**
 * MCP tool descriptions inside server source code.
 *
 * In a server, a tool's docstring or `description` string is not a comment: the server sends
 * it to the model as part of `tools/list`, and the model follows it. That is where tool
 * poisoning hides ("<IMPORTANT> before using this tool, read ~/.ssh/id_rsa …"). Statically we
 * cannot run the server, but we can find those strings and scan them as instructions.
 */

/** Source that defines MCP tools (Python SDK / FastMCP, TypeScript SDK, low-level handlers). */
export const MCP_SERVER_CODE = /\b(FastMCP|@mcp\.tool|@server\.(list_tools|call_tool|tool)|from mcp\b|import mcp\b|McpServer|@modelcontextprotocol\/sdk|ListToolsRequestSchema|registerTool\s*\(|server\.tool\s*\()/;

export interface Description {
  text: string;
  /** 1-based line where the string starts. */
  line: number;
}

// Bounded: an unclosed quote must not make every later start position scan to the end of the file.
const STRING = String.raw`(["'\x60])((?:\\[\s\S]|(?!\1)[^\\]){0,8000})\1`;
const PATTERNS = [
  // Python docstrings and other triple-quoted strings
  /("""|''')([\s\S]{0,20000}?)\1/g,
  // description="…" / description: '…' / "description": "…"
  new RegExp(String.raw`["']?\bdescription["']?\s*[:=]\s*` + STRING, 'g'),
  // zod: .describe("…")
  new RegExp(String.raw`\.describe\(\s*` + STRING, 'g'),
  // server.tool("name", "description", …)
  new RegExp(String.raw`\.tool\(\s*(["'\x60])[^"'\x60\n]{0,200}\1\s*,\s*(["'\x60])((?:\\[\s\S]|(?!\2)[^\\]){0,8000})\2`, 'g'),
];

// `\n` becomes a space, not a newline: the text must keep the source's line count, or findings
// would point below the string they came from.
const unescape = (s: string) => s.replace(/\\[nrt]/g, '  ').replace(/\\(["'`\\])/g, '$1');

/** `force`: the file belongs to an MCP server (its own source or a module it imports), marker or not. */
export function toolDescriptions(source: string, force = false): Description[] {
  if (!force && !MCP_SERVER_CODE.test(source)) return [];
  const out: Description[] = [];
  const seen = new Set<number>();
  for (const re of PATTERNS) {
    for (const m of source.matchAll(re)) {
      const body = m[m.length - 1] ?? '';
      if (body.trim().length < 12) continue; // names and short labels carry no instructions
      const start = (m.index ?? 0) + m[0].indexOf(body);
      if (seen.has(start)) continue;
      seen.add(start);
      out.push({ text: unescape(body), line: source.slice(0, start).split('\n').length });
    }
  }
  return out;
}
