import type { FastifyReply } from 'fastify';

/**
 * Shared list-query handling for management routes, so every endpoint that
 * lists things offers the same sort, filter and pagination the data tables
 * expect. The frontend speaks a PostgREST-style querystring
 * (`?name=ilike.*ada*&order=created_at.desc&limit=25&offset=0`); this parses
 * that into SQL fragments the route composes into its own, already
 * permission-scoped, query.
 *
 * Columns are allowlisted, values are parameterised, and the caller supplies
 * the parameter start index so the filter params slot after its own.
 */

/**
 * Maps an API column name (what the client sends) to its SQL expression (what
 * the query uses, e.g. 'r.name' in a joined query). Values are developer
 * authored and trusted; keys are matched against the request and never
 * interpolated.
 */
export type ColumnMap = Record<string, string>;

export interface ListParamsConfig {
  /** Columns allowed in ORDER BY, mapped to their SQL expression. */
  sortable: ColumnMap;
  /** Columns allowed to filter on, mapped to their SQL expression. */
  filterable: ColumnMap;
  /** Applied when the request sets no order, e.g. 'name.asc'. */
  defaultOrder?: string;
  /** Largest page a caller may request. Default 200. */
  maxLimit?: number;
}

export interface ParsedListParams {
  /** True when the request asked to paginate (sent limit or offset). */
  paginated: boolean;
  /** The page size, or the returned-row count when unpaginated. */
  limit: number;
  offset: number;
  /** 'ORDER BY "col" ASC' or ''. */
  orderSql: string;
  /** Conditions joined by AND, without a WHERE or leading AND, or ''. The route
   *  composes these with its own scope conditions. */
  filterSql: string;
  /** Filter values, numbered from startIndex. */
  params: unknown[];
  /** ' LIMIT $n OFFSET $m', or '' when the request did not ask to paginate. */
  pageSql: string;
  /** All params in order: filters, then limit and offset when paginating. */
  allParams: unknown[];
}

export class ListQueryError extends Error {
  constructor(message: string) { super(message); this.name = 'ListQueryError'; }
}

const RESERVED = new Set(['order', 'limit', 'offset', 'select', 'include_archived']);

const OPERATORS: Record<string, (col: string, i: number) => { sql: string; wildcard?: boolean }> = {
  eq:    (c, i) => ({ sql: `${c} = $${i}` }),
  neq:   (c, i) => ({ sql: `${c} <> $${i}` }),
  gt:    (c, i) => ({ sql: `${c} > $${i}` }),
  gte:   (c, i) => ({ sql: `${c} >= $${i}` }),
  lt:    (c, i) => ({ sql: `${c} < $${i}` }),
  lte:   (c, i) => ({ sql: `${c} <= $${i}` }),
  like:  (c, i) => ({ sql: `${c} LIKE $${i}`,  wildcard: true }),
  ilike: (c, i) => ({ sql: `${c} ILIKE $${i}`, wildcard: true }),
};

function parseInteger(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) throw new ListQueryError(`invalid_integer:${value}`);
  return n;
}

function buildOrder(raw: string | undefined, sortable: ColumnMap, fallback: string | undefined): string {
  const spec = raw ?? fallback;
  if (!spec) return '';
  const parts: string[] = [];
  for (const segment of spec.split(',')) {
    const [col, dir = 'asc'] = segment.trim().split('.');
    const expr = sortable[col];
    if (!expr) throw new ListQueryError(`unsortable_column:${col}`);
    const direction = dir.toLowerCase() === 'desc' ? 'DESC' : 'ASC';
    parts.push(`${expr} ${direction}`);
  }
  return parts.length ? `ORDER BY ${parts.join(', ')}` : '';
}

/**
 * Parses the querystring into SQL fragments. `qs` is req.query. `startIndex` is
 * one past the count of params the route already uses, so filter params do not
 * collide with the route's own.
 */
export function parseListParams(
  qs: Record<string, unknown>,
  config: ListParamsConfig,
  startIndex = 1,
): ParsedListParams {
  const maxLimit = config.maxLimit ?? 200;

  const first = (v: unknown): string | undefined =>
    Array.isArray(v) ? (v[0] as string | undefined) : (v as string | undefined);

  // Pagination is opt-in: a request that sends neither limit nor offset gets
  // every matching row, so existing clients that expect the full list are
  // unchanged. A request that paginates is clamped to the max page.
  const paginated = first(qs.limit) !== undefined || first(qs.offset) !== undefined;
  const requestedLimit = parseInteger(first(qs.limit), maxLimit);
  const limit = Math.min(requestedLimit, maxLimit);
  const offset = parseInteger(first(qs.offset), 0);

  const orderSql = buildOrder(first(qs.order), config.sortable, config.defaultOrder);

  const conditions: string[] = [];
  const params: unknown[] = [];
  let index = startIndex;

  for (const [key, rawValue] of Object.entries(qs)) {
    if (RESERVED.has(key)) continue;
    const value = first(rawValue);
    if (value === undefined || value === '') continue;
    const expr = config.filterable[key];
    if (!expr) throw new ListQueryError(`unfilterable_column:${key}`);

    const dot = value.indexOf('.');
    const op = dot === -1 ? 'eq' : value.slice(0, dot).toLowerCase();
    const raw = dot === -1 ? value : value.slice(dot + 1);
    const build = OPERATORS[op];
    if (!build) throw new ListQueryError(`unsupported_operator:${op}`);

    const { sql, wildcard } = build(expr, index);
    conditions.push(sql);
    params.push(wildcard ? raw.replace(/\*/g, '%') : raw);
    index += 1;
  }

  const filterSql = conditions.join(' AND ');
  const pageSql = paginated ? ` LIMIT $${index} OFFSET $${index + 1}` : '';

  return {
    paginated,
    limit,
    offset,
    orderSql,
    filterSql,
    params,
    pageSql,
    allParams: paginated ? [...params, limit, offset] : [...params],
  };
}

/** Joins scope conditions with the parsed filter conditions into a WHERE, or ''. */
export function composeWhere(...conditions: Array<string | undefined | null>): string {
  const kept = conditions.filter((c): c is string => Boolean(c && c.trim()));
  return kept.length ? `WHERE ${kept.join(' AND ')}` : '';
}

/** Sets the Content-Range header the frontend reads for the total row count. */
export function setContentRange(reply: FastifyReply, offset: number, returned: number, total: number): void {
  const end = returned > 0 ? offset + returned - 1 : offset;
  reply.header('Content-Range', `${offset}-${end}/${total}`);
}
