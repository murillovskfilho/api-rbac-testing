import { createHash, randomBytes } from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import { createLocalJWKSet, jwtVerify } from 'jose';
import {
  computeTotals,
  TENANTS,
  type AuditEvent,
  type Invoice,
  type InvoiceLine,
  type Permission,
} from './domain';
import type { IdentityProvider } from './idp';

/**
 * Billing API: multi-tenant invoices with Auth0-style RBAC, read-only support impersonation,
 * audit trail, strict input validation, idempotent creation and RFC 7807 error bodies.
 * Each createApp() call has its own in-memory store, so every test file starts clean.
 */

interface Principal {
  sub: string;
  homeTenant: string;
  tenant: string; // effective tenant (differs when impersonating)
  permissions: string[];
  impersonating: boolean;
}
type AuthedRequest = Request & { principal: Principal };

const IMPERSONATION_HEADER = 'x-act-as-tenant';
const newId = (prefix: string) => `${prefix}_${randomBytes(8).toString('hex')}`;

function problem(res: Response, status: number, title: string, detail?: string, extra: Record<string, unknown> = {}) {
  res.status(status).type('application/problem+json').json({ type: 'about:blank', title, status, ...(detail ? { detail } : {}), ...extra });
}

export function createApp(idp: IdentityProvider) {
  const jwks = createLocalJWKSet(idp.jwks);
  const invoices: Invoice[] = [];
  const audit: AuditEvent[] = [];
  const sequences = new Map<string, number>();
  const idempotency = new Map<string, { bodyHash: string; status: number; body: unknown }>();

  const nextNumber = (tenant: string) => {
    const n = (sequences.get(tenant) ?? 0) + 1;
    sequences.set(tenant, n);
    return `INV-${String(n).padStart(4, '0')}`;
  };

  function insertInvoice(tenant: string, createdBy: string, input: { customer: string; lines: InvoiceLine[]; taxRateBps: number }, extra: Partial<Invoice> = {}) {
    const invoice: Invoice = {
      id: newId('inv'),
      tenantId: tenant,
      number: nextNumber(tenant),
      customer: input.customer,
      currency: 'USD',
      lines: input.lines,
      taxRateBps: input.taxRateBps,
      ...computeTotals(input.lines, input.taxRateBps),
      status: 'open',
      createdBy,
      createdAt: new Date().toISOString(),
      ...extra,
    };
    invoices.push(invoice);
    return invoice;
  }

  // Seed data.
  const line = (description: string, quantity: number, unitPriceCents: number) => ({ description, quantity, unitPriceCents });
  insertInvoice('northwind', 'seed', { customer: 'Blue Yonder Airlines', lines: [line('Freight Q1', 3, 125000)], taxRateBps: 825 }, { internalNotes: 'VIP: manual discount approved by finance' });
  insertInvoice('northwind', 'seed', { customer: 'Fabrikam', lines: [line('Storage', 1, 99900)], taxRateBps: 0 }, { status: 'paid' });
  insertInvoice('northwind', 'seed', { customer: 'Litware', lines: [line('Labels', 500, 45)], taxRateBps: 500 }, { status: 'void' });
  insertInvoice('contoso', 'seed', { customer: 'Woodgrove Bank', lines: [line('Courier', 12, 1999)], taxRateBps: 700 }, { internalNotes: 'Disputed in 2025' });
  insertInvoice('contoso', 'seed', { customer: 'Tailspin Toys', lines: [line('Pallets', 2, 32050)], taxRateBps: 0 });

  /** The public representation. Allow-list, never deny-list: internal fields cannot leak by accident. */
  const view = (i: Invoice) => ({
    id: i.id,
    number: i.number,
    customer: i.customer,
    currency: i.currency,
    lines: i.lines,
    taxRateBps: i.taxRateBps,
    subtotalCents: i.subtotalCents,
    taxCents: i.taxCents,
    totalCents: i.totalCents,
    status: i.status,
    createdBy: i.createdBy,
    createdAt: i.createdAt,
  });

  function record(p: Principal, action: string, resource: string) {
    audit.push({
      id: newId('evt'),
      at: new Date().toISOString(),
      tenant: p.tenant,
      actor: p.sub,
      actorTenant: p.homeTenant,
      impersonated: p.impersonating,
      action,
      resource,
    });
  }

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));
  app.use('/idp', idp.router);
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  async function authenticate(req: Request, res: Response, next: NextFunction) {
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
    res.setHeader('WWW-Authenticate', 'Bearer realm="billing", error="invalid_token"');
    if (!token) return problem(res, 401, 'Unauthorized', 'A bearer token is required.');

    let claims;
    try {
      ({ payload: claims } = await jwtVerify(token, jwks, {
        issuer: idp.issuer,
        audience: idp.audience,
        algorithms: ['RS256'], // never accept "none" or symmetric algorithms for these keys
        requiredClaims: ['sub', 'exp', 'org_id', 'permissions'],
      }));
    } catch {
      return problem(res, 401, 'Unauthorized', 'The bearer token is invalid or expired.');
    }
    if (typeof claims.org_id !== 'string' || !Array.isArray(claims.permissions) || !claims.permissions.every((p: unknown) => typeof p === 'string')) {
      return problem(res, 401, 'Unauthorized', 'The bearer token has malformed claims.');
    }
    res.removeHeader('WWW-Authenticate');

    const principal: Principal = {
      sub: claims.sub!,
      homeTenant: claims.org_id,
      tenant: claims.org_id,
      permissions: claims.permissions as string[],
      impersonating: false,
    };

    const actAs = req.header(IMPERSONATION_HEADER);
    if (actAs !== undefined) {
      if (!principal.permissions.includes('impersonate:tenants')) {
        return problem(res, 403, 'Forbidden', 'Missing permission: impersonate:tenants');
      }
      if (!(TENANTS as readonly string[]).includes(actAs)) return problem(res, 404, 'Not Found', 'Unknown tenant.');
      if (req.method !== 'GET') return problem(res, 403, 'Forbidden', 'Impersonated sessions are read-only.');
      principal.tenant = actAs;
      principal.impersonating = true;
      record(principal, 'impersonation.request', `${req.method} ${req.originalUrl}`);
    }

    (req as AuthedRequest).principal = principal;
    next();
  }

  const requires = (permission: Permission) => (req: Request, res: Response, next: NextFunction) =>
    (req as AuthedRequest).principal.permissions.includes(permission)
      ? next()
      : problem(res, 403, 'Forbidden', `Missing permission: ${permission}`);

  // Cross-tenant ids are reported as "not found", never "forbidden": no existence oracle (BOLA).
  const findOwn = (req: Request) =>
    invoices.find((i) => i.id === req.params.id && i.tenantId === (req as AuthedRequest).principal.tenant);

  const api = express.Router();
  api.use(authenticate);

  api.get('/invoices', requires('read:invoices'), (req, res) => {
    const { tenant } = (req as AuthedRequest).principal;
    const errors = [];
    const status = req.query.status as string | undefined;
    if (status !== undefined && !['open', 'paid', 'void'].includes(status)) errors.push({ field: 'status', message: 'must be one of open, paid, void' });
    const limit = req.query.limit === undefined ? 20 : Number(req.query.limit);
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) errors.push({ field: 'limit', message: 'must be an integer between 1 and 100' });
    const offset = req.query.offset === undefined ? 0 : Number(req.query.offset);
    if (!Number.isInteger(offset) || offset < 0) errors.push({ field: 'offset', message: 'must be a non-negative integer' });
    if (errors.length) return problem(res, 400, 'Bad Request', 'Invalid query parameters.', { errors });

    const matching = invoices.filter((i) => i.tenantId === tenant && (!status || i.status === status));
    res.json({ data: matching.slice(offset, offset + limit).map(view), total: matching.length, limit, offset });
  });

  api.get('/invoices/:id', requires('read:invoices'), (req, res) => {
    const invoice = findOwn(req);
    if (!invoice) return problem(res, 404, 'Not Found', 'Invoice not found.');
    res.json(view(invoice));
  });

  api.post('/invoices', requires('write:invoices'), (req, res) => {
    const p = (req as AuthedRequest).principal;
    const key = req.header('idempotency-key');
    const bodyHash = createHash('sha256').update(JSON.stringify(req.body ?? null)).digest('hex');
    const scopedKey = key ? `${p.tenant}:${key}` : undefined;

    if (scopedKey && idempotency.has(scopedKey)) {
      const saved = idempotency.get(scopedKey)!;
      if (saved.bodyHash !== bodyHash) {
        return problem(res, 422, 'Unprocessable Entity', 'Idempotency-Key was already used with a different request body.');
      }
      res.setHeader('Idempotent-Replayed', 'true');
      return res.status(saved.status).json(saved.body);
    }

    const parsed = parseInvoiceInput(req.body, { partial: false });
    if (!parsed.ok) return problem(res, 400, 'Bad Request', 'The request body is invalid.', { errors: parsed.errors });
    const invoice = insertInvoice(p.tenant, p.sub, parsed.value as Required<InvoiceInput>);
    record(p, 'invoice.created', invoice.id);
    const body = view(invoice);
    if (scopedKey) idempotency.set(scopedKey, { bodyHash, status: 201, body });
    res.status(201).location(`/v1/invoices/${invoice.id}`).json(body);
  });

  api.patch('/invoices/:id', requires('write:invoices'), (req, res) => {
    const p = (req as AuthedRequest).principal;
    const invoice = findOwn(req);
    if (!invoice) return problem(res, 404, 'Not Found', 'Invoice not found.');
    const parsed = parseInvoiceInput(req.body, { partial: true });
    if (!parsed.ok) return problem(res, 400, 'Bad Request', 'The request body is invalid.', { errors: parsed.errors });
    if (invoice.status !== 'open') return problem(res, 409, 'Conflict', `A ${invoice.status} invoice cannot be changed.`);

    Object.assign(invoice, parsed.value);
    Object.assign(invoice, computeTotals(invoice.lines, invoice.taxRateBps));
    record(p, 'invoice.updated', invoice.id);
    res.json(view(invoice));
  });

  for (const [action, permission, from, to] of [
    ['pay', 'write:invoices', ['open'], 'paid'],
    ['void', 'void:invoices', ['open'], 'void'],
  ] as const) {
    api.post(`/invoices/:id/${action}`, requires(permission), (req, res) => {
      const p = (req as AuthedRequest).principal;
      const invoice = findOwn(req);
      if (!invoice) return problem(res, 404, 'Not Found', 'Invoice not found.');
      if (!(from as readonly string[]).includes(invoice.status)) {
        return problem(res, 409, 'Conflict', `A ${invoice.status} invoice cannot be marked ${to}.`);
      }
      invoice.status = to;
      record(p, `invoice.${to}`, invoice.id);
      res.json(view(invoice));
    });
  }

  api.get('/audit-events', requires('read:audit'), (req, res) => {
    const { tenant } = (req as AuthedRequest).principal;
    res.json({ data: audit.filter((e) => e.tenant === tenant).reverse() });
  });

  app.use('/v1', api);
  app.use((_req, res) => problem(res, 404, 'Not Found', 'No such route.'));
  // Malformed JSON and other errors: never leak stack traces.
  app.use((err: Error & { status?: number; type?: string }, _req: Request, res: Response, _next: NextFunction) => {
    if (err.type === 'entity.parse.failed') return problem(res, 400, 'Bad Request', 'The request body is not valid JSON.');
    if (err.type === 'entity.too.large') return problem(res, 413, 'Payload Too Large');
    problem(res, 500, 'Internal Server Error');
  });

  return app;
}

interface InvoiceInput {
  customer?: string;
  lines?: InvoiceLine[];
  taxRateBps?: number;
}
type FieldError = { field: string; message: string };

/**
 * Strict allow-list validation. Any unknown field (tenantId, status, totalCents, createdBy, ...)
 * is rejected, which is the defence against mass assignment.
 */
function parseInvoiceInput(body: unknown, { partial }: { partial: boolean }): { ok: true; value: InvoiceInput } | { ok: false; errors: FieldError[] } {
  const errors: FieldError[] = [];
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return { ok: false, errors: [{ field: '', message: 'must be a JSON object' }] };
  }
  const b = body as Record<string, unknown>;
  for (const key of Object.keys(b)) {
    if (!['customer', 'lines', 'taxRateBps'].includes(key)) errors.push({ field: key, message: 'is not allowed' });
  }

  const value: InvoiceInput = {};
  if (b.customer !== undefined || !partial) {
    if (typeof b.customer !== 'string' || b.customer.trim().length === 0 || b.customer.length > 120) {
      errors.push({ field: 'customer', message: 'must be a string of 1 to 120 characters' });
    } else value.customer = b.customer.trim();
  }
  if (b.lines !== undefined || !partial) {
    if (!Array.isArray(b.lines) || b.lines.length < 1 || b.lines.length > 50) {
      errors.push({ field: 'lines', message: 'must be an array of 1 to 50 lines' });
    } else {
      b.lines.forEach((raw, i) => {
        const l = (raw ?? {}) as Record<string, unknown>;
        for (const key of Object.keys(l)) {
          if (!['description', 'quantity', 'unitPriceCents'].includes(key)) errors.push({ field: `lines[${i}].${key}`, message: 'is not allowed' });
        }
        if (typeof l.description !== 'string' || l.description.length < 1 || l.description.length > 200) {
          errors.push({ field: `lines[${i}].description`, message: 'must be a string of 1 to 200 characters' });
        }
        if (!Number.isInteger(l.quantity) || (l.quantity as number) < 1 || (l.quantity as number) > 10_000) {
          errors.push({ field: `lines[${i}].quantity`, message: 'must be an integer between 1 and 10000' });
        }
        if (!Number.isInteger(l.unitPriceCents) || (l.unitPriceCents as number) < 0 || (l.unitPriceCents as number) > 10_000_000) {
          errors.push({ field: `lines[${i}].unitPriceCents`, message: 'must be an integer between 0 and 10000000' });
        }
      });
      value.lines = (b.lines as Record<string, unknown>[]).map((l) => ({
        description: l.description as string,
        quantity: l.quantity as number,
        unitPriceCents: l.unitPriceCents as number,
      }));
    }
  }
  if (b.taxRateBps !== undefined) {
    if (!Number.isInteger(b.taxRateBps) || (b.taxRateBps as number) < 0 || (b.taxRateBps as number) > 2500) {
      errors.push({ field: 'taxRateBps', message: 'must be an integer between 0 and 2500' });
    } else value.taxRateBps = b.taxRateBps as number;
  } else if (!partial) value.taxRateBps = 0;

  if (partial && Object.keys(b).length === 0) errors.push({ field: '', message: 'at least one field is required' });
  return errors.length ? { ok: false, errors } : { ok: true, value };
}
