import fc from 'fast-check';
import { createHarness, validInvoice, type Harness } from '../support/harness';

let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});

/** Independent oracle in exact integer arithmetic (BigInt), not a copy of the production formula. */
function expectedTotals(lines: { quantity: number; unitPriceCents: number }[], taxRateBps: number) {
  const subtotal = lines.reduce((s, l) => s + BigInt(l.quantity) * BigInt(l.unitPriceCents), 0n);
  const doubled = subtotal * BigInt(taxRateBps) * 2n; // tax*20000, to round half up without floats
  const tax = (doubled + 10000n) / 20000n;
  return { subtotalCents: Number(subtotal), taxCents: Number(tax), totalCents: Number(subtotal + tax) };
}

describe('Invoice totals', () => {
  it.each([
    // subtotal, bps, expected tax: the rounding boundaries
    [1050, 500, 53], // 52.50 -> 53 (half up)
    [1049, 500, 52], // 52.45 -> 52
    [1, 2500, 0], //    0.25 -> 0
    [2, 2500, 1], //    0.50 -> 1
    [0, 2500, 0],
    [999_999, 0, 0],
  ])('subtotal %i at %i bps has %i cents of tax', async (subtotal, bps, tax) => {
    const res = await h.as('clerk').post('/v1/invoices', validInvoice({
      lines: [{ description: 'line', quantity: 1, unitPriceCents: subtotal }],
      taxRateBps: bps,
    }));

    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ subtotalCents: subtotal, taxCents: tax, totalCents: subtotal + tax });
  });

  it('are always computed exactly, for any lines and tax rate (property-based)', async () => {
    const line = fc.record({
      description: fc.constantFrom('Freight', 'Storage', 'Labels', 'Fuel surcharge'),
      quantity: fc.integer({ min: 1, max: 10_000 }),
      unitPriceCents: fc.integer({ min: 0, max: 10_000_000 }),
    });
    await fc.assert(
      fc.asyncProperty(fc.array(line, { minLength: 1, maxLength: 50 }), fc.integer({ min: 0, max: 2500 }), async (lines, taxRateBps) => {
        const res = await h.as('clerk').post('/v1/invoices', { customer: 'Property', lines, taxRateBps });
        const expected = expectedTotals(lines, taxRateBps);
        return (
          res.status === 201 &&
          res.body.subtotalCents === expected.subtotalCents &&
          res.body.taxCents === expected.taxCents &&
          res.body.totalCents === expected.totalCents &&
          Number.isSafeInteger(res.body.totalCents)
        );
      }),
      { numRuns: 150 },
    );
  });

  it('are recomputed when lines change', async () => {
    const invoice = await h.createInvoice('clerk', validInvoice({ taxRateBps: 1000 }));

    const res = await h.as('clerk').patch(`/v1/invoices/${invoice.id}`, {
      lines: [{ description: 'Bigger', quantity: 10, unitPriceCents: 1000 }],
    });

    expect(res.body).toMatchObject({ subtotalCents: 10_000, taxCents: 1_000, totalCents: 11_000 });
  });
});

describe('Invoice lifecycle', () => {
  it.each([
    // starting state, action, expected status, final state
    ['open', 'pay', 200, 'paid'],
    ['open', 'void', 200, 'void'],
    ['paid', 'void', 409, 'paid'],
    ['paid', 'pay', 409, 'paid'],
    ['void', 'pay', 409, 'void'],
    ['void', 'void', 409, 'void'],
  ] as const)('%s invoice: %s -> %i, stays/ends %s', async (start, action, status, end) => {
    const invoice = await h.createInvoice('admin');
    if (start !== 'open') await h.as('admin').post(`/v1/invoices/${invoice.id}/${start === 'paid' ? 'pay' : 'void'}`).expect(200);

    const res = await h.as('admin').post(`/v1/invoices/${invoice.id}/${action}`);

    expect(res.status).toBe(status);
    expect((await h.as('admin').get(`/v1/invoices/${invoice.id}`)).body.status).toBe(end);
  });

  it.each(['pay', 'void'])('a %s invoice can no longer be edited', async (action) => {
    const invoice = await h.createInvoice('admin');
    await h.as('admin').post(`/v1/invoices/${invoice.id}/${action}`).expect(200);

    const res = await h.as('admin').patch(`/v1/invoices/${invoice.id}`, { customer: 'Too late' });

    expect(res.status).toBe(409);
  });
});

describe('Idempotent creation', () => {
  it('replays the original response for the same key and body', async () => {
    const total = async () => (await h.as('clerk').get('/v1/invoices?limit=1')).body.total as number;
    const before = await total();
    const body = validInvoice({ customer: 'Retry Ltd' });
    const first = await h.as('clerk').post('/v1/invoices', body).set('Idempotency-Key', 'retry-1');
    const retry = await h.as('clerk').post('/v1/invoices', body).set('Idempotency-Key', 'retry-1');

    expect(first.status).toBe(201);
    expect(retry.status).toBe(201);
    expect(retry.headers['idempotent-replayed']).toBe('true');
    expect(retry.body).toEqual(first.body);
    expect(await total()).toBe(before + 1); // the retry did not create a second invoice
  });

  it('refuses the same key with a different body', async () => {
    await h.as('clerk').post('/v1/invoices', validInvoice({ customer: 'A' })).set('Idempotency-Key', 'retry-2').expect(201);

    const res = await h.as('clerk').post('/v1/invoices', validInvoice({ customer: 'B' })).set('Idempotency-Key', 'retry-2');

    expect(res.status).toBe(422);
    expect(res).toSatisfyApiSpec();
  });

  it('creates separate invoices without a key', async () => {
    const a = await h.createInvoice('clerk');
    const b = await h.createInvoice('clerk');
    expect(a.id).not.toBe(b.id);
    expect(Number(b.number.slice(4))).toBe(Number(a.number.slice(4)) + 1);
  });
});

describe('Input validation', () => {
  it.each([
    ['empty customer', { customer: '  ' }, 'customer'],
    ['no lines', { lines: [] }, 'lines'],
    ['51 lines', { lines: Array.from({ length: 51 }, () => ({ description: 'x', quantity: 1, unitPriceCents: 1 })) }, 'lines'],
    ['zero quantity', { lines: [{ description: 'x', quantity: 0, unitPriceCents: 1 }] }, 'lines[0].quantity'],
    ['fractional quantity', { lines: [{ description: 'x', quantity: 1.5, unitPriceCents: 1 }] }, 'lines[0].quantity'],
    ['negative price', { lines: [{ description: 'x', quantity: 1, unitPriceCents: -1 }] }, 'lines[0].unitPriceCents'],
    ['price as string', { lines: [{ description: 'x', quantity: 1, unitPriceCents: '100' }] }, 'lines[0].unitPriceCents'],
    ['tax above 25%', { taxRateBps: 2501 }, 'taxRateBps'],
  ])('rejects %s', async (_case, override, field) => {
    const res = await h.as('clerk').post('/v1/invoices', validInvoice(override));

    expect(res.status).toBe(400);
    expect(res.body.errors.map((e: { field: string }) => e.field)).toContain(field);
    expect(res).toSatisfyApiSpec();
  });

  it.each([
    ['status=late', 'status'],
    ['limit=0', 'limit'],
    ['limit=101', 'limit'],
    ['offset=-1', 'offset'],
  ])('rejects the query %s', async (query, field) => {
    const res = await h.as('viewer').get(`/v1/invoices?${query}`);

    expect(res.status).toBe(400);
    expect(res.body.errors[0].field).toBe(field);
  });

  it('filters and paginates', async () => {
    const all = (await h.as('viewer').get('/v1/invoices?limit=100')).body;
    const open = (await h.as('viewer').get('/v1/invoices?status=open&limit=100')).body;
    const page = (await h.as('viewer').get('/v1/invoices?limit=2&offset=1')).body;

    expect(open.data.every((i: { status: string }) => i.status === 'open')).toBe(true);
    expect(open.total).toBeLessThan(all.total);
    expect(page).toMatchObject({ limit: 2, offset: 1, total: all.total });
    expect(page.data).toEqual(all.data.slice(1, 3));
  });
});

describe('Audit trail', () => {
  it('records who changed what', async () => {
    const invoice = await h.createInvoice('clerk');
    await h.as('admin').post(`/v1/invoices/${invoice.id}/void`).expect(200);

    const events = (await h.as('admin').get('/v1/audit-events')).body.data;

    expect(events.slice(0, 2)).toEqual([
      expect.objectContaining({ action: 'invoice.void', actor: 'alice@northwind.test', resource: invoice.id, impersonated: false }),
      expect.objectContaining({ action: 'invoice.created', actor: 'bob@northwind.test', resource: invoice.id }),
    ]);
  });
});
