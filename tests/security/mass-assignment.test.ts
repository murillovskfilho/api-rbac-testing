import { createHarness, validInvoice, type Harness } from '../support/harness';

/**
 * OWASP API3 (property level authorization) / mass assignment: clients must not be able to set
 * server-owned fields, and must find out loudly (400) rather than being silently ignored.
 */
let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});

const PROTECTED: [string, unknown][] = [
  ['tenantId', 'contoso'],
  ['status', 'paid'],
  ['totalCents', 1],
  ['subtotalCents', 1],
  ['taxCents', 0],
  ['createdBy', 'someone-else@northwind.test'],
  ['id', 'inv_ffffffffffffffff'],
  ['number', 'INV-9999'],
  ['internalNotes', 'approved'],
  ['currency', 'BRL'],
];

describe('Mass assignment', () => {
  it.each(PROTECTED)('POST rejects the server-owned field "%s"', async (field, value) => {
    const before = (await h.as('admin').get('/v1/invoices')).body.total;

    const res = await h.as('admin').post('/v1/invoices', validInvoice({ [field]: value }));

    expect(res.status).toBe(400);
    expect(res.body.errors).toEqual([{ field, message: 'is not allowed' }]);
    expect(res).toSatisfyApiSpec();
    expect((await h.as('admin').get('/v1/invoices')).body.total).toBe(before);
  });

  it.each(PROTECTED)('PATCH rejects the server-owned field "%s" and changes nothing', async (field, value) => {
    const invoice = await h.createInvoice('admin');

    const res = await h.as('admin').patch(`/v1/invoices/${invoice.id}`, { customer: 'Changed', [field]: value });

    expect(res.status).toBe(400);
    expect(res.body.errors).toContainEqual({ field, message: 'is not allowed' });
    const after = await h.as('admin').get(`/v1/invoices/${invoice.id}`);
    expect(after.body).toEqual(invoice);
  });

  it('rejects unknown fields inside nested line items', async () => {
    const res = await h.as('admin').post('/v1/invoices', {
      customer: 'Nested',
      lines: [{ description: 'Freight', quantity: 1, unitPriceCents: 100, discountCents: 100 }],
    });

    expect(res.status).toBe(400);
    expect(res.body.errors).toEqual([{ field: 'lines[0].discountCents', message: 'is not allowed' }]);
  });

  it('ignores client-sent totals because there is nowhere to send them: the server computes them', async () => {
    const res = await h.as('admin').post('/v1/invoices', validInvoice({ lines: [{ description: 'x', quantity: 3, unitPriceCents: 1000 }], taxRateBps: 1000 }));

    expect(res.body).toMatchObject({ subtotalCents: 3000, taxCents: 300, totalCents: 3300 });
  });
});
