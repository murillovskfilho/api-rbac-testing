import fc from 'fast-check';
import { createHarness, validInvoice, type Harness, type Persona } from '../support/harness';

/**
 * OWASP API1: Broken Object Level Authorization. A valid user of tenant A must not read or change
 * tenant B's objects by guessing or reusing their ids, and must not learn that they exist.
 */
let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});

const crossTenantCalls = (id: string) =>
  [
    ['GET', (p: Persona) => h.as(p).get(`/v1/invoices/${id}`)],
    ['PATCH', (p: Persona) => h.as(p).patch(`/v1/invoices/${id}`, { customer: 'Hijacked' })],
    ['POST pay', (p: Persona) => h.as(p).post(`/v1/invoices/${id}/pay`)],
    ['POST void', (p: Persona) => h.as(p).post(`/v1/invoices/${id}/void`)],
  ] as const;

describe('Tenant isolation (BOLA)', () => {
  it('answers cross-tenant access exactly like a non-existent id', async () => {
    const victim = await h.createInvoice('admin'); // northwind
    const nonexistent = 'inv_0000000000000000';

    for (const [name, call] of crossTenantCalls(victim.id)) {
      const crossTenant = await call('otherAdmin'); // contoso admin, full permissions in contoso
      const [, sameCallOnMissingId] = crossTenantCalls(nonexistent).find(([n]) => n === name)!;
      const missing = await sameCallOnMissingId('otherAdmin');

      expect({ name, status: crossTenant.status }).toEqual({ name, status: 404 });
      expect({ name, body: crossTenant.body }).toEqual({ name, body: missing.body }); // no existence oracle
    }

    const after = await h.as('admin').get(`/v1/invoices/${victim.id}`);
    expect(after.body).toMatchObject({ customer: victim.customer, status: 'open' });
  });

  it("never lists another tenant's invoices", async () => {
    await h.createInvoice('admin');
    await h.createInvoice('otherAdmin');

    const northwind = await h.invoiceIds('admin');
    const contoso = await h.invoiceIds('otherAdmin');

    expect(northwind.length).toBeGreaterThan(0);
    expect(contoso.length).toBeGreaterThan(0);
    expect(northwind.filter((id) => contoso.includes(id))).toEqual([]);
  });

  it('holds for any invoice, any cross-tenant operation (property-based)', async () => {
    const tenants: [Persona, Persona][] = [
      ['admin', 'otherAdmin'],
      ['otherAdmin', 'admin'],
      ['clerk', 'otherAdmin'],
    ];
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...tenants),
        fc.constantFrom(0, 1, 2, 3),
        fc.string({ minLength: 1, maxLength: 40 }).filter((s) => s.trim().length > 0),
        async ([owner, intruder], op, customer) => {
          const invoice = await h.createInvoice(owner, validInvoice({ customer }));
          const [, call] = crossTenantCalls(invoice.id)[op];
          const res = await call(intruder);
          const stillThere = await h.as(owner).get(`/v1/invoices/${invoice.id}`);
          return res.status === 404 && stillThere.body.status === 'open' && stillThere.body.customer === customer.trim();
        },
      ),
      { numRuns: 40 },
    );
  });

  it('scopes idempotency keys per tenant: one tenant cannot replay another tenant\'s response', async () => {
    const key = 'order-2026-0001';
    const first = await h.as('admin').post('/v1/invoices', validInvoice({ customer: 'Northwind only' })).set('Idempotency-Key', key);
    const second = await h.as('otherAdmin').post('/v1/invoices', validInvoice({ customer: 'Northwind only' })).set('Idempotency-Key', key);

    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    expect(second.headers['idempotent-replayed']).toBeUndefined();
    expect(second.body.id).not.toBe(first.body.id);
  });
});
