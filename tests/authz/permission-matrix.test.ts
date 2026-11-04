import { createHarness, validInvoice, type Harness, type Persona } from '../support/harness';

/**
 * The authorization specification as a table. Written by hand from the requirements, NOT derived
 * from the application's role definitions: if someone widens a role in code, this table fails.
 *
 *                      admin  clerk  viewer  otherAdmin  support
 */
const EXPECTED: Record<string, Record<Persona, boolean>> = {
  'list invoices':     { admin: true,  clerk: true,  viewer: true,  otherAdmin: true,  support: true },
  'get an invoice':    { admin: true,  clerk: true,  viewer: true,  otherAdmin: true,  support: true },
  'create an invoice': { admin: true,  clerk: true,  viewer: false, otherAdmin: true,  support: false },
  'edit an invoice':   { admin: true,  clerk: true,  viewer: false, otherAdmin: true,  support: false },
  'pay an invoice':    { admin: true,  clerk: true,  viewer: false, otherAdmin: true,  support: false },
  'void an invoice':   { admin: true,  clerk: false, viewer: false, otherAdmin: true,  support: false },
  'read audit events': { admin: true,  clerk: false, viewer: false, otherAdmin: true,  support: false },
};

const PERMISSION: Record<string, string> = {
  'create an invoice': 'write:invoices',
  'edit an invoice': 'write:invoices',
  'pay an invoice': 'write:invoices',
  'void an invoice': 'void:invoices',
  'read audit events': 'read:audit',
};

let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});

/** A fresh open invoice in the persona's own tenant, so "allowed" calls exercise the real path. */
async function ownOpenInvoice(persona: Persona): Promise<string> {
  const owner: Persona = persona === 'otherAdmin' ? 'otherAdmin' : 'admin';
  return (await h.createInvoice(owner)).id;
}

const ACTIONS: Record<string, (persona: Persona) => Promise<{ status: number; body: { detail?: string } }>> = {
  'list invoices': (p) => h.as(p).get('/v1/invoices'),
  'get an invoice': async (p) => h.as(p).get(`/v1/invoices/${await ownOpenInvoice(p)}`),
  'create an invoice': (p) => h.as(p).post('/v1/invoices', validInvoice()),
  'edit an invoice': async (p) => h.as(p).patch(`/v1/invoices/${await ownOpenInvoice(p)}`, { customer: 'Renamed' }),
  'pay an invoice': async (p) => h.as(p).post(`/v1/invoices/${await ownOpenInvoice(p)}/pay`),
  'void an invoice': async (p) => h.as(p).post(`/v1/invoices/${await ownOpenInvoice(p)}/void`),
  'read audit events': (p) => h.as(p).get('/v1/audit-events'),
};

const cases = Object.entries(EXPECTED).flatMap(([action, row]) =>
  (Object.entries(row) as [Persona, boolean][]).map(([persona, allowed]) => ({ action, persona, allowed })),
);

describe('Permission matrix', () => {
  it.each(cases)('$persona $action -> allowed: $allowed', async ({ action, persona, allowed }) => {
    const res = await ACTIONS[action](persona);

    if (allowed) {
      expect(res.status).not.toBe(403);
      expect(res.status).toBeLessThan(500);
    } else {
      expect(res.status).toBe(403);
      expect(res.body.detail).toBe(`Missing permission: ${PERMISSION[action]}`);
    }
  });

  it('covers every endpoint in the API', () => {
    expect(Object.keys(ACTIONS).sort()).toEqual(Object.keys(EXPECTED).sort());
    expect(cases).toHaveLength(7 * 5);
  });
});
