import { createHarness, validInvoice, type Harness } from '../support/harness';

/**
 * Support impersonation ("act as tenant"): useful, and dangerous. The rules under test:
 * only `impersonate:tenants` may use it, it is read-only, and every use is visible in the
 * impersonated tenant's audit trail.
 */
let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});

const ACT_AS = 'X-Act-As-Tenant';

describe('Support impersonation', () => {
  it('sees nothing without impersonating: a support agent has no tenant data of their own', async () => {
    const res = await h.as('support').get('/v1/invoices');

    expect(res.status).toBe(200);
    expect(res.body.total).toBe(0);
  });

  it('reads exactly what the tenant sees while impersonating', async () => {
    const asTenant = await h.invoiceIds('admin');

    const res = await h.as('support').get('/v1/invoices?limit=100').set(ACT_AS, 'northwind');

    expect(res.status).toBe(200);
    expect(res.body.data.map((i: { id: string }) => i.id)).toEqual(asTenant);
    expect(res).toSatisfyApiSpec();
  });

  it.each([
    ['create', (_id: string) => ['post', '/v1/invoices', validInvoice()] as const],
    ['edit', (id: string) => ['patch', `/v1/invoices/${id}`, { customer: 'Support edit' }] as const],
    ['pay', (id: string) => ['post', `/v1/invoices/${id}/pay`, undefined] as const],
    ['void', (id: string) => ['post', `/v1/invoices/${id}/void`, undefined] as const],
  ])('cannot %s while impersonating (read-only)', async (_name, build) => {
    const invoice = await h.createInvoice('admin');
    const [method, url, body] = build(invoice.id);

    const res = await h.as('support').call(method, url, body).set(ACT_AS, 'northwind');

    expect(res.status).toBe(403);
    expect(res.body.detail).toBe('Impersonated sessions are read-only.');
    expect((await h.as('admin').get(`/v1/invoices/${invoice.id}`)).body).toEqual(invoice);
  });

  it('refuses impersonation to users without the permission', async () => {
    const res = await h.as('clerk').get('/v1/invoices').set(ACT_AS, 'contoso');

    expect(res.status).toBe(403);
    expect(res.body.detail).toBe('Missing permission: impersonate:tenants');
  });

  it('refuses an unknown tenant', async () => {
    const res = await h.as('support').get('/v1/invoices').set(ACT_AS, 'umbrella');
    expect(res.status).toBe(404);
  });

  it('does not grant permissions the agent lacks, even while impersonating', async () => {
    const res = await h.as('support').get('/v1/audit-events').set(ACT_AS, 'northwind');

    expect(res.status).toBe(403);
    expect(res.body.detail).toBe('Missing permission: read:audit');
  });

  it("records every impersonated request in that tenant's audit trail only", async () => {
    await h.as('support').get('/v1/invoices?status=open').set(ACT_AS, 'contoso');

    const contosoAudit = (await h.as('otherAdmin').get('/v1/audit-events')).body.data;
    const northwindAudit = (await h.as('admin').get('/v1/audit-events')).body.data;

    expect(contosoAudit[0]).toMatchObject({
      tenant: 'contoso',
      actor: 'sam@support.test',
      actorTenant: 'internal',
      impersonated: true,
      action: 'impersonation.request',
      resource: 'GET /v1/invoices?status=open',
    });
    expect(northwindAudit.some((e: { resource: string }) => e.resource === 'GET /v1/invoices?status=open')).toBe(false);
  });
});
