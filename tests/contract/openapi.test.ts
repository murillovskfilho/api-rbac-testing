import { createHarness, validInvoice, type Harness } from '../support/harness';

/**
 * Contract sweep: at least one real response for every documented operation and status code is
 * validated against openapi/openapi.yaml (status, content type and closed body schema).
 */
let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});

describe('OpenAPI contract', () => {
  it('list invoices: 200, 400, 401, 403, 404', async () => {
    const responses = [
      await h.as('viewer').get('/v1/invoices?status=open&limit=5'), // 200
      await h.as('viewer').get('/v1/invoices?limit=0'), // 400
      await h.anonymous().get('/v1/invoices'), // 401
      await h.as('viewer').get('/v1/invoices').set('X-Act-As-Tenant', 'contoso'), // 403
      await h.as('support').get('/v1/invoices').set('X-Act-As-Tenant', 'nope'), // 404
    ];
    expect(responses.map((r) => r.status)).toEqual([200, 400, 401, 403, 404]);
    for (const res of responses) expect(res).toSatisfyApiSpec();
  });

  it('create invoice: 201, 400, 403, 422', async () => {
    const created = await h.as('clerk').post('/v1/invoices', validInvoice()).set('Idempotency-Key', 'contract-1');
    const responses = [
      created,
      await h.as('clerk').post('/v1/invoices', { customer: '' }),
      await h.as('viewer').post('/v1/invoices', validInvoice()),
      await h.as('clerk').post('/v1/invoices', validInvoice({ customer: 'other' })).set('Idempotency-Key', 'contract-1'),
    ];
    expect(responses.map((r) => r.status)).toEqual([201, 400, 403, 422]);
    expect(created.headers.location).toBe(`/v1/invoices/${created.body.id}`);
    for (const res of responses) expect(res).toSatisfyApiSpec();
  });

  it('get, edit, pay and void: success and error codes', async () => {
    const a = await h.createInvoice('admin');
    const b = await h.createInvoice('admin');
    const responses = [
      await h.as('viewer').get(`/v1/invoices/${a.id}`), // 200
      await h.as('viewer').get('/v1/invoices/inv_0000000000000000'), // 404
      await h.as('clerk').patch(`/v1/invoices/${a.id}`, { taxRateBps: 100 }), // 200
      await h.as('clerk').patch(`/v1/invoices/${a.id}`, {}), // 400
      await h.as('clerk').post(`/v1/invoices/${a.id}/pay`), // 200
      await h.as('clerk').patch(`/v1/invoices/${a.id}`, { customer: 'late' }), // 409
      await h.as('clerk').post(`/v1/invoices/${b.id}/void`), // 403
      await h.as('admin').post(`/v1/invoices/${b.id}/void`), // 200
      await h.as('admin').post(`/v1/invoices/${b.id}/void`), // 409
    ];
    expect(responses.map((r) => r.status)).toEqual([200, 404, 200, 400, 200, 409, 403, 200, 409]);
    for (const res of responses) expect(res).toSatisfyApiSpec();
  });

  it('audit events: 200 and 403', async () => {
    await h.as('support').get('/v1/invoices').set('X-Act-As-Tenant', 'northwind');
    const ok = await h.as('admin').get('/v1/audit-events');
    const denied = await h.as('clerk').get('/v1/audit-events');

    expect([ok.status, denied.status]).toEqual([200, 403]);
    expect(ok.body.data.length).toBeGreaterThan(0);
    expect(ok).toSatisfyApiSpec();
    expect(denied).toSatisfyApiSpec();
  });
});
