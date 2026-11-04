import { createHarness, type Harness } from '../support/harness';

/** OWASP API3 (excessive data exposure) and safe error handling. */
let h: Harness;
beforeAll(async () => {
  h = await createHarness();
});

describe('Data exposure', () => {
  it('never returns internal fields or the tenant id, in lists or in single reads', async () => {
    const list = await h.as('admin').get('/v1/invoices?limit=100');
    const raw = JSON.stringify(list.body);

    expect(raw).not.toContain('internalNotes');
    expect(raw).not.toContain('VIP: manual discount approved'); // the seeded internal note
    expect(raw).not.toContain('tenantId');

    for (const { id } of list.body.data) {
      const one = await h.as('admin').get(`/v1/invoices/${id}`);
      expect(one.body).not.toHaveProperty('internalNotes');
      expect(one.body).not.toHaveProperty('tenantId');
      expect(one).toSatisfyApiSpec(); // the closed schema would fail on any extra field
    }
  });

  it('does not advertise the server framework', async () => {
    const res = await h.as('viewer').get('/v1/invoices');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('answers malformed JSON with a clean problem document, no stack trace', async () => {
    const res = await h
      .as('admin')
      .post('/v1/invoices')
      .set('Content-Type', 'application/json')
      .send('{"customer": "broken",');

    expect(res.status).toBe(400);
    expect(res.headers['content-type']).toMatch(/^application\/problem\+json/);
    expect(res.body).toEqual({ type: 'about:blank', title: 'Bad Request', status: 400, detail: 'The request body is not valid JSON.' });
    expect(res.text).not.toMatch(/at .+\.(ts|js):\d+/);
  });

  it('refuses oversized bodies', async () => {
    const res = await h.as('admin').post('/v1/invoices', { customer: 'x'.repeat(70_000), lines: [] });
    expect(res.status).toBe(413);
  });

  it('answers unknown routes with a problem document', async () => {
    const res = await h.as('admin').get('/v1/admin/users');
    expect(res.status).toBe(404);
    expect(res.body).toMatchObject({ title: 'Not Found', status: 404 });
  });
});
