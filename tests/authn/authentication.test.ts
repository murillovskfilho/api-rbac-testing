import { DEMO_PASSWORD } from '../../src/domain';
import { forgedTokens } from '../support/forged-tokens';
import { createHarness, type Harness } from '../support/harness';

let h: Harness;
let attacks: Record<string, string>;

beforeAll(async () => {
  h = await createHarness();
  attacks = await forgedTokens(h.idp);
});

describe('Authentication (JWT RS256 via JWKS)', () => {
  it('accepts a token obtained through the identity provider', async () => {
    const tokenRes = await h
      .anonymous()
      .post('/idp/oauth/token')
      .send({ grant_type: 'password', username: 'carol@northwind.test', password: DEMO_PASSWORD, audience: h.idp.audience });
    expect(tokenRes.status).toBe(200);
    expect(tokenRes.body).toMatchObject({ token_type: 'Bearer', expires_in: 900 });

    const res = await h.withToken(tokenRes.body.access_token).get('/v1/invoices');

    expect(res.status).toBe(200);
    expect(res).toSatisfyApiSpec();
  });

  it.each([
    ['wrong password', { grant_type: 'password', username: 'carol@northwind.test', password: 'nope' }, 403, 'invalid_grant'],
    ['unknown user', { grant_type: 'password', username: 'eve@evil.test', password: DEMO_PASSWORD }, 403, 'invalid_grant'],
    ['unsupported grant', { grant_type: 'client_credentials' }, 400, 'unsupported_grant_type'],
  ])('the token endpoint refuses %s', async (_case, body, status, error) => {
    const res = await h.anonymous().post('/idp/oauth/token').send({ audience: 'https://api.billing.test', ...body });

    expect(res.status).toBe(status);
    expect(res.body.error).toBe(error);
    expect(res.body.access_token).toBeUndefined();
  });

  it('does not reveal whether a user exists', async () => {
    const send = (username: string) =>
      h.anonymous().post('/idp/oauth/token').send({ grant_type: 'password', username, password: 'wrong', audience: h.idp.audience });

    const [known, unknown] = await Promise.all([send('carol@northwind.test'), send('eve@evil.test')]);

    expect(known.status).toBe(unknown.status);
    expect(known.body).toEqual(unknown.body);
  });

  it('publishes only public key material in the JWKS', async () => {
    const res = await h.anonymous().get('/idp/.well-known/jwks.json');

    expect(res.status).toBe(200);
    expect(res.body.keys).toHaveLength(1);
    const [key] = res.body.keys;
    expect(key).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig', kid: h.idp.kid });
    for (const privatePart of ['d', 'p', 'q', 'dp', 'dq', 'qi']) expect(key).not.toHaveProperty(privatePart);
  });

  describe('refuses with 401', () => {
    it.each([
      ['no Authorization header', undefined],
      ['a Basic scheme', 'Basic YWxpY2U6c2VjcmV0'],
      ['an empty bearer token', 'Bearer '],
    ])('%s', async (_case, header) => {
      const req = h.anonymous().get('/v1/invoices');
      const res = await (header ? req.set('Authorization', header) : req);

      expect(res.status).toBe(401);
      expect(res.headers['www-authenticate']).toMatch(/^Bearer /);
      expect(res).toSatisfyApiSpec();
    });

    // One test per forged token: expired, wrong iss/aud, alg none, HS256 confusion, tampering, ...
    it.each([
      'expired token',
      'token not valid yet (nbf in the future)',
      'wrong issuer',
      'wrong audience',
      'signed by an unknown key with a known kid',
      'unknown kid',
      'alg "none" (unsigned)',
      'HS256 signed with the public key (algorithm confusion)',
      'payload edited after signing (privilege escalation)',
      'missing org_id claim',
      'permissions claim is not an array',
      'not a JWT at all',
    ])('%s', async (attack) => {
      const res = await h.withToken(attacks[attack]).get('/v1/invoices');

      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({ title: 'Unauthorized', status: 401 });
      expect(res.body).not.toHaveProperty('data');
      expect(res).toSatisfyApiSpec();
    });
  });

  it('covers every forged token it generates', () => {
    // Guard against adding an attack to the generator and forgetting to test it.
    expect(Object.keys(attacks)).toHaveLength(12);
  });
});
