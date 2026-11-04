import { Router } from 'express';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyLike } from 'jose';
import { DEMO_PASSWORD, ROLES, USERS } from './domain';

export const ISSUER = 'https://idp.billing.test/';
export const AUDIENCE = 'https://api.billing.test';
const TOKEN_TTL_SECONDS = 15 * 60;

export interface IdentityProvider {
  issuer: string;
  audience: string;
  kid: string;
  jwks: { keys: JWK[] };
  privateKey: KeyLike;
  publicKey: KeyLike;
  /** Issues a token for a known user, the way /oauth/token does. */
  issueFor(email: string): Promise<string>;
  router: Router;
}

/**
 * A tiny Auth0-like identity provider: RS256 keys, a JWKS endpoint, a password grant, and
 * access tokens carrying `org_id` (tenant) and `permissions` claims. Keys are generated per
 * instance, so nothing secret is ever committed.
 */
export async function createIdentityProvider(): Promise<IdentityProvider> {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const kid = `key-${Date.now().toString(36)}`;
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };

  async function issueFor(email: string): Promise<string> {
    const user = USERS.find((u) => u.email === email);
    if (!user) throw new Error(`unknown user ${email}`);
    return new SignJWT({ org_id: user.tenant, permissions: ROLES[user.role], name: user.name })
      .setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject(user.email)
      .setIssuedAt()
      .setExpirationTime(`${TOKEN_TTL_SECONDS}s`)
      .sign(privateKey);
  }

  const router = Router();
  router.get('/.well-known/jwks.json', (_req, res) => {
    res.json({ keys: [jwk] });
  });
  router.post('/oauth/token', async (req, res) => {
    const { grant_type, username, password, audience } = req.body ?? {};
    if (grant_type !== 'password') {
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
    }
    if (audience !== AUDIENCE) {
      res.status(400).json({ error: 'invalid_request', error_description: 'unknown audience' });
      return;
    }
    if (!USERS.some((u) => u.email === username) || password !== DEMO_PASSWORD) {
      res.status(403).json({ error: 'invalid_grant', error_description: 'Wrong email or password.' });
      return;
    }
    res.json({ access_token: await issueFor(username), token_type: 'Bearer', expires_in: TOKEN_TTL_SECONDS });
  });

  return { issuer: ISSUER, audience: AUDIENCE, kid, jwks: { keys: [jwk] }, privateKey, publicKey, issueFor, router };
}
