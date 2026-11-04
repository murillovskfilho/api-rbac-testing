import { exportSPKI, generateKeyPair, SignJWT, type JWTPayload } from 'jose';
import type { IdentityProvider } from '../../src/idp';

const b64url = (value: object | string) =>
  Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** A legitimate-looking payload for a northwind admin, to be bent by each attack. */
export const basePayload = (): JWTPayload & Record<string, unknown> => ({
  sub: 'alice@northwind.test',
  org_id: 'northwind',
  permissions: ['read:invoices', 'write:invoices', 'void:invoices', 'read:audit'],
});

/**
 * Builds the tokens an attacker (or a misconfigured client) would send. Each one must be refused
 * with 401. They are generated, never hard-coded, so they always target this run's keys.
 */
export async function forgedTokens(idp: IdentityProvider): Promise<Record<string, string>> {
  const sign = (payload: JWTPayload, opts: { expiresIn?: string | number; issuer?: string; audience?: string; notBefore?: number } = {}) => {
    const jwt = new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: idp.kid })
      .setIssuer(opts.issuer ?? idp.issuer)
      .setAudience(opts.audience ?? idp.audience)
      .setIssuedAt();
    if (opts.notBefore !== undefined) jwt.setNotBefore(opts.notBefore);
    jwt.setExpirationTime(opts.expiresIn ?? '5m');
    return jwt.sign(idp.privateKey);
  };

  const attacker = await generateKeyPair('RS256');
  const valid = await sign(basePayload());
  const [header, , signature] = valid.split('.');

  // Algorithm confusion: HS256 "signed" with the server's *public* key as the HMAC secret.
  const publicPem = await exportSPKI(idp.publicKey);
  const hsToken = await new SignJWT(basePayload())
    .setProtectedHeader({ alg: 'HS256', kid: idp.kid })
    .setIssuer(idp.issuer)
    .setAudience(idp.audience)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(new TextEncoder().encode(publicPem));

  const unsignedPayload = { ...basePayload(), iss: idp.issuer, aud: idp.audience, exp: nowSeconds() + 300 };

  return {
    'expired token': await sign(basePayload(), { expiresIn: nowSeconds() - 60 }),
    'token not valid yet (nbf in the future)': await sign(basePayload(), { notBefore: nowSeconds() + 3600 }),
    'wrong issuer': await sign(basePayload(), { issuer: 'https://evil.example/' }),
    'wrong audience': await sign(basePayload(), { audience: 'https://another-api.test' }),
    'signed by an unknown key with a known kid': await new SignJWT(basePayload())
      .setProtectedHeader({ alg: 'RS256', kid: idp.kid })
      .setIssuer(idp.issuer)
      .setAudience(idp.audience)
      .setExpirationTime('5m')
      .sign(attacker.privateKey),
    'unknown kid': await new SignJWT(basePayload())
      .setProtectedHeader({ alg: 'RS256', kid: 'attacker-key' })
      .setIssuer(idp.issuer)
      .setAudience(idp.audience)
      .setExpirationTime('5m')
      .sign(attacker.privateKey),
    'alg "none" (unsigned)': `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url(unsignedPayload)}.`,
    'HS256 signed with the public key (algorithm confusion)': hsToken,
    'payload edited after signing (privilege escalation)': `${header}.${b64url({
      ...unsignedPayload,
      permissions: [...basePayload().permissions as string[], 'impersonate:tenants'],
    })}.${signature}`,
    'missing org_id claim': await sign({ sub: 'alice@northwind.test', permissions: ['read:invoices'] }),
    'permissions claim is not an array': await sign({ ...basePayload(), permissions: 'read:invoices' }),
    'not a JWT at all': 'definitely-not-a-jwt',
  };
}
