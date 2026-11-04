import request from 'supertest';
import type { Express } from 'express';
import { createApp } from '../../src/app';
import { createIdentityProvider, type IdentityProvider } from '../../src/idp';

/** Who the tests act as. One line per role, plus an admin of another tenant and a support agent. */
export const PERSONAS = {
  admin: 'alice@northwind.test', // billing_admin @ northwind
  clerk: 'bob@northwind.test', // billing_clerk @ northwind
  viewer: 'carol@northwind.test', // viewer @ northwind
  otherAdmin: 'dan@contoso.test', // billing_admin @ contoso
  support: 'sam@support.test', // support_agent @ internal (can impersonate, read-only)
} as const;
export type Persona = keyof typeof PERSONAS;

type Method = 'get' | 'post' | 'patch';
export interface Client {
  get(url: string): request.Test;
  post(url: string, body?: object): request.Test;
  patch(url: string, body?: object): request.Test;
  call(method: Method, url: string, body?: object): request.Test;
}

export interface Harness {
  app: Express;
  idp: IdentityProvider;
  as(persona: Persona): Client;
  withToken(token: string): Client;
  anonymous(): request.Agent;
  /** Creates an invoice as `persona` and returns its body (asserts 201). */
  createInvoice(persona: Persona, body?: object): Promise<InvoiceBody>;
  /** Ids of the invoices `persona` can see. */
  invoiceIds(persona: Persona): Promise<string[]>;
}

export interface InvoiceBody {
  id: string;
  number: string;
  status: string;
  customer: string;
  subtotalCents: number;
  taxCents: number;
  totalCents: number;
  [key: string]: unknown;
}

export const validInvoice = (overrides: object = {}) => ({
  customer: 'Northwind Traders',
  lines: [{ description: 'Freight', quantity: 2, unitPriceCents: 1250 }],
  taxRateBps: 800,
  ...overrides,
});

/**
 * A fresh app, identity provider and store per test file: no shared state, no ordering coupling.
 * Requests go in-process through supertest, so the suite needs no running server.
 */
export async function createHarness(): Promise<Harness> {
  const idp = await createIdentityProvider();
  const app = createApp(idp);
  const tokens = Object.fromEntries(
    await Promise.all(Object.entries(PERSONAS).map(async ([p, email]) => [p, await idp.issueFor(email)])),
  ) as Record<Persona, string>;

  const withToken = (token: string): Client => {
    const call = (method: Method, url: string, body?: object) => {
      const req = request(app)[method](url).set('Authorization', `Bearer ${token}`);
      return body === undefined ? req : req.send(body);
    };
    return {
      call,
      get: (url) => call('get', url),
      post: (url, body) => call('post', url, body),
      patch: (url, body) => call('patch', url, body),
    };
  };
  const as = (persona: Persona) => withToken(tokens[persona]);

  return {
    app,
    idp,
    as,
    withToken,
    anonymous: () => request.agent(app),
    async createInvoice(persona, body = validInvoice()) {
      const res = await as(persona).post('/v1/invoices', body);
      if (res.status !== 201) throw new Error(`create as ${persona} failed: ${res.status} ${JSON.stringify(res.body)}`);
      return res.body;
    },
    async invoiceIds(persona) {
      const res = await as(persona).get('/v1/invoices?limit=100');
      return res.body.data.map((i: { id: string }) => i.id);
    },
  };
}
