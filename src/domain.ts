/** Permissions follow the Auth0 RBAC convention: "<action>:<resource>". */
export const PERMISSIONS = [
  'read:invoices',
  'write:invoices',
  'void:invoices',
  'read:audit',
  'impersonate:tenants',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

export const ROLES: Record<string, Permission[]> = {
  billing_admin: ['read:invoices', 'write:invoices', 'void:invoices', 'read:audit'],
  billing_clerk: ['read:invoices', 'write:invoices'],
  viewer: ['read:invoices'],
  support_agent: ['impersonate:tenants', 'read:invoices'],
};

export interface User {
  email: string;
  name: string;
  tenant: string;
  role: keyof typeof ROLES;
}

/** Demo-only identities for this local lab. The mock IdP accepts DEMO_PASSWORD for all of them. */
export const DEMO_PASSWORD = 'Demo-Passw0rd!';
export const USERS: User[] = [
  { email: 'alice@northwind.test', name: 'Alice Admin', tenant: 'northwind', role: 'billing_admin' },
  { email: 'bob@northwind.test', name: 'Bob Clerk', tenant: 'northwind', role: 'billing_clerk' },
  { email: 'carol@northwind.test', name: 'Carol Viewer', tenant: 'northwind', role: 'viewer' },
  { email: 'dan@contoso.test', name: 'Dan Admin', tenant: 'contoso', role: 'billing_admin' },
  { email: 'sam@support.test', name: 'Sam Support', tenant: 'internal', role: 'support_agent' },
];
export const TENANTS = ['northwind', 'contoso'] as const;

export interface InvoiceLine {
  description: string;
  quantity: number;
  unitPriceCents: number;
}

export type InvoiceStatus = 'open' | 'paid' | 'void';

export interface Invoice {
  id: string;
  tenantId: string;
  number: string;
  customer: string;
  currency: 'USD';
  lines: InvoiceLine[];
  taxRateBps: number;
  subtotalCents: number;
  taxCents: number;
  totalCents: number;
  status: InvoiceStatus;
  createdBy: string;
  createdAt: string;
  /** Internal only. Must never leave the API (excessive data exposure). */
  internalNotes?: string;
}

export interface AuditEvent {
  id: string;
  at: string;
  tenant: string;
  actor: string;
  actorTenant: string;
  impersonated: boolean;
  action: string;
  resource: string;
}

/**
 * Money is integer cents. Tax uses round-half-up on the exact product, so a subtotal of 1050
 * at 5% (500 bps) is 52.5 -> 53 cents. Totals are always computed by the server.
 */
export function computeTotals(lines: InvoiceLine[], taxRateBps: number) {
  const subtotalCents = lines.reduce((sum, l) => sum + l.quantity * l.unitPriceCents, 0);
  const taxCents = Math.floor((subtotalCents * taxRateBps + 5000) / 10000);
  return { subtotalCents, taxCents, totalCents: subtotalCents + taxCents };
}
