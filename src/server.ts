import { createApp } from './app';
import { createIdentityProvider } from './idp';

async function main(): Promise<void> {
  const idp = await createIdentityProvider();
  const port = Number(process.env.PORT ?? 4000);
  createApp(idp).listen(port, () => {
    console.log(`Billing API on http://localhost:${port} (IdP at /idp, API at /v1)`);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
