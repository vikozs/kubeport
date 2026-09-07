# Deploying kubeport.kosir.info

The site is one static page in `site/` (plus `_headers`). It is built for Cloudflare Pages on the free plan.

## First deploy

1. Cloudflare dashboard: Workers & Pages, Create, Pages, **Connect to Git**, pick `kubeport/kubeport`.
2. Build settings: framework preset **None**, build command *(empty)*, build output directory `site`.
3. Deploy. You get `kubeport.pages.dev`.
4. **Custom domains**: add `kubeport.kosir.info`. Because `kosir.info` is already on Cloudflare, the CNAME (`kubeport` to `kubeport.pages.dev`) is created for you; otherwise add it by hand, proxied.

## From the command line

```
npm i -g wrangler
wrangler login
wrangler pages project create kubeport --production-branch main
wrangler pages deploy site --project-name kubeport
```

PowerShell users: the same commands work as written.

## Updating

Every push to `main` that touches `site/` redeploys. The terminal transcript in the hero is real output of `kubeport check` on `fixtures/k3s-app`; regenerate it after changing rules so the page never lies:

```
NO_COLOR=1 bin/kubeport check --from k3s:1.31 --to openshift:4.19/vsphere fixtures/k3s-app
```
