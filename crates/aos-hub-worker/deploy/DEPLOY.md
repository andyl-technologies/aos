# Deploy the AOS Hub Worker

Use the [AOS Hub Cloudflare deployment
guide](../../../docs/users/aos-hub/cloudflare.md).

The supported path is the `pkg-aos-hub-cloudflare` package and `aos-hub worker`
installer. It deploys the bundled Worker artifact, creates the current R2, KV,
and Queue resources, configures Durable Objects and scheduled work, preserves
secrets on routine updates, and bootstraps the instance owner.

The scripts and checked-in provider configuration in this crate are
development fixtures. They are not an alternative production deployment path.
