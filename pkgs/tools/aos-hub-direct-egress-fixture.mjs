export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/bytes") {
      if (request.method !== "GET"
          || request.headers.get("range") !== "bytes=1-3"
          || request.headers.get("authorization") !== "Bearer e2e-token") {
        return new Response("closed request headers drifted", { status: 400 });
      }
      return new Response("bcd", { status: 206 });
    }
    if (url.pathname === "/head") {
      return new Response(null, { status: 200, headers: { "x-egress-fixture": "head" } });
    }
    if (url.pathname === "/redirect-same") {
      return Response.redirect("https://egress.test/redirect-final", 302);
    }
    if (url.pathname === "/redirect-final") {
      return new Response("redirect-ok");
    }
    if (url.pathname === "/redirect-cross") {
      return Response.redirect("https://other.test/redirect-final", 302);
    }
    if (url.pathname === "/redirect-mutating") {
      return Response.redirect("https://egress.test/redirect-final", 307);
    }
    if (url.pathname === "/redirect-downgrade") {
      return Response.redirect("http://egress.test/redirect-final", 302);
    }
    if (url.pathname === "/webhook") {
      const body = await request.text();
      if (request.method !== "POST"
          || request.headers.get("content-type") !== "application/json"
          || request.headers.get("x-aos-event") !== "release.published"
          || request.headers.get("x-aos-signature") !== "sha256=e2e"
          || request.headers.get("x-aos-delivery-id") !== "delivery-e2e"
          || body !== '{"ok":true}') {
        return new Response("webhook contract drifted", { status: 400 });
      }
      return new Response(null, { status: 204 });
    }
    return new Response("unexpected direct-egress request", { status: 404 });
  },
};
