// Actual local HTTP tests of the controlled provider's versioned store.
// SigV4 and Worker/SQL admission belong to the separate connected runtime gate.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { VersionedObjects } from "./aos-hub-external-oci-provider.mjs";

async function fixture(action) {
  const store = new VersionedObjects("managed/binding/fixture");
  const records = [];
  let dropPositive = false;
  const server = createServer((request, response) => {
    const url = new URL(request.url, "http://fixture.invalid");
    const key = url.pathname.slice(1);
    assert.equal(request.method, "DELETE");
    const result = store.conditionalDelete(key, url.searchParams.get("versionId"), request.headers["if-match"]);
    records.push({ method:request.method, status:result.status, deleted:result.deleted });
    if (result.deleted) {
      response.setHeader("x-amz-version-id", result.object.version);
      if (dropPositive) { dropPositive = false; response.destroy(); return; }
    }
    response.statusCode = result.status; response.end();
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const remove = (key, version, etag) => fetch(`${origin}/${key}${version ? `?versionId=${version}` : ""}`, {
    method:"DELETE", headers:etag ? {"if-match":etag} : {}, redirect:"manual",
  });
  try { await action({store,records,remove,drop:() => { dropPositive = true; }}); }
  finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}

const key = "managed/binding/fixture/oci/private/upload/chunk";

test("actual stored version and strong tag are both required before deletion", async () => {
  await fixture(async ({store,records,remove}) => {
    const first = store.put(key,Buffer.from("first actual bytes"));
    const second = store.put(key,Buffer.from("second actual bytes"));
    assert.notEqual(first.version,second.version);
    assert.notEqual(first.etag,second.etag);
    assert.equal((await remove(key,"missing-version",second.etag)).status,412);
    assert.equal((await remove(key,second.version,first.etag)).status,412);
    assert.equal((await remove(key,undefined,second.etag)).status,403);
    assert.equal((await remove(key,second.version,undefined)).status,403);
    assert.equal(store.get(key),second);
    assert(records.every(record => !record.deleted));
    const exact = await remove(key,second.version,second.etag);
    assert.equal(exact.status,204);
    assert.equal(exact.headers.get("x-amz-version-id"),second.version);
    assert.equal(store.get(key),first,"deleting the actual current version exposes its retained predecessor");
    assert.equal(store.get(key,second.version),undefined);
    assert.equal((await remove(key,first.version,first.etag)).status,204);
    assert.equal(store.get(key),undefined);
    assert.equal(records.filter(record => record.deleted).length,2);
  });
});

test("lost acknowledgement records actual deletion without inventing a positive receipt", async () => {
  await fixture(async ({store,records,remove,drop}) => {
    const selected = store.put(key,Buffer.from("unique cancelled original"));
    drop();
    await assert.rejects(remove(key,selected.version,selected.etag));
    assert.equal(store.get(key,selected.version),undefined);
    assert.deepEqual(records,[{method:"DELETE",status:204,deleted:true}]);
    // This is the provider's state only. A disconnected caller has no positive
    // acknowledgement and must not turn later absence into a guard receipt.
  });
});

test("stored history is bounded and confined to OCI or service capability probes", () => {
  const store = new VersionedObjects("managed/binding/fixture");
  assert.throws(() => store.put("managed/binding/another/oci/private/x",Buffer.from("x")));
  assert.throws(() => store.put(key,Buffer.alloc(20*1024*1024+1)));
  assert.throws(() => store.conditionalDelete("other/key","v",'"tag"'));
  const input = Buffer.from("actual immutable input");
  const selected = store.put(key,input);
  input[0] ^= 0xff;
  assert.equal(selected.bytes.toString(),"actual immutable input");
  assert.deepEqual(store.keys(),[key]);
});
