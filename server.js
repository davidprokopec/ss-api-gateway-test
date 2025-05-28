import Koa from "koa";
import Router from "@koa/router";
import koaBodyImport from "koa-body";
import { createHmac } from "crypto";

const koaBody = koaBodyImport.default || koaBodyImport;

const UNPARSED_BODY = Symbol.for("unparsedBody");
const secret = "1cc41027be86568febfe0121304a5e87f5e055ee";
const app = new Koa();
const router = new Router();

function generateHmac(secret, body) {
  return createHmac("sha256", secret).update(body).digest("hex");
}

router.use(
  koaBody({
    includeUnparsed: true,
  }),
);

router.use((ctx, next) => {
  const hmacHeader = ctx.headers["x-smartsupp-hmac"];
  const bodyHeader = ctx.headers["x-debug-body"];
  const rawBody = ctx.request.body[UNPARSED_BODY];
  const bodyHex = Buffer.from(rawBody, "utf8").toString("hex");

  const expected_hmac = generateHmac(secret, rawBody);
  if (hmacHeader !== expected_hmac) {
    console.log(
      `Invalid HMAC signature: hmac_header=${hmacHeader}, expected_hmac_sig=${expected_hmac} body=${rawBody}, bodyHex=${bodyHex}, bodyHeader=${bodyHeader}`,
    );
    ctx.throw(403, "Invalid request hmac signature");
  }
  return next();
});

router.post("/webhook", (ctx) => {
  const raw = ctx.request.body[UNPARSED_BODY];
  if (typeof raw !== "string") ctx.throw(400, "Missing raw body");
  ctx.body = { hex: Buffer.from(raw, "utf8").toString("hex") };
});

app.use(router.routes()).use(router.allowedMethods());
app.listen(3000, () => console.log("Listening on http://localhost:3000"));
