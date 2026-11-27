// Look-alikes from real repositories: none of these is a flow.
import Router from "@koa/router";
import { Controller, Get, Post, Req, Res, Body } from "@nestjs/common";
import fs from "fs";

const router = new Router();
const API_URL = "https://api.example.com";

// outline: the host compared to a constant first
export function apexRedirect() {
  return async function apexRedirectMiddleware(ctx: any, next: any) {
    if (ctx.headers.host === "getoutline.com") {
      ctx.redirect(`https://www.${ctx.headers.host}${ctx.path}`);
    }
    return next();
  };
}

// outline: two handlers in one file don't share variables
router.post("documents.import", async (ctx: any) => {
  const file = ctx.request.files.file;
  await fs.readFile(file.filepath);
});
router.post("documents.other", async (ctx: any) => {
  const file = ctx.request.body.name;
  ctx.body = { file };
});

// outline: a record looked up with request data is the database's, not the request's
router.get("shares.info", async (ctx: any) => {
  const share = await loadPublicShare({ id: ctx.params.shareId });
  ctx.redirect(share.canonicalUrl);
  const team = await getTeamFromContext(ctx);
  ctx.redirect(team.url);
});

// directus: a service's answer, a relative redirect, request data only in the query string
router.post("/logout", async (ctx: any) => {
  const { context } = sp.createLogoutRequest(idp, "redirect", ctx.request.body);
  ctx.redirect(context);
  ctx.redirect(`./callback?${new URLSearchParams(ctx.request.body)}`);
  const layout = ctx.query.layout;
  ctx.redirect(`${destination}/embed?layout=${layout}`);
});

// cal.com: a path on a fixed base; tldraw: a fixed base from a constant
router.get("/booking", async (ctx: any) => {
  const uid = ctx.query.uid;
  ctx.redirect(new URL(`/booking/${uid}`, WEBAPP_URL).toString());
  await fetch(`${API_URL}/bookings/${uid}`);
  await fetch(`${process.env.SYNC_URL}/rooms/${uid}`);
});

// a value checked by a validator before use, and a validator's result
router.get("/go", async (ctx: any) => {
  const next = ctx.query.next;
  if (!isSafeRedirect(next)) throw new Error("bad");
  ctx.redirect(next);
  const host = await getValidatedHost(ctx.query.host);
  ctx.redirect(`https://${host}/home`);
});

@Controller("oauth")
export class OAuthController {
  @Post("authorize")
  async authorize(@Body() body: AuthorizeDto, @Res() res: any) {
    if (!isOriginAllowed(body.redirectUri, allowed)) {
      throw new Error("Invalid 'redirect_uri' value.");
    }
    return res.redirect(`${body.redirectUri}?code=1`);
  }

  // immich: @Req() as a whole isn't request data; its url path stays on this site
  @Get(":id/thumbnail")
  async view(@Req() req: any, @Res() res: any) {
    const [path] = req.url.split("?", 2);
    return res.redirect(path);
  }
}

// client code: `context` is not a request
export async function makeRequest(context: { headers: Record<string, string> }, url: string) {
  return fetch(context.headers.base);
}

// directus: a redirect target passed back through a checker that throws on a bad one
router.post("/acs", async (ctx: any) => {
  let redirect = ctx.request.body?.RelayState;
  if (redirect) {
    redirect = resolveLoginRedirect(redirect, { provider: "saml" });
  }
  ctx.redirect(redirect);
});

// tldraw: the host is checked first; what follows it is only its path
router.get("/:origin/:path+", async (ctx: any) => {
  const { origin, path } = ctx.params;
  if (!isValidOrigin(origin)) return;
  await fetch(new URL(`${protocol}://${origin}/${path}`));
});

// a function taking `{ ctx, input }` outside tRPC: a build step's own options, not a client's
export function transform({ ctx, input }: { ctx: any; input: string }) {
  return fs.readFileSync(input);
}
