// Shared @effect/platform HTTP toolkit for cocore's Node services.
//
// Services author routes as an `HttpRouter` (handlers are Effects returning
// `HttpServerResponse`) and turn the app into a traced Node request listener
// with `makeNodeHandler`, or launch it on an ephemeral port for a callback
// with `withServer`. Either
// way a span per request is emitted to the service's o11y runtime and
// exported to Honeycomb when OTLP is configured (a no-op otherwise).
//
// `makeNodeHandler` builds the listener on a long-lived o11y runtime (so the
// scoped OTel tracer stays open) and returns a plain `(req,res) => void` — it
// can back multiple ports / be embedded in a non-Effect server without that
// caller depending on Effect directly.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { HttpRouter, HttpServer, HttpServerRequest, HttpServerResponse } from "@effect/platform";
import { NodeHttpServer } from "@effect/platform-node";
import { Effect, Layer } from "effect";

import { makeRuntime } from "./runtime.ts";
import { otlpEnabled, sdkLayer, type O11yConfig } from "./tracing.ts";

/** Parse the request's query string into `URLSearchParams`. */
export const searchParams = Effect.map(
  HttpServerRequest.HttpServerRequest,
  (req) => new URL(req.url, "http://localhost").searchParams,
);

/** Hard cap on a JSON request body. Bounds the in-memory buffer a single POST
 *  can force before we parse it — without this, an unauthenticated route (e.g.
 *  the bridge mirror) lets a caller push an arbitrarily large body into memory.
 *  Override with COCORE_MAX_JSON_BODY_BYTES. */
const MAX_JSON_BODY_BYTES = Number(process.env["COCORE_MAX_JSON_BODY_BYTES"] ?? 1024 * 1024);

/** Read + JSON-parse the request body. Empty body → `{}`. Rejects a body whose
 *  declared `content-length` or actual size exceeds {@link MAX_JSON_BODY_BYTES}
 *  before parsing. Fails catchably (not as a defect) with
 *  `Error("body must be JSON")` on malformed JSON (or `Error("body too large")`
 *  on an oversized body). */
export const jsonBody: Effect.Effect<unknown, Error, HttpServerRequest.HttpServerRequest> =
  HttpServerRequest.HttpServerRequest.pipe(
    Effect.flatMap((req) => {
      const cl = req.headers["content-length"];
      const declared = typeof cl === "string" ? Number(cl) : Number.NaN;
      if (Number.isFinite(declared) && declared > MAX_JSON_BODY_BYTES) {
        return Effect.fail(new Error("body too large"));
      }
      return req.text;
    }),
    Effect.flatMap((raw) => {
      if (Buffer.byteLength(raw, "utf8") > MAX_JSON_BODY_BYTES) {
        return Effect.fail(new Error("body too large"));
      }
      return raw.trim().length === 0
        ? Effect.succeed({} as unknown)
        : Effect.try({
            try: () => JSON.parse(raw) as unknown,
            catch: () => new Error("body must be JSON"),
          });
    }),
    Effect.catchAll((e) =>
      Effect.fail(e instanceof Error && e.message === "body too large" ? e : new Error("body must be JSON")),
    ),
  );

/** A request header value, or undefined. */
export const header = (name: string) =>
  Effect.map(HttpServerRequest.HttpServerRequest, (req) => req.headers[name.toLowerCase()]);

/** The bearer token from the Authorization header, or null. */
export const bearer = Effect.map(HttpServerRequest.HttpServerRequest, (req) => {
  const h = req.headers["authorization"];
  if (typeof h !== "string") return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1]!.trim() : null;
});

/** 200 JSON response (synchronous — keeps route error channels clean). */
export const ok = (data: unknown): HttpServerResponse.HttpServerResponse =>
  HttpServerResponse.text(JSON.stringify(data), { contentType: "application/json" });

/** JSON response with an explicit status. Shape `{ error, ... }` by convention. */
export const err = (
  status: number,
  body: Record<string, unknown>,
): HttpServerResponse.HttpServerResponse =>
  HttpServerResponse.text(JSON.stringify(body), { contentType: "application/json", status });

/** The tracing layer for a service — NodeSdk when OTLP is configured, else
 *  an empty (no-op) layer. */
function tracingLayer(config: O11yConfig): Layer.Layer<never> {
  return otlpEnabled() ? (sdkLayer(config) as unknown as Layer.Layer<never>) : Layer.empty;
}

/** Build a traced Node request listener from an `HttpRouter` app. The app is
 *  served behind `makeHandler` on a long-lived o11y runtime; the returned
 *  listener responds to every request (404 for unmatched routes). */
export function makeNodeHandler(
  app: HttpRouter.HttpRouter<never, never>,
  config: O11yConfig,
): Promise<(req: IncomingMessage, res: ServerResponse) => void> {
  const runtime = makeRuntime(config);
  return runtime.runPromise(
    NodeHttpServer.makeHandler(app).pipe(Effect.provide(NodeHttpServer.layerContext)),
  );
}

/** Launch `app` on an ephemeral port, hand the base URL to `fn`, then tear
 *  the server down. For tests + one-shot embedding. */
export function withServer<A>(
  app: HttpRouter.HttpRouter<never, never>,
  config: O11yConfig,
  fn: (baseUrl: string) => Promise<A>,
): Promise<A> {
  return Effect.gen(function* () {
    const server = yield* HttpServer.HttpServer;
    const address = server.address;
    const port = address._tag === "TcpAddress" ? address.port : 0;
    return yield* Effect.promise(() => fn(`http://127.0.0.1:${port}`));
  }).pipe(
    Effect.provide(HttpServer.serve(app)),
    Effect.provide(NodeHttpServer.layer(() => createServer(), { port: 0 })),
    Effect.provide(tracingLayer(config)),
    Effect.scoped,
    Effect.runPromise,
  );
}
