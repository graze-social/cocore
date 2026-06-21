// AppView HTTP wiring — a thin skin over the shared @cocore/o11y/http
// toolkit so the AppView, infra/services, and the advisor all build routes
// the same idiomatic way (HttpRouter handlers returning HttpServerResponse,
// traced per request). The request helpers are re-exported verbatim; only
// the service name ("cocore-appview") is bound here.

import type { HttpRouter } from "@effect/platform";
import { makeNodeHandler, withServer } from "@cocore/o11y/http";
import type { IncomingMessage, ServerResponse } from "node:http";

export { bearer, err, header, jsonBody, ok, searchParams } from "@cocore/o11y/http";

const SERVICE = { serviceName: "cocore-appview" };

/** Launch the app on an ephemeral port for a single callback (tests). */
export const withAppviewServer = <A>(
  app: HttpRouter.HttpRouter<never, never>,
  fn: (baseUrl: string) => Promise<A>,
): Promise<A> => withServer(app, SERVICE, fn);

/** Traced Node request listener for the AppView app. */
export const appviewNodeHandler = (
  app: HttpRouter.HttpRouter<never, never>,
): Promise<(req: IncomingMessage, res: ServerResponse) => void> => makeNodeHandler(app, SERVICE);
