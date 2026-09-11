import { createFileRoute } from "@tanstack/react-router";
import { devicePairStartResponse } from "@/lib/console-xrpc-http.server.ts";

export const Route = createFileRoute("/api/xrpc/dev.cocore.devicePair.start")({
  server: {
    handlers: {
      POST: async ({ request }) => devicePairStartResponse(request),
    },
  },
});
