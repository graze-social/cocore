import { createFileRoute } from "@tanstack/react-router";
import { devicePairDescribeResponse } from "@/lib/console-xrpc-http.server.ts";

export const Route = createFileRoute("/api/xrpc/dev.cocore.devicePair.describe")({
  server: {
    handlers: {
      GET: async ({ request }) => devicePairDescribeResponse(request),
    },
  },
});
