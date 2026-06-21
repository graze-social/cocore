export type CommunityTool = {
  id: string;
  name: string;
  description: string;
  repoUrl: string;
  install?: string;
  setup?: Array<string>;
  tags: Array<string>;
};

export const COMMUNITY_TOOLS_CATALOG: Array<CommunityTool> = [
  {
    id: "pi-cocore",
    name: "pi-cocore",
    description:
      "A Pi extension that adds co/core as a model provider. Run open-source models on Apple Silicon via co/core — directly inside pi.",
    repoUrl: "https://github.com/willnewby/pi-cocore",
    install: "pi install git:github.com/willnewby/pi-cocore",
    setup: [
      "Get your API key from console.cocore.dev.",
      "Start pi — on first run you'll be prompted for the key.",
      "Or run /cocore-setup at any time to configure or change your key.",
    ],
    tags: ["pi", "Apple Silicon", "extension"],
  },
  {
    id: "cocore-local-gateway",
    name: "cocore-local-gateway",
    description:
      "Exposes locally-running MLX models from a co/core agent as an OpenAI-compatible API endpoint over TCP — bridging the agent's Unix sockets to localhost and overlay networks (ZeroTier, Tailscale) without routing through the co/core network.",
    repoUrl: "https://github.com/tenorune/cocore-local-gateway",
    install:
      "git clone https://github.com/tenorune/cocore-local-gateway\ncd cocore-local-gateway\ncp .env.example .env\n./install.sh",
    setup: [
      "Configure .env with the port, bind interfaces, and socket directory.",
      "Run install.sh to load it as a LaunchAgent (auto-starts on macOS).",
      "Verify with: curl -s http://127.0.0.1:1234/v1/models | python3 -m json.tool",
      "Point your OpenAI-compatible clients (OpenCode, pi, OFF GRID) at the gateway endpoint.",
    ],
    tags: ["OpenAI API", "MLX", "gateway", "macOS"],
  },
];
