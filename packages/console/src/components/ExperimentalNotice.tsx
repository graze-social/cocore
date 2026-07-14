// Shared "this is experimental and not proven" surfacing for the security
// features whose copy has repeatedly over-promised: the confidential tier,
// hardware attestation, and the credit/token exchange.
//
// The canonical wording lives HERE so every surface says the same thing. When
// the guarantee actually becomes proven/audited, we soften the language in one
// place. Rule of thumb for callers: describe what a mechanism *aims* to do,
// never assert that it *holds* — pair any confidentiality/attestation/credit
// claim with an <ExperimentalNotice>.

import { Alert, type AlertVariant } from "@/design-system/alert";

export type ExperimentalTopic = "confidentiality" | "attestation" | "tokens";

/** One source of truth for the disclaimer copy. Calm and factual — an honest
 *  status note, not an alarm. The aim is that a reader comes away knowing the
 *  feature is a work in progress they shouldn't lean on for anything sensitive,
 *  without feeling shouted at. */
const EXPERIMENTAL_COPY: Record<ExperimentalTopic, { title: string; body: string }> = {
  confidentiality: {
    title: "Confidential mode is experimental",
    body: "It aims to keep your prompt unreadable to the machine's operator: a trusted brokerage routes your job to genuine Apple hardware running a known build under a hardened runtime, with the agent's signing and prompt-decryption keys held in the Secure Enclave so the operator can't copy them to another machine, and the receipt is countersigned to prove that machine served it. But it's a raised bar, not a hardware guarantee — Apple Silicon has a secure enclave for keys but not for general compute, so a compromised OS kernel or someone with physical access to the machine could still read your prompt while it's being processed. Don't send anything you'd need cryptographically kept private.",
  },
  attestation: {
    title: "Attestation is experimental",
    body: "Hardware attestation is a best-effort signal that a machine is genuine Apple hardware running a known build, now bound to a Secure-Enclave key the operator can't lift off the machine. It still doesn't prove the hardware itself is uncompromised — a kernel exploit or physical access is out of scope — so treat it as a strong hint, not a guarantee.",
  },
  tokens: {
    title: "Credits and settlement are experimental",
    body: "Token metering, settlement, and payouts are still being proven out and can be incorrect, delayed, or lost. Credits aren't money — don't treat a balance as something you can count on.",
  },
};

/** Block-level note for a page/section that leans on one of these features.
 *  Defaults to a calm `info` tone; a surface where the caveat is genuinely
 *  load-bearing (e.g. an opt-in confirmation) can pass `variant="warning"`.
 *  `children` appends extra context. */
export function ExperimentalNotice({
  topic,
  variant = "info",
  children,
  ...rest
}: {
  topic: ExperimentalTopic;
  variant?: AlertVariant;
  children?: React.ReactNode;
} & Omit<React.ComponentProps<"div">, "title">): React.ReactNode {
  const { title, body } = EXPERIMENTAL_COPY[topic];
  // Container props (spacing, etc.) go on a plain wrapper div — the DS Alert
  // only accepts stylex styles, not raw layout props.
  return (
    <div {...rest}>
      <Alert variant={variant} title={title}>
        {body}
        {children}
      </Alert>
    </div>
  );
}
