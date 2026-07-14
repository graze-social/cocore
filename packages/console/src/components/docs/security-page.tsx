"use client";

import * as stylex from "@stylexjs/stylex";
import { Link } from "@tanstack/react-router";

import { docsStyles } from "@/components/docs/docs-page.stylex.tsx";
import { ExperimentalNotice } from "@/components/ExperimentalNotice.tsx";

/**
 * Detailed explainer for the two — orthogonal — security postures a co/core
 * provider can hold: Secure Mode (hardware attestation) and the Confidential
 * tier (operator-blind inference). The provider app links here from its
 * Status → Security section.
 */
export function SecurityDocsPage() {
  return (
    <>
      <div {...stylex.props(docsStyles.masthead)}>
        <div {...stylex.props(docsStyles.kicker)}>Security</div>
        <h1 {...stylex.props(docsStyles.title)}>Secure Mode &amp; the Confidential tier</h1>
        <p {...stylex.props(docsStyles.dek)}>
          A co/core provider can carry two independent security postures. They answer different
          questions and are earned separately — you can have either, both, or neither. This page
          explains what each one <em>aims</em> to show, how it works, and what it means for the
          prompts you send (as a requestor) or serve (as an operator). Both are experimental and not
          independently audited yet — the note below says what that means in practice.
        </p>
      </div>

      <ExperimentalNotice topic="confidentiality" style={{ marginBottom: 16 }}>
        {" "}
        Hardware attestation, which the confidential tier builds on, is experimental in the same
        way: a best-effort signal, not a verified guarantee.
      </ExperimentalNotice>

      <div {...stylex.props(docsStyles.introProse)}>
        <h2 {...stylex.props(docsStyles.h2, docsStyles.h2First)}>The two are orthogonal</h2>
        <p {...stylex.props(docsStyles.prose)}>
          <strong>Secure Mode</strong> answers{" "}
          <em>“is this genuine, untampered Apple hardware?”</em> The{" "}
          <strong>Confidential tier</strong> answers{" "}
          <em>“can the machine&apos;s operator read the prompts a requestor sends it?”</em> One is
          about the integrity of the hardware; the other is about who can observe the data. A
          machine can attest its hardware and still run inference somewhere its operator can read,
          or aim to seal inference from its operator without an Apple hardware-root attestation.
          Neither posture is independently proven — treat both as experimental.
        </p>

        <h2 {...stylex.props(docsStyles.h2)}>
          Secure Mode — “this aims to show it&apos;s a real Mac”
        </h2>
        <p {...stylex.props(docsStyles.prose)}>
          Secure Mode enrolls the Mac with co/core&apos;s device management and obtains an Apple{" "}
          <strong>Managed Device Attestation</strong> certificate chain — an Apple-signed credential
          rooted in the device&apos;s Secure Enclave that is designed to show the silicon is
          genuine, the OS is intact, and System Integrity Protection is on. It sets the
          provider&apos;s trust level to <strong>hardware-attested</strong>. This is experimental:
          we don&apos;t treat the attestation as independently verified, and it may be wrong or
          worked around in ways we haven&apos;t ruled out.
        </p>
        <p {...stylex.props(docsStyles.prose)}>
          What it defends against: a spoofed or tampered provider — a VM pretending to be a Mac, or
          a machine with SIP disabled. What it does <em>not</em> say: anything about whether the
          operator can see your data. A genuine, hardware-attested Mac can still run inference in a
          process its operator reads. Secure Mode is optional and additive — turning it on never
          changes how the machine serves, only how strongly it can prove what it is.
        </p>

        <h2 {...stylex.props(docsStyles.h2)}>
          The Confidential tier — sealing prompts from the machine&apos;s operator
        </h2>
        <p {...stylex.props(docsStyles.prose)}>
          This is what the confidential tier <em>aims</em> to give a <strong>requestor</strong> —
          though it&apos;s experimental and unproven, so don&apos;t rely on it for anything you
          couldn&apos;t stand to have exposed. The goal: when you send a prompt to a confidential
          provider, the machine&apos;s own operator has <em>no ordinary, supported way</em> to read
          it. A best-effort provider runs inference in a helper process the operator controls and
          can freely observe. A confidential provider instead runs inference{" "}
          <strong>entirely inside the measured, signed co/core agent</strong> — the in-process
          engine, with no subprocess and no IPC to tap — so the plaintext stays inside the attested
          binary, under a hardened runtime with library validation and anti-debugging. The
          operator&apos;s everyday tools for looking inside a running program — reading another
          process&apos;s memory, attaching a debugger, swapping in a logging build — don&apos;t
          reach it.
        </p>
        <p {...stylex.props(docsStyles.prose)}>
          “Operator” here means the person running the provider machine. If you&apos;re an operator
          reading this in the app: confidential means that <em>you</em> have no ordinary way to read
          what requestors send you — and that&apos;s the point. It&apos;s what lets requestors trust
          your machine with sensitive work.
        </p>
        <p {...stylex.props(docsStyles.prose)}>
          How it&apos;s checked, so a requestor doesn&apos;t have to take the operator&apos;s word
          for it: the matchmaker challenges the running agent with an AMFI-gated push that only the
          genuine, team-signed binary can answer, and the binary&apos;s measured code identity (its
          code-directory hash) must be in the blessed-build set, under a hardened runtime with
          library validation and verified SIP. The agent&apos;s signing and prompt-decryption keys
          are held in the <strong>Secure Enclave</strong>, so they can&apos;t be lifted onto another
          host — the fix for the 2026-07-05 copy-the-key spoof, where a genuine Mac&apos;s software
          key was copied to a non-Apple box to serve &ldquo;confidential&rdquo; traffic. Only when
          all of that holds does the provider advertise the <strong>attested-confidential</strong>{" "}
          tier.
        </p>

        <h2 {...stylex.props(docsStyles.h2)}>What the confidential tier is — and isn&apos;t</h2>
        <p {...stylex.props(docsStyles.prose)}>
          Be precise about the <em>kind</em> of guarantee this is, because it&apos;s easy to
          overstate. The confidential tier is <strong>not</strong> a hardware trusted-execution
          environment (TEE) in the sense of Intel SGX, AMD SEV-SNP, or AWS Nitro Enclaves.
          Apple&apos;s Secure Enclave protects the device&apos;s signing keys and produces the
          attestation, but it does <strong>not</strong> run the model — your prompt and the model
          weights execute in ordinary macOS user space and on the GPU, like any other app.
        </p>
        <p {...stylex.props(docsStyles.prose)}>
          What seals them from the operator is the{" "}
          <strong>verified platform-security posture</strong>, not memory isolation in silicon: code
          signing, System Integrity Protection, the hardened runtime, library validation,
          anti-debugging, disabled core dumps, and the absence of any subprocess or IPC to tap.
          Under that posture the operator has no <em>ordinary</em> path to the plaintext — but the
          guarantee still rests on the OS and the signed-binary supply chain being intact. A
          vulnerability in macOS or in the agent, or a maliciously substituted signed build, could
          still expose plaintext. So the honest claim is a raised bar, not an absolute: confidential
          moves the trust from <em>“trust the machine&apos;s operator”</em> to{" "}
          <em>“trust Apple&apos;s platform security and co/core&apos;s measured, signed build”</em>{" "}
          — a meaningful shift, but a different and shallower one than a hardware enclave that
          isolates memory from the host itself. If you need that stronger property, a hardware-TEE
          provider is the right tool; the confidential tier is the strongest posture we can reach on
          stock Apple hardware without one — and, for now, an experimental one.
        </p>

        <h2 {...stylex.props(docsStyles.h2)}>Why they&apos;re independent</h2>
        <p {...stylex.props(docsStyles.prose)}>
          <strong>Neither</strong> — fast best-effort serving: a real-enough machine whose operator
          can read prompts. <strong>Secure Mode only</strong> — attested genuine hardware, but
          inference still runs where the operator can read it. <strong>Confidential only</strong> —
          the operator has no ordinary way to read prompts, but you&apos;re trusting the
          code-identity proof without an Apple hardware-root attestation of the silicon.{" "}
          <strong>Both</strong> — genuine attested hardware <em>and</em> a sealed inference path the
          operator can&apos;t ordinarily read.
        </p>

        <h2 {...stylex.props(docsStyles.h2)}>The model constraint for operators</h2>
        <p {...stylex.props(docsStyles.prose)}>
          Confidential serving runs in the agent&apos;s in-process engine, which only loads certain
          model architectures — Qwen2 / Qwen3 / Qwen3.5 / Qwen3.6 / Llama / Gemma / Phi /
          Mistral-class weights. A model outside that set (for example a Gemma 4 or Llama 4
          architecture) can only be served best-effort, in the readable helper process. The provider
          app marks each model in the picker as <strong>“Confidential”</strong> or{" "}
          <strong>“Best-effort only”</strong>: choosing a best-effort-only model means your machine
          can&apos;t offer requestors the confidential posture while serving it, even if the machine
          is otherwise confidential-capable. Pick a confidential-capable model to keep it.
        </p>

        <h2 {...stylex.props(docsStyles.h2)}>Turning them on</h2>
        <p {...stylex.props(docsStyles.prose)}>
          Both are controlled from the provider app under{" "}
          <strong>Open co/core → Status → Security</strong>: <em>Enable Secure Mode</em> runs the
          device-enrollment wizard, and <em>Enable confidential</em> opts the machine into the
          attested-confidential tier (the same intent the console&apos;s per-machine control
          writes). The machine then restarts serving to earn the posture; it only advertises the
          higher tier once actually earned, so opting in never overstates what a machine can prove.
          For the receipt and lexicon fields these map to, see the{" "}
          <Link to="/docs/lexicons" {...stylex.props(docsStyles.proseLink)}>
            lexicon reference
          </Link>
          .
        </p>
      </div>
    </>
  );
}
