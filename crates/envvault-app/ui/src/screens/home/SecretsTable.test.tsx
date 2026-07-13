// Component tests required by spec §10.2:
// 1. a secret value is masked by default,
// 2. revealing a production secret requires two deliberate actions.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../../bindings", () => ({
  commands: {
    revealSecret: vi.fn().mockResolvedValue({ status: "ok", data: "sk_live_PLAINTEXT" }),
    copySecret: vi.fn().mockResolvedValue({ status: "ok", data: 30 }),
    listProjects: vi.fn().mockResolvedValue({ status: "ok", data: [] }),
    listSecrets: vi.fn().mockResolvedValue({ status: "ok", data: [] }),
    vaultStatus: vi.fn().mockResolvedValue({ status: "ok", data: {} }),
  },
}));

import { useVault } from "../../store";
import { SecretsTable } from "./SecretsTable";
import type { SecretMeta } from "../../bindings";

const meta: SecretMeta = {
  id: "s1",
  key: "STRIPE_SECRET_KEY",
  note: null,
  detectedType: "StripeSecret",
  detectedLabel: "Stripe secret",
  createdAt: "2026-07-13T00:00:00Z",
  rotatedAt: "2026-07-13T00:00:00Z",
  valueLength: 17,
};

describe("SecretsTable", () => {
  beforeEach(() => {
    useVault.setState({
      selectedProjectId: "p1",
      selectedEnvId: "e1",
      secrets: [meta],
    });
  });

  it("masks values by default and reveals only on explicit action", async () => {
    const user = userEvent.setup();
    render(
      <SecretsTable filter="" isProduction={false} onEdit={() => {}} onDelete={() => {}} />,
    );

    // Masked: plaintext is nowhere in the document, dots are.
    expect(screen.queryByText("sk_live_PLAINTEXT")).toBeNull();
    expect(screen.getByLabelText("hidden value")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Reveal STRIPE_SECRET_KEY" }));
    expect(await screen.findByText("sk_live_PLAINTEXT")).toBeInTheDocument();

    // Hiding drops it again.
    await user.click(screen.getByRole("button", { name: "Hide STRIPE_SECRET_KEY" }));
    expect(screen.queryByText("sk_live_PLAINTEXT")).toBeNull();
  });

  it("production reveal takes two deliberate actions", async () => {
    const user = userEvent.setup();
    render(
      <SecretsTable filter="" isProduction={true} onEdit={() => {}} onDelete={() => {}} />,
    );

    // Action 1: reveal click → confirmation dialog, still no plaintext.
    await user.click(screen.getByRole("button", { name: "Reveal STRIPE_SECRET_KEY" }));
    expect(await screen.findByText("Reveal a production secret?")).toBeInTheDocument();
    expect(screen.queryByText("sk_live_PLAINTEXT")).toBeNull();

    // Action 2: explicit confirmation → now it shows.
    await user.click(screen.getByRole("button", { name: "Reveal it" }));
    expect(await screen.findByText("sk_live_PLAINTEXT")).toBeInTheDocument();
  });
});
