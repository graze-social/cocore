import * as stylex from "@stylexjs/stylex";
import { useQuery } from "@tanstack/react-query";
import {
  Link,
  Outlet,
  createFileRoute,
  createLink,
  redirect,
  useLocation,
} from "@tanstack/react-router";

import { listMyMachinesQueryOptions } from "@/components/machines/machines.functions.ts";
import { NavbarAuth } from "@/components/NavbarAuth.tsx";
import { NavbarDiscoverMenu } from "@/components/NavbarDiscoverMenu.tsx";
import { SaveHandleOnLoginSuccess } from "@/components/SaveHandleOnLoginSuccess.tsx";
import { getMyTermsStateQueryOptions } from "@/components/terms/terms.functions.ts";
import { ThemeToggle } from "@/components/ThemeToggle.tsx";
import { Card, CardDescription, CardHeader, CardTitle } from "@/design-system/card";
import { Footer } from "@/design-system/footer";
import { HeaderLayout } from "@/design-system/header-layout";
import { Page } from "@/design-system/page/index.tsx";
import { getSessionQueryOptions } from "@/integrations/auth/session.functions.ts";
import { Link as DSLink } from "@/design-system/link";
import {
  Navbar,
  NavbarAction,
  NavbarActionGroup,
  NavbarLink,
  NavbarLogo,
  NavbarNavigation,
} from "@/design-system/navbar";
import { primaryColor } from "@/design-system/theme/color.stylex";
import { Flex } from "@/design-system/flex";
import { fontSize } from "@/design-system/theme/typography.stylex";
import { Text } from "@/design-system/typography/text";

const styles = stylex.create({
  logoLink: {
    gridColumnEnd: "logo",
    gridColumnStart: "logo",
    gridRowEnd: "logo",
    gridRowStart: "logo",
    textDecoration: "none",
    color: primaryColor.text2,
  },
  logoText: {
    color: primaryColor.textContrast,
    cornerRadius: "squircle",
    fontSize: fontSize.xs,
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
  },
  logoMark: {
    display: "block",
    width: "1.125rem",
    height: "1.125rem",
  },
  footerGoober: {
    display: "block",
    width: "3rem",
    height: "3rem",
    objectFit: "contain",
    opacity: 0.9,
    pointerEvents: "none",
    userSelect: "none",
  },
  footerBottomRow: {
    width: "100%",
  },
});

const NavbarRouterLink = createLink(NavbarLink);
const FooterRouterLink = createLink(DSLink);

export const Route = createFileRoute("/_header-layout")({
  beforeLoad: async ({ context, location }) => {
    await context.queryClient.ensureQueryData(getSessionQueryOptions);
    const session = context.queryClient.getQueryData(getSessionQueryOptions.queryKey);
    const skipTermsStateQuery =
      location.pathname === "/terms" ||
      location.pathname === "/privacy" ||
      location.pathname === "/account";
    if (!session || skipTermsStateQuery || location.pathname === "/accept-terms") {
      return;
    }
    await context.queryClient.ensureQueryData(getMyTermsStateQueryOptions);
    const termsState = context.queryClient.getQueryData(getMyTermsStateQueryOptions.queryKey);
    if (termsState != null && termsState.activePolicy != null && termsState.accepted === false) {
      // `location.search` is the parsed object (TanStack Router); the
      // string form is `searchStr` ("?…"). Interpolating the object
      // here would yield "[object Object]" at best, and on a
      // null-prototype parsed-search object it throws
      // "Cannot convert object to primitive value" during SSR.
      const redirectTarget = `${location.pathname}${location.searchStr}`;
      throw redirect({
        to: "/accept-terms",
        search: { redirect: redirectTarget },
        replace: true,
      });
    }
  },
  loader: async ({ context }) => {
    await context.queryClient.ensureQueryData(getSessionQueryOptions);
    const session = context.queryClient.getQueryData(getSessionQueryOptions.queryKey);
    if (session) {
      await context.queryClient.ensureQueryData(listMyMachinesQueryOptions);
    }
  },
  component: HeaderLayoutChrome,
});

function HeaderLayoutChrome() {
  const { data: session } = useQuery(getSessionQueryOptions);
  const { data: fleet } = useQuery({
    ...listMyMachinesQueryOptions,
    enabled: Boolean(session),
  });
  const machineCount = session ? (fleet?.machines.length ?? 0) : 0;

  // Terms: `beforeLoad` redirects out-of-date signed-in users to
  // `/accept-terms?redirect=…`. /terms, /privacy, and /account skip
  // that check so legal pages stay readable and operators can
  // bootstrap policy. Here we only gate on noPolicyBlocked (no
  // published exchange policy yet).
  const location = useLocation();
  const skipTermsStateQuery =
    location.pathname === "/terms" ||
    location.pathname === "/privacy" ||
    location.pathname === "/account";
  const termsQ = useQuery({
    ...getMyTermsStateQueryOptions,
    enabled: Boolean(session) && !skipTermsStateQuery,
  });
  const termsState = termsQ.data ?? null;
  const noPolicyBlocked =
    Boolean(session) &&
    !skipTermsStateQuery &&
    termsState !== null &&
    termsState.activePolicy === null;

  return (
    <HeaderLayout.Root maxWidth="1600px">
      <SaveHandleOnLoginSuccess />
      <HeaderLayout.Header>
        <Navbar>
          <Link to="/" preload="intent" {...stylex.props(styles.logoLink)}>
            <NavbarLogo>
              <Flex align="center" gap="md">
                <div {...stylex.props(styles.logoText)}>
                  <img
                    src="/favicon.svg"
                    alt=""
                    width={18}
                    height={18}
                    {...stylex.props(styles.logoMark)}
                  />
                </div>
                <Text>co/core</Text>
              </Flex>
            </NavbarLogo>
          </Link>
          <NavbarNavigation justify="left">
            {session != null ? (
              <>
                <NavbarRouterLink to="/machines">
                  <Flex align="center" gap="md">
                    <Text>machines</Text>
                    {machineCount > 0 ? (
                      <Text variant="secondary" size="sm">
                        ({machineCount})
                      </Text>
                    ) : (
                      ""
                    )}
                  </Flex>
                </NavbarRouterLink>
                {/* /earnings removed in the closed-loop pivot — there is no
                    USD-payout concept here, so the page conflicted with the
                    rest of the dashboard semantics. Provider income is now
                    surfaced as `receipt-in` events on /account's balance
                    log, and per-machine throughput is on /machines. */}
                <NavbarRouterLink to="/chat">chat</NavbarRouterLink>
                <NavbarRouterLink to="/jobs">jobs</NavbarRouterLink>
                <NavbarDiscoverMenu profileId={session.user.handle ?? session.user.did} />
              </>
            ) : (
              <>
                <NavbarRouterLink to="/models">models</NavbarRouterLink>
                <NavbarRouterLink to="/explore">explore</NavbarRouterLink>
                <NavbarRouterLink to="/leaderboard">leaderboard</NavbarRouterLink>
                <NavbarRouterLink to="/blog">blog</NavbarRouterLink>
                <NavbarRouterLink to="/docs">API</NavbarRouterLink>
              </>
            )}
          </NavbarNavigation>
          <NavbarActionGroup>
            {session == null ? (
              <NavbarAction alwaysVisible>
                <ThemeToggle />
              </NavbarAction>
            ) : null}
            <NavbarAuth />
          </NavbarActionGroup>
        </Navbar>
      </HeaderLayout.Header>

      <HeaderLayout.Page>{noPolicyBlocked ? <NoPolicyGate /> : <Outlet />}</HeaderLayout.Page>

      <HeaderLayout.Footer>
        <Footer.Root>
          <Footer.Section>
            <Footer.Logo>
              <Link to="/machines" preload="intent" {...stylex.props(styles.logoLink)}>
                <Flex align="center" gap="md">
                  <div {...stylex.props(styles.logoText)}>
                    <img
                      src="/favicon.svg"
                      alt=""
                      width={18}
                      height={18}
                      {...stylex.props(styles.logoMark)}
                    />
                  </div>
                  <Text>co/core</Text>
                </Flex>
              </Link>
            </Footer.Logo>
            <Footer.NavSection>
              <Footer.NavGroup title="Resources">
                <FooterRouterLink to="/docs" preload="intent">
                  Docs
                </FooterRouterLink>
                <FooterRouterLink to="/models" preload="intent">
                  Models
                </FooterRouterLink>
                <FooterRouterLink to="/blog" preload="intent">
                  Blog
                </FooterRouterLink>
                <DSLink
                  href="https://github.com/graze-social/cocore"
                  target="_blank"
                  rel="noreferrer"
                >
                  Code
                </DSLink>
              </Footer.NavGroup>
              <Footer.NavGroup title="Legal">
                <FooterRouterLink to="/terms" preload="intent">
                  Terms
                </FooterRouterLink>
                <FooterRouterLink to="/privacy" preload="intent">
                  Privacy
                </FooterRouterLink>
              </Footer.NavGroup>
            </Footer.NavSection>
          </Footer.Section>
          <Footer.Section>
            <Flex align="center" justify="between" gap="md" style={styles.footerBottomRow}>
              <Footer.Copyright>
                © {new Date().getFullYear()} co/core. All rights reserved.
              </Footer.Copyright>
              <img
                src="/goobies/balloon.png"
                alt=""
                aria-hidden
                {...stylex.props(styles.footerGoober)}
              />
            </Flex>
          </Footer.Section>
        </Footer.Root>
      </HeaderLayout.Footer>
    </HeaderLayout.Root>
  );
}

// Replaces the route Outlet when the user is signed in but the
// exchange hasn't published an `exchangePolicy` record yet. Surfaces
// the missing-policy state explicitly instead of letting users into
// an app whose terms haven't been declared.
function NoPolicyGate() {
  return (
    <Page.Root>
      <Page.Header>
        <Page.Title>Service initializing</Page.Title>
        <Page.Description>
          The exchange hasn't published its terms-of-service policy yet, so co/core can't show you
          what you'd be agreeing to. The services container republishes the policy on next boot.
          Refresh this page in a minute or two.
        </Page.Description>
      </Page.Header>
      <Card size="md">
        <CardHeader hasBorder>
          <CardTitle>Waiting for `dev.cocore.compute.exchangePolicy`</CardTitle>
          <CardDescription>
            Once the policy is republished, this page will replace itself with the terms-acceptance
            prompt. You can keep this tab open and refresh, or come back later.
          </CardDescription>
        </CardHeader>
      </Card>
    </Page.Root>
  );
}
