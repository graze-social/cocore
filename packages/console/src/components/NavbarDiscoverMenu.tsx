"use client";

import { createLink, useLocation } from "@tanstack/react-router";
import { ChevronDown } from "lucide-react";

import { Flex } from "@/design-system/flex";
import { NavbarLink, NavbarMenu, NavbarMenuList, NavbarMenuTrigger } from "@/design-system/navbar";

const NavbarRouterLink = createLink(NavbarLink);

const DISCOVER_PATHS = ["/friends", "/leaderboard", "/models", "/explore"] as const;

function isDiscoverPath(pathname: string, profilePath?: string): boolean {
  if (DISCOVER_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`))) {
    return true;
  }
  if (profilePath && (pathname === profilePath || pathname.startsWith(`${profilePath}/`))) {
    return true;
  }
  return false;
}

export function NavbarDiscoverMenu({ profileId }: { profileId?: string | null }) {
  const location = useLocation();
  const profilePath = profileId ? `/u/${profileId}` : undefined;
  const isOnDiscoverPage = isDiscoverPath(location.pathname, profilePath);

  return (
    <NavbarMenu
      defaultMobileExpanded={isOnDiscoverPage}
      trigger={
        <NavbarMenuTrigger>
          <Flex align="center" gap="md">
            discover
            <ChevronDown size={16} aria-hidden />
          </Flex>
        </NavbarMenuTrigger>
      }
    >
      <NavbarMenuList>
        {profileId ? (
          <NavbarRouterLink to="/u/$identifier" params={{ identifier: profileId }}>
            me
          </NavbarRouterLink>
        ) : null}
        {profileId ? <NavbarRouterLink to="/friends">friends</NavbarRouterLink> : null}
        <NavbarRouterLink to="/models">models</NavbarRouterLink>
        <NavbarRouterLink to="/models/capacity">capacity</NavbarRouterLink>
        <NavbarRouterLink to="/leaderboard">leaderboard</NavbarRouterLink>
        <NavbarRouterLink to="/explore">explore</NavbarRouterLink>
      </NavbarMenuList>
    </NavbarMenu>
  );
}
