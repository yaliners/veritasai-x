import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Outlet,
  Link,
  createRootRouteWithContext,
  useRouter,
  useRouterState,
} from "@tanstack/react-router";

import { AppSidebar } from "@/components/veritas/app-sidebar";
import { Toaster } from "sonner";
import { LayoutDashboard, Radar, BarChart3, ListChecks, Settings } from "lucide-react";
import { cn } from "@/lib/utils";

function NotFoundComponent() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="max-w-md text-center">
        <h1 className="text-7xl font-bold text-foreground">404</h1>
        <h2 className="mt-4 text-xl font-semibold text-foreground">Page not found</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          The page you're looking for doesn't exist or has been moved.
        </p>
        <div className="mt-6">
          <Link
            to="/"
            className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Go home
          </Link>
        </div>
      </div>
    </div>
  );
}

function ErrorComponent({ error, reset }: { error: Error; reset: () => void }) {
  console.error(error);
  const router = useRouter();

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="max-w-md text-center">
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          This page didn't load
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Something went wrong on our end. You can try refreshing or head back home.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-2">
          <button
            onClick={() => {
              router.invalidate();
              reset();
            }}
            className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Try again
          </button>
          <a
            href="/"
            className="inline-flex items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-accent"
          >
            Go home
          </a>
        </div>
      </div>
    </div>
  );
}

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: ErrorComponent,
});

const bottomNavItems = [
  { to: "/dashboard", label: "Home", icon: LayoutDashboard },
  { to: "/threats", label: "Alerts", icon: Radar },
  { to: "/analytics", label: "Analytics", icon: BarChart3 },
  { to: "/trusted", label: "Trusted", icon: ListChecks },
  { to: "/settings", label: "Settings", icon: Settings },
];

function RootComponent() {
  const { queryClient } = Route.useRouteContext();
  const path = useRouterState({ select: (r) => r.location.pathname });
  const isLandingPage = path === "/";

  return (
    <QueryClientProvider client={queryClient}>
      <div className="flex min-h-screen w-full">
        {!isLandingPage && <AppSidebar />}
        <div className="flex min-w-0 flex-1 flex-col pb-[60px] md:pb-0">
          <Outlet />
        </div>
      </div>

      {!isLandingPage && (
        <nav className="fixed bottom-0 left-0 right-0 z-50 h-[60px] bg-[#0F172A] border-t border-white/[0.07] flex justify-around items-center md:hidden">
          {bottomNavItems.map((item) => {
            const active = path === item.to;
            const Icon = item.icon;
            return (
              <Link
                key={item.to}
                to={item.to}
                className="flex flex-col items-center justify-center flex-1 h-full py-1 gap-1 select-none"
              >
                <Icon className={cn("h-5 w-5 transition-colors", active ? "text-[#06B6D4]" : "text-[#64748B]")} />
                <span className={cn("text-[10px] font-medium transition-colors", active ? "text-[#06B6D4]" : "text-[#64748B]")}>
                  {item.label}
                </span>
              </Link>
            );
          })}
        </nav>
      )}

      <Toaster position="bottom-right" richColors />
    </QueryClientProvider>
  );
}
