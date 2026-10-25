import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { useState } from "react";
import { RouterProvider } from "react-router-dom";
import { Toaster } from "sonner";

import { router } from "@/app/router";
import { AuthProvider } from "@/shared/auth/auth-context";
import { ThemeColorSync } from "@/shared/components/theme-color-sync";

export function App() {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: 1,
            refetchOnWindowFocus: false,
            staleTime: 10_000,
          },
        },
      }),
  );

  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
      {/* Mounted here — inside ThemeProvider, above the router — so the
          theme-color metas follow the resolved theme on the login page too,
          not only inside the admin shell. */}
      <ThemeColorSync />
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <RouterProvider router={router} />
          <Toaster position="top-center" richColors closeButton />
        </AuthProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
