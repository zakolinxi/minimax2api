import { useQuery } from "@tanstack/react-query";

import { apiRequest } from "@/shared/api/client";

type HealthDTO = { status: string; version?: string };

// useServerVersion reports the version of the running binary.
//
// It is read from /health rather than compiled into the bundle: the sidebar and
// the API docs both display it, and a hard-coded copy drifts from
// `gateway.Version` the first time only one of them is bumped. /health needs no
// token, and one shared query key means both callers cost a single request for
// the life of the page.
export function useServerVersion(): string {
  const { data } = useQuery({
    queryKey: ["health"],
    queryFn: () => apiRequest<HealthDTO>("/health", { auth: false }),
    staleTime: Infinity,
    retry: false,
  });
  return data?.version ?? "";
}
