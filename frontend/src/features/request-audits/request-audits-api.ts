import { apiRequest } from "@/shared/api/client";

export type AuditDTO = {
  id: string;
  createdAt: string;
  keyName: string;
  model: string;
  accountName: string;
  /**
   * Set on management-operation records the backend writes for admin actions.
   * Those carry `action` (and optionally `detail`) while model and key stay
   * empty, which is how the list tells them apart from /v1 traffic.
   */
  action?: string;
  detail?: string;
  status: number;
  latencyMs: number;
  firstTokenMs: number;
  promptTokens: number;
  completionTokens: number;
  stream: boolean;
  retries: number;
  ip: string;
  userAgent: string;
  error: string;
  requestBody: string;
  responseBody: string;
};

export type AuditListResult = {
  items: AuditDTO[];
  total: number;
  page: number;
  pageSize: number;
};

export function listAudits(query: {
  page: number;
  pageSize: number;
  search?: string;
  status?: string;
}): Promise<AuditListResult> {
  const params = new URLSearchParams({ page: String(query.page), pageSize: String(query.pageSize) });
  if (query.search) params.set("search", query.search);
  if (query.status) params.set("status", query.status);
  return apiRequest<AuditListResult>(`/admin/api/audits?${params.toString()}`);
}

export function getAudit(id: string): Promise<{ audit: AuditDTO }> {
  return apiRequest(`/admin/api/audits/${id}`);
}

export function clearAudits(): Promise<void> {
  return apiRequest("/admin/api/audits", { method: "DELETE" });
}
