import { useTranslation } from "react-i18next";

import { Badge } from "@/components/ui/badge";
import { Tooltip } from "@/components/ui/tooltip";
import type { AccountDTO, AccountStatus } from "@/features/accounts/accounts-api";
import { cn } from "@/shared/lib/cn";
import { formatDate, formatDateTime, formatRelative, hasInstant } from "@/shared/lib/format";

const STATUS_TONE: Record<AccountStatus, string> = {
  active: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  cooldown: "bg-amber-500/10 text-amber-700 dark:text-amber-300",
  disabled: "bg-muted text-muted-foreground",
  invalid: "bg-red-500/10 text-red-700 dark:text-red-300",
};

export function AccountNameCell({ account }: { account: AccountDTO }) {
  const { t, i18n } = useTranslation();
  const mainland = account.region === "cn";
  const tier = account.credit ? account.credit.tokenPlanTier.trim() || account.credit.planName.trim() : "";
  const expiresAt = account.credit?.tokenPlanExpiresAt ?? "";
  const expired = hasInstant(expiresAt) && Date.parse(expiresAt) <= Date.now();
  return (
    <div className="min-w-0 max-w-64">
      <div className="flex items-center gap-1.5">
        <span className="truncate text-xs font-medium text-foreground" title={account.name}>
          {account.name || account.identifier || account.tokenMasked}
        </span>
        {/* The region selects the upstream host, so it belongs in the identity
            line rather than in a detail the operator has to go looking for. */}
        <Badge
          variant="outline"
          className={cn("shrink-0", mainland && "border-amber-500/40 text-amber-700 dark:text-amber-300")}
        >
          {mainland ? t("accounts.regionCN") : t("accounts.regionGlobal")}
        </Badge>
        {account.group ? (
          <Badge variant="outline" className="shrink-0">
            {account.group}
          </Badge>
        ) : null}
      </div>
      <p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground" title={account.identifier || account.tokenMasked}>
        {/* The plan column is hidden on phones, where adding a fifth column
            pushed the balance off the first screen. The state still has to be
            visible there — it decides whether H3 may route here at all — so it
            rides on the identifier line instead. */}
        <span
          className={cn(
            account.subscribed && !expired && "text-emerald-600 dark:text-emerald-300",
            expired && "text-destructive",
            "md:hidden",
          )}
        >
          {account.credit ? tier || t("accounts.unsubscribed") : t("accounts.subscriptionUnknown")}
          {hasInstant(expiresAt)
            ? ` · ${expired
                ? t("accounts.expiredOn", { time: formatDate(expiresAt, i18n.language) })
                : t("accounts.expiresOn", { time: formatDate(expiresAt, i18n.language) })}`
            : ""}
          {" · "}
        </span>
        {account.identifier || account.tokenMasked}
      </p>
      {account.remark ? (
        <p className="mt-0.5 truncate text-[10px] text-muted-foreground" title={account.remark}>
          {account.remark}
        </p>
      ) : null}
      <p className="mt-0.5 truncate text-[10px] text-muted-foreground">
        {/* formatRelative already renders "—" for the Go zero time. */}
        {t("accounts.lastUsed")} · {formatRelative(account.lastUsedAt, i18n.language)}
      </p>
    </div>
  );
}

export function AccountStatusCell({ account }: { account: AccountDTO }) {
  const { t, i18n } = useTranslation();

  // Status is a snapshot taken when the failure happened, so it keeps saying
  // cooldown after the window has elapsed. Left as-is the row reads "cooling"
  // with a retry time in the past, which looks like a stuck account rather than
  // one the pool will happily schedule again — and the summary panel counts it
  // as active, so the two would contradict each other.
  const cooling = account.status === "cooldown" && Date.parse(account.cooldownUntil) > Date.now();
  const effective = account.status === "cooldown" && !cooling ? "active" : account.status;

  const label =
    effective === "active"
      ? t("accounts.statusActive")
      : effective === "cooldown"
        ? t("accounts.statusCooldown")
        : effective === "disabled"
          ? t("accounts.statusDisabled")
          : t("accounts.statusInvalid");

  const detail =
    account.status !== "cooldown"
      ? account.lastError || ""
      : cooling
        ? t("accounts.quotaResetAt", { time: formatRelative(account.cooldownUntil, i18n.language) })
        : t("accounts.cooldownElapsed");

  return (
    <div className="flex flex-col items-center gap-1">
      <span className={cn("inline-flex h-5 items-center rounded-full px-2 text-[11px] leading-none", STATUS_TONE[effective])}>
        {label}
      </span>
      {detail ? (
        <Tooltip label={detail}>
          <span className="block max-w-28 truncate text-[10px] text-muted-foreground">{detail}</span>
        </Tooltip>
      ) : null}
      {account.failCount > 0 ? (
        <span className="text-[10px] text-muted-foreground tabular-nums">失败 {account.failCount}</span>
      ) : null}
    </div>
  );
}

/**
 * Plan status for one account.
 *
 * "Unsynced" is a state of its own, not a polite word for "free": with no
 * membership reading the pool will not route a plan-only model here at all, so
 * the operator needs to tell "refresh the balance" apart from "buy a plan".
 */
export function AccountPlanCell({ account }: { account: AccountDTO }) {
  const { t, i18n } = useTranslation();
  if (!account.credit) {
    return (
      <Tooltip label={t("accounts.creditUnknown")}>
        <span className="text-[11px] text-muted-foreground">{t("accounts.subscriptionUnknown")}</span>
      </Tooltip>
    );
  }

  // The Token Plan tier is the subscription the plan-only models route on; the
  // membership name is the older label and stays as a fallback for readings
  // that predate the Token Plan fields.
  const tier = account.credit.tokenPlanTier.trim() || account.credit.planName.trim();
  const expiresAt = account.credit.tokenPlanExpiresAt;
  const expired = hasInstant(expiresAt) && Date.parse(expiresAt) <= Date.now();
  const status = expired
    ? t("accounts.subscriptionExpired")
    : account.subscribed
      ? t("accounts.subscribed")
      : t("accounts.unsubscribed");

  return (
    <div className="min-w-0 space-y-0.5">
      <Tooltip label={status}>
        <span
          className={cn(
            "inline-flex h-5 items-center rounded-full px-2 text-[11px] leading-none",
            account.subscribed && !expired
              ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
              : "bg-muted text-muted-foreground",
          )}
        >
          {tier || t("accounts.unsubscribed")}
        </span>
      </Tooltip>
      {hasInstant(expiresAt) ? (
        <p
          className={cn("truncate text-[10px]", expired ? "text-destructive" : "text-muted-foreground")}
          title={formatDateTime(expiresAt, i18n.language)}
        >
          {expired
            ? t("accounts.expiredOn", { time: formatDate(expiresAt, i18n.language) })
            : t("accounts.expiresOn", { time: formatDate(expiresAt, i18n.language) })}
        </p>
      ) : account.subscribed ? (
        <p className="truncate text-[10px] text-muted-foreground">{t("accounts.expiryUnknown")}</p>
      ) : null}
    </div>
  );
}

export function AccountRoutingCell({ account }: { account: AccountDTO }) {
  return (
    <div className="space-y-0.5 text-[11px] text-muted-foreground">
      <p className="tabular-nums">
        优先级 <span className="text-foreground">{account.priority}</span>
      </p>
      <p className="tabular-nums">
        并发 <span className="text-foreground">{account.inflight}</span> / {account.maxConcurrent}
      </p>
    </div>
  );
}
