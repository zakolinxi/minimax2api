import { useTranslation } from "react-i18next";

import { Select } from "@/components/ui/select";

export const PERIOD_DAYS = [1, 7, 30, 90] as const;
export type PeriodDays = (typeof PERIOD_DAYS)[number];

export function toPeriodValue(days: PeriodDays): string {
  return `${days}d`;
}

export function PeriodSelector({
  value,
  onChange,
  ariaLabel,
}: {
  value: PeriodDays;
  onChange: (value: PeriodDays) => void;
  ariaLabel?: string;
}) {
  const { t } = useTranslation();
  return (
    <Select
      ariaLabel={ariaLabel}
      className="min-w-28"
      value={String(value)}
      onChange={(next) => onChange(Number(next) as PeriodDays)}
      options={[
        { value: "1", label: t("periods.last24h") },
        { value: "7", label: t("periods.last7d") },
        { value: "30", label: t("periods.last30d") },
        { value: "90", label: t("periods.last90d") },
      ]}
    />
  );
}
