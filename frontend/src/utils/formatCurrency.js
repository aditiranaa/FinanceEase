export default function formatCurrency(
  value,
  currency = "USD"
) {
  const locale =
    currency === "INR"
      ? "en-IN"
      : currency === "EUR"
      ? "de-DE"
      : "en-US";

  return Number(value || 0).toLocaleString(locale, {
    style: "currency",
    currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}