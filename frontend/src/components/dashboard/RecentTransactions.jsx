import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowDownRight,
  ArrowUpDown,
  ArrowUpRight,
  CalendarDays,
  ChevronLeft,
  ChevronRight,
  CircleDollarSign,
  Download,
  Filter,
  Loader2,
  Pencil,
  Receipt,
  RefreshCw,
  Save,
  Search,
  SlidersHorizontal,
  TrendingDown,
  TrendingUp,
  Trash2,
  Wallet,
  X,
} from "lucide-react";

import { deleteTransaction, updateTransaction } from "../../api/authApi";

/* ========================================================================== */
/* Constants and helpers                                                       */
/* ========================================================================== */

const TRANSACTIONS_PER_PAGE = 10;

const CATEGORY_STYLES = {
  salary: "bg-emerald-500/10 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-400/10 dark:text-emerald-300 dark:ring-emerald-400/20",
  food: "bg-orange-500/10 text-orange-700 ring-orange-600/20 dark:bg-orange-400/10 dark:text-orange-300 dark:ring-orange-400/20",
  shopping: "bg-pink-500/10 text-pink-700 ring-pink-600/20 dark:bg-pink-400/10 dark:text-pink-300 dark:ring-pink-400/20",
  bills: "bg-red-500/10 text-red-700 ring-red-600/20 dark:bg-red-400/10 dark:text-red-300 dark:ring-red-400/20",
  travel: "bg-blue-500/10 text-blue-700 ring-blue-600/20 dark:bg-blue-400/10 dark:text-blue-300 dark:ring-blue-400/20",
  health: "bg-violet-500/10 text-violet-700 ring-violet-600/20 dark:bg-violet-400/10 dark:text-violet-300 dark:ring-violet-400/20",
  entertainment: "bg-amber-500/10 text-amber-700 ring-amber-600/20 dark:bg-amber-400/10 dark:text-amber-300 dark:ring-amber-400/20",
  investment: "bg-cyan-500/10 text-cyan-700 ring-cyan-600/20 dark:bg-cyan-400/10 dark:text-cyan-300 dark:ring-cyan-400/20",
  other: "bg-slate-500/10 text-slate-700 ring-slate-600/20 dark:bg-slate-400/10 dark:text-slate-300 dark:ring-slate-400/20",
};

const SUMMARY_STYLES = {
  emerald: {
    caption: "text-emerald-600 dark:text-emerald-400",
    icon: "bg-emerald-500/10 text-emerald-600 dark:bg-emerald-400/10 dark:text-emerald-300",
  },
  rose: {
    caption: "text-rose-600 dark:text-rose-400",
    icon: "bg-rose-500/10 text-rose-600 dark:bg-rose-400/10 dark:text-rose-300",
  },
  cyan: {
    caption: "text-cyan-600 dark:text-cyan-400",
    icon: "bg-cyan-500/10 text-cyan-600 dark:bg-cyan-400/10 dark:text-cyan-300",
  },
  slate: {
    caption: "text-slate-600 dark:text-slate-400",
    icon: "bg-slate-100 text-slate-700 dark:bg-white/10 dark:text-slate-300",
  },
};

const inputClass =
  "w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-emerald-500 focus:ring-4 focus:ring-emerald-500/10 dark:border-white/10 dark:bg-slate-900/80 dark:text-white dark:placeholder:text-slate-500 dark:focus:border-emerald-400";

const getTransactionId = (transaction) =>
  transaction?.id ?? transaction?._id ?? transaction?.transactionId;

const toAmount = (value) => {
  const amount = Number(value);
  return Number.isFinite(amount) ? amount : 0;
};

const getDate = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

const toDateInput = (value) => {
  const date = getDate(value);
  if (!date) return "";
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
};

const formatCurrency = (value, withSign = false) => {
  const amount = toAmount(value);
  const result = `₹${Math.abs(amount).toLocaleString("en-IN", {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
  })}`;
  return withSign ? `${amount >= 0 ? "+" : "-"}${result}` : result;
};

const formatDate = (value) => {
  const date = getDate(value);
  if (!date) return "No date";
  return new Intl.DateTimeFormat("en-IN", {
    day: "numeric",
    month: "short",
    year: "numeric",
  }).format(date);
};

const formatRelativeDate = (value) => {
  const date = getDate(value);
  if (!date) return "Unknown date";
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const target = new Date(date.getFullYear(), date.getMonth(), date.getDate());
  const difference = Math.round((today - target) / 86400000);
  if (difference === 0) return "Today";
  if (difference === 1) return "Yesterday";
  if (difference > 1 && difference < 7) return `${difference} days ago`;
  if (difference < 0) return "Upcoming";
  return formatDate(value);
};

const categoryClass = (category) =>
  CATEGORY_STYLES[String(category || "other").trim().toLowerCase()] ||
  CATEGORY_STYLES.other;

const escapeCsv = (value) => {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
};

const pageItems = (page, totalPages) => {
  if (totalPages <= 7) return Array.from({ length: totalPages }, (_, index) => index + 1);
  if (page <= 4) return [1, 2, 3, 4, 5, "right", totalPages];
  if (page >= totalPages - 3) return [1, "left", totalPages - 4, totalPages - 3, totalPages - 2, totalPages - 1, totalPages];
  return [1, "left", page - 1, page, page + 1, "right", totalPages];
};

/* ========================================================================== */
/* RecentTransactions                                                          */
/* ========================================================================== */

const RecentTransactions = ({ transactions = [], fetchTransactions }) => {
  /* Filters, sorting and pagination */
  const [searchTerm, setSearchTerm] = useState("");
  const [dateFilter, setDateFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sortBy, setSortBy] = useState("newest");
  const [currentPage, setCurrentPage] = useState(1);

  /* CRUD state */
  const [editingId, setEditingId] = useState(null);
  const [editData, setEditData] = useState({ description: "", category: "", amount: "", date: "" });
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [notice, setNotice] = useState(null);

  useEffect(() => setCurrentPage(1), [searchTerm, dateFilter, typeFilter, sortBy]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key !== "Escape") return;
      if (deleteTarget && !isDeleting) setDeleteTarget(null);
      if (editingId && !isSaving) setEditingId(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [deleteTarget, editingId, isDeleting, isSaving]);

  useEffect(() => {
    if (!notice) return undefined;
    const timeout = window.setTimeout(() => setNotice(null), 4200);
    return () => window.clearTimeout(timeout);
  }, [notice]);

  /* Summary calculations */
  const summary = useMemo(() => {
    const income = transactions.reduce((sum, transaction) => {
      const amount = toAmount(transaction.amount);
      return amount > 0 ? sum + amount : sum;
    }, 0);
    const expense = transactions.reduce((sum, transaction) => {
      const amount = toAmount(transaction.amount);
      return amount < 0 ? sum + Math.abs(amount) : sum;
    }, 0);
    return { income, expense, balance: income - expense, count: transactions.length };
  }, [transactions]);

  /* Filtering */
  const filteredTransactions = useMemo(() => {
    const search = searchTerm.trim().toLowerCase();
    const today = new Date();
    return transactions.filter((transaction) => {
      const description = String(transaction.description || "").toLowerCase();
      const category = String(transaction.category || "").toLowerCase();
      const amount = toAmount(transaction.amount);
      const date = getDate(transaction.date);
      if (search && !description.includes(search) && !category.includes(search)) return false;
      if (typeFilter === "income" && amount <= 0) return false;
      if (typeFilter === "expense" && amount >= 0) return false;
      if (dateFilter === "all" || !date) return true;
      if (dateFilter === "today") return date.toDateString() === today.toDateString();
      return date.getMonth() === today.getMonth() && date.getFullYear() === today.getFullYear();
    });
  }, [transactions, searchTerm, dateFilter, typeFilter]);

  /* Sorting */
  const sortedTransactions = useMemo(() => {
    const sorted = [...filteredTransactions];
    sorted.sort((a, b) => {
      const aDate = getDate(a.date)?.getTime() || 0;
      const bDate = getDate(b.date)?.getTime() || 0;
      const aAmount = Math.abs(toAmount(a.amount));
      const bAmount = Math.abs(toAmount(b.amount));
      if (sortBy === "oldest") return aDate - bDate;
      if (sortBy === "highest") return bAmount - aAmount;
      if (sortBy === "lowest") return aAmount - bAmount;
      return bDate - aDate;
    });
    return sorted;
  }, [filteredTransactions, sortBy]);

  /* Pagination */
  const totalPages = Math.max(1, Math.ceil(sortedTransactions.length / TRANSACTIONS_PER_PAGE));
  const safePage = Math.min(currentPage, totalPages);
  const startIndex = (safePage - 1) * TRANSACTIONS_PER_PAGE;
  const endIndex = startIndex + TRANSACTIONS_PER_PAGE;
  const currentTransactions = useMemo(
    () => sortedTransactions.slice(startIndex, endIndex),
    [sortedTransactions, startIndex, endIndex]
  );
  const paginationItems = useMemo(() => pageItems(safePage, totalPages), [safePage, totalPages]);

  /* CRUD */
  const refresh = useCallback(async () => {
    if (typeof fetchTransactions !== "function") return;
    try {
      setIsRefreshing(true);
      await fetchTransactions();
      setNotice({ type: "success", text: "Transactions refreshed successfully." });
    } catch (error) {
      console.error(error);
      setNotice({ type: "error", text: "Unable to refresh transactions. Please try again." });
    } finally {
      setIsRefreshing(false);
    }
  }, [fetchTransactions]);

  const startEditing = useCallback((transaction) => {
    setEditingId(getTransactionId(transaction));
    setEditData({
      description: transaction.description || "",
      category: transaction.category || "",
      amount: String(transaction.amount ?? ""),
      date: toDateInput(transaction.date),
    });
  }, []);

  const cancelEditing = useCallback(() => {
    setEditingId(null);
    setEditData({ description: "", category: "", amount: "", date: "" });
  }, []);

  const saveTransaction = useCallback(async (id) => {
    const description = editData.description.trim();
    const category = editData.category.trim();
    const amount = Number(editData.amount);
    if (!description || !category || !editData.date || !Number.isFinite(amount)) {
      setNotice({ type: "error", text: "Please complete all fields with a valid amount." });
      return;
    }
    try {
      setIsSaving(true);
      await updateTransaction(id, { description, category, amount, date: editData.date });
      await Promise.resolve(fetchTransactions?.());
      cancelEditing();
      setNotice({ type: "success", text: "Transaction updated successfully." });
    } catch (error) {
      console.error(error);
      setNotice({ type: "error", text: "Unable to update this transaction. Please try again." });
    } finally {
      setIsSaving(false);
    }
  }, [cancelEditing, editData, fetchTransactions]);

  const confirmDelete = useCallback(async () => {
    const id = getTransactionId(deleteTarget);
    if (id === undefined || id === null) return;
    try {
      setIsDeleting(true);
      await deleteTransaction(id);
      await Promise.resolve(fetchTransactions?.());
      setDeleteTarget(null);
      setNotice({ type: "success", text: "Transaction deleted successfully." });
    } catch (error) {
      console.error(error);
      setNotice({ type: "error", text: "Unable to delete this transaction. Please try again." });
    } finally {
      setIsDeleting(false);
    }
  }, [deleteTarget, fetchTransactions]);

  /* Export CSV */
  const exportCsv = useCallback(() => {
    const rows = [["Description", "Category", "Amount", "Date"], ...sortedTransactions.map((transaction) => [
      transaction.description || "",
      transaction.category || "",
      transaction.amount ?? "",
      transaction.date || "",
    ])];
    const blob = new Blob([rows.map((row) => row.map(escapeCsv).join(",")).join("\n")], {
      type: "text/csv;charset=utf-8;",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `transactions-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setNotice({ type: "success", text: `${sortedTransactions.length} transactions exported to CSV.` });
  }, [sortedTransactions]);

  const clearFilters = () => {
    setSearchTerm("");
    setDateFilter("all");
    setTypeFilter("all");
    setSortBy("newest");
  };

  const hasActiveFilters = searchTerm.trim() || dateFilter !== "all" || typeFilter !== "all" || sortBy !== "newest";

  const categoryBadge = (category) => (
    <span className={`inline-flex max-w-full truncate rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${categoryClass(category)}`}>
      {category || "Other"}
    </span>
  );

  const amountBadge = (amount) => {
    const isIncome = toAmount(amount) >= 0;
    return (
      <div className={`inline-flex items-center gap-1.5 rounded-xl px-2.5 py-1.5 text-sm font-bold ${isIncome ? "bg-emerald-500/10 text-emerald-700 dark:bg-emerald-400/10 dark:text-emerald-300" : "bg-rose-500/10 text-rose-700 dark:bg-rose-400/10 dark:text-rose-300"}`}>
        {isIncome ? <ArrowUpRight className="h-4 w-4" /> : <ArrowDownRight className="h-4 w-4" />}
        {formatCurrency(amount, true)}
      </div>
    );
  };

  const editFields = () => (
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="sm:col-span-2">
        <label className="mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300">Description</label>
        <input className={inputClass} name="description" value={editData.description} onChange={(event) => setEditData((data) => ({ ...data, description: event.target.value }))} disabled={isSaving} />
      </div>
      <div>
        <label className="mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300">Category</label>
        <input className={inputClass} name="category" value={editData.category} onChange={(event) => setEditData((data) => ({ ...data, category: event.target.value }))} disabled={isSaving} />
      </div>
      <div>
        <label className="mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300">Amount</label>
        <input className={inputClass} name="amount" type="number" step="0.01" value={editData.amount} onChange={(event) => setEditData((data) => ({ ...data, amount: event.target.value }))} disabled={isSaving} />
      </div>
      <div className="sm:col-span-2">
        <label className="mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300">Date</label>
        <input className={inputClass} name="date" type="date" value={editData.date} onChange={(event) => setEditData((data) => ({ ...data, date: event.target.value }))} disabled={isSaving} />
      </div>
    </div>
  );

  return (
    <section className="mx-auto w-full max-w-7xl space-y-5 sm:space-y-6">
      {/* Header */}
      <div className="relative isolate overflow-hidden rounded-[1.75rem] bg-slate-950 px-5 py-6 shadow-2xl shadow-slate-950/15 sm:px-7 sm:py-8 lg:px-9 lg:py-10 dark:ring-1 dark:ring-white/10">
        <div className="absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top_right,_rgba(16,185,129,0.35),_transparent_32%),radial-gradient(circle_at_bottom_left,_rgba(6,182,212,0.22),_transparent_35%)]" />
        <div className="absolute -right-20 -top-24 -z-10 h-72 w-72 rounded-full bg-emerald-400/20 blur-3xl" />
        <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl">
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.16em] text-emerald-100 backdrop-blur"><span className="h-1.5 w-1.5 rounded-full bg-emerald-300" />Financial overview</div>
            <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Recent transactions</h1>
            <p className="mt-3 max-w-xl text-sm leading-6 text-slate-300 sm:text-base">Stay in control of every payment, purchase, and deposit from one focused workspace.</p>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <button type="button" onClick={refresh} disabled={isRefreshing} className="inline-flex min-h-11 items-center justify-center gap-2 rounded-xl border border-white/15 bg-white/10 px-4 py-2.5 text-sm font-semibold text-white backdrop-blur transition hover:bg-white/20 disabled:cursor-not-allowed disabled:opacity-60"><RefreshCw className={`h-4 w-4 ${isRefreshing ? "animate-spin" : ""}`} />Refresh</button>
            <button type="button" onClick={exportCsv} disabled={!sortedTransactions.length} className="inline-flex min-h-11 items-center justify-center gap-2 rounded-xl bg-white px-4 py-2.5 text-sm font-bold text-slate-900 shadow-lg shadow-black/10 transition hover:scale-[1.02] hover:bg-emerald-50 disabled:cursor-not-allowed disabled:opacity-50"><Download className="h-4 w-4" />Export CSV</button>
          </div>
        </div>
      </div>

      {/* Status */}
      {notice && <div role="status" className={`flex items-center justify-between gap-3 rounded-2xl border px-4 py-3 text-sm font-medium ${notice.type === "success" ? "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-400/20 dark:bg-emerald-400/10 dark:text-emerald-200" : "border-rose-200 bg-rose-50 text-rose-800 dark:border-rose-400/20 dark:bg-rose-400/10 dark:text-rose-200"}`}><span>{notice.text}</span><button type="button" onClick={() => setNotice(null)} className="rounded-lg p-1 hover:bg-black/5 dark:hover:bg-white/10" aria-label="Dismiss message"><X className="h-4 w-4" /></button></div>}

      {/* Summary cards */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["Total income", formatCurrency(summary.income), "Money received", TrendingUp, "emerald"],
          ["Total expense", formatCurrency(summary.expense), "Money spent", TrendingDown, "rose"],
          ["Balance", formatCurrency(summary.balance), "Available balance", Wallet, "cyan"],
          ["Total transactions", summary.count.toLocaleString("en-IN"), "All recorded activity", Receipt, "slate"],
        ].map(([label, value, caption, Icon, color]) => {
          const styles = SUMMARY_STYLES[color];
          return (
          <div key={label} className="group rounded-2xl border border-slate-200/80 bg-white p-5 shadow-sm transition duration-300 hover:-translate-y-0.5 hover:shadow-lg dark:border-white/10 dark:bg-slate-900/70 dark:shadow-none">
            <div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium text-slate-500 dark:text-slate-400">{label}</p><p className="mt-2 text-2xl font-bold tracking-tight text-slate-900 dark:text-white">{value}</p><p className={`mt-1 text-xs font-medium ${styles.caption}`}>{caption}</p></div><div className={`rounded-2xl p-3 transition group-hover:scale-110 ${styles.icon}`}><Icon className="h-5 w-5" /></div></div>
          </div>
          );
        })}
      </div>

      {/* Toolbar */}
      <div className="rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-slate-900/70 sm:p-5">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-end">
          <div className="flex-1"><label htmlFor="transaction-search" className="mb-2 block text-xs font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-slate-400">Search transactions</label><div className="relative"><Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" /><input id="transaction-search" type="search" value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} placeholder="Search by description or category..." className={`${inputClass} pl-10`} /></div></div>
          <div className="grid gap-3 sm:grid-cols-3 xl:w-[570px]">
            <div><label htmlFor="date-filter" className="mb-2 block text-xs font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-slate-400">Date range</label><div className="relative"><CalendarDays className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" /><select id="date-filter" value={dateFilter} onChange={(event) => setDateFilter(event.target.value)} className={`${inputClass} appearance-none pl-9 pr-9 font-medium`}><option value="all">All time</option><option value="today">Today</option><option value="month">This month</option></select></div></div>
            <div><label htmlFor="type-filter" className="mb-2 block text-xs font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-slate-400">Type</label><div className="relative"><Filter className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" /><select id="type-filter" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} className={`${inputClass} appearance-none pl-9 pr-9 font-medium`}><option value="all">All types</option><option value="income">Income</option><option value="expense">Expense</option></select></div></div>
            <div><label htmlFor="sort-transactions" className="mb-2 block text-xs font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-slate-400">Sort by</label><div className="relative"><ArrowUpDown className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" /><select id="sort-transactions" value={sortBy} onChange={(event) => setSortBy(event.target.value)} className={`${inputClass} appearance-none pl-9 pr-9 font-medium`}><option value="newest">Newest</option><option value="oldest">Oldest</option><option value="highest">Highest amount</option><option value="lowest">Lowest amount</option></select></div></div>
          </div>
          <button type="button" onClick={clearFilters} disabled={!hasActiveFilters} className="inline-flex min-h-11 items-center justify-center gap-2 rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-45 dark:border-white/10 dark:text-slate-200 dark:hover:bg-white/5"><SlidersHorizontal className="h-4 w-4" />Clear filters</button>
        </div>
        <div className="mt-4 flex items-center justify-between gap-3 border-t border-slate-100 pt-4 dark:border-white/10"><p className="text-sm text-slate-500 dark:text-slate-400"><span className="font-bold text-slate-900 dark:text-white">{sortedTransactions.length.toLocaleString("en-IN")}</span> matching transaction{sortedTransactions.length === 1 ? "" : "s"}</p>{hasActiveFilters && <span className="rounded-full bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-300">Filters active</span>}</div>
      </div>

      {/* Loading skeleton */}
      {isRefreshing ? <div className="rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-slate-900/70 sm:p-5"><div className="space-y-3 animate-pulse">{Array.from({ length: 7 }).map((_, index) => <div key={index} className="flex items-center justify-between gap-4 rounded-xl border border-slate-100 p-4 dark:border-white/5"><div className="flex items-center gap-3"><div className="h-10 w-10 rounded-xl bg-slate-200 dark:bg-white/10" /><div className="space-y-2"><div className="h-3.5 w-36 rounded bg-slate-200 dark:bg-white/10" /><div className="h-3 w-24 rounded bg-slate-100 dark:bg-white/5" /></div></div><div className="h-8 w-24 rounded-xl bg-slate-200 dark:bg-white/10" /></div>)}</div></div> : <>
        {/* Desktop table */}
        <div className="hidden overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm dark:border-white/10 dark:bg-slate-900/70 lg:block"><div className="max-h-[680px] overflow-auto"><table className="w-full border-separate border-spacing-0 text-left"><thead className="sticky top-0 z-10 bg-slate-50/95 backdrop-blur dark:bg-slate-950/95"><tr className="text-xs font-bold uppercase tracking-[0.12em] text-slate-500 dark:text-slate-400"><th className="border-b border-slate-200 px-6 py-4 dark:border-white/10">Transaction</th><th className="border-b border-slate-200 px-5 py-4 dark:border-white/10">Category</th><th className="border-b border-slate-200 px-5 py-4 dark:border-white/10">Date</th><th className="border-b border-slate-200 px-5 py-4 text-right dark:border-white/10">Amount</th><th className="border-b border-slate-200 px-6 py-4 text-right dark:border-white/10">Actions</th></tr></thead><tbody>
          {currentTransactions.length === 0 ? <tr><td colSpan="5" className="px-6 py-20"><div className="mx-auto flex max-w-sm flex-col items-center text-center"><div className="rounded-2xl bg-slate-100 p-4 text-slate-400 dark:bg-white/5 dark:text-slate-500"><Receipt className="h-8 w-8" /></div><h2 className="mt-5 text-lg font-bold text-slate-900 dark:text-white">No transactions found</h2><p className="mt-2 text-sm leading-6 text-slate-500 dark:text-slate-400">Try adjusting your search or filters to find what you are looking for.</p>{hasActiveFilters && <button type="button" onClick={clearFilters} className="mt-5 rounded-xl bg-slate-900 px-4 py-2 text-sm font-semibold text-white dark:bg-white dark:text-slate-900">Clear all filters</button>}</div></td></tr> : currentTransactions.map((transaction) => {
            const id = getTransactionId(transaction);
            const editing = editingId === id;
            return <tr key={id} className="group transition hover:bg-slate-50/80 dark:hover:bg-white/[0.035]">
              <td colSpan={editing ? 5 : 1} className="border-b border-slate-100 px-6 py-4 dark:border-white/5">{editing ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50/50 p-4 dark:border-emerald-400/20 dark:bg-emerald-400/5"><div className="mb-4 flex items-center justify-between"><div><p className="text-sm font-bold text-slate-900 dark:text-white">Edit transaction</p><p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">Update the transaction details below.</p></div><div className="flex gap-2"><button type="button" onClick={() => saveTransaction(id)} disabled={isSaving} className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-emerald-600 px-3 text-xs font-bold text-white hover:bg-emerald-700 disabled:opacity-60">{isSaving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}Save</button><button type="button" onClick={cancelEditing} disabled={isSaving} className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 text-xs font-bold text-slate-700 dark:border-white/10 dark:bg-slate-900 dark:text-slate-200"><X className="h-3.5 w-3.5" />Cancel</button></div></div>{editFields()}</div> : <div className="flex min-w-[220px] items-center gap-3"><div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-500 text-sm font-bold text-white">{String(transaction.description || "T").trim().charAt(0).toUpperCase()}</div><div className="min-w-0"><p className="truncate font-semibold text-slate-900 dark:text-white">{transaction.description || "Untitled transaction"}</p><p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">ID #{id ?? "—"}</p></div></div>}</td>
              {!editing && <><td className="border-b border-slate-100 px-5 py-4 dark:border-white/5">{categoryBadge(transaction.category)}</td><td className="border-b border-slate-100 px-5 py-4 dark:border-white/5"><p className="text-sm font-semibold text-slate-700 dark:text-slate-200">{formatRelativeDate(transaction.date)}</p><p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{formatDate(transaction.date)}</p></td><td className="border-b border-slate-100 px-5 py-4 text-right dark:border-white/5">{amountBadge(transaction.amount)}</td><td className="border-b border-slate-100 px-6 py-4 dark:border-white/5"><div className="flex justify-end gap-2"><button type="button" onClick={() => startEditing(transaction)} className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/10 text-blue-600 transition hover:bg-blue-600 hover:text-white dark:bg-blue-400/10 dark:text-blue-300" aria-label="Edit transaction"><Pencil className="h-4 w-4" /></button><button type="button" onClick={() => setDeleteTarget(transaction)} className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-rose-500/10 text-rose-600 transition hover:bg-rose-600 hover:text-white dark:bg-rose-400/10 dark:text-rose-300" aria-label="Delete transaction"><Trash2 className="h-4 w-4" /></button></div></td></>}
            </tr>;
          })}
        </tbody></table></div></div>

        {/* Mobile cards */}
        <div className="space-y-3 lg:hidden">{currentTransactions.length === 0 ? <div className="rounded-2xl border border-slate-200/80 bg-white px-5 py-14 text-center shadow-sm dark:border-white/10 dark:bg-slate-900/70"><div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 text-slate-400 dark:bg-white/5"><Receipt className="h-7 w-7" /></div><h2 className="mt-4 text-lg font-bold text-slate-900 dark:text-white">No transactions found</h2><p className="mx-auto mt-2 max-w-xs text-sm leading-6 text-slate-500 dark:text-slate-400">Try changing your search or filter settings.</p></div> : currentTransactions.map((transaction) => {
          const id = getTransactionId(transaction);
          const editing = editingId === id;
          return <article key={id} className="overflow-hidden rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-slate-900/70">{editing ? <><div className="mb-4 flex items-center justify-between"><div><p className="font-bold text-slate-900 dark:text-white">Edit transaction</p><p className="text-xs text-slate-500 dark:text-slate-400">Make changes and save.</p></div><button type="button" onClick={cancelEditing} disabled={isSaving} className="rounded-lg p-2 text-slate-500"><X className="h-4 w-4" /></button></div>{editFields()}<div className="mt-4 grid grid-cols-2 gap-3"><button type="button" onClick={() => saveTransaction(id)} disabled={isSaving} className="inline-flex min-h-11 items-center justify-center gap-2 rounded-xl bg-emerald-600 px-4 py-2.5 text-sm font-bold text-white disabled:opacity-60">{isSaving && <Loader2 className="h-4 w-4 animate-spin" />}Save</button><button type="button" onClick={cancelEditing} disabled={isSaving} className="min-h-11 rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-bold text-slate-700 dark:border-white/10 dark:text-slate-200">Cancel</button></div></> : <><div className="flex items-start justify-between gap-3"><div className="flex min-w-0 items-center gap-3"><div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-500 text-sm font-bold text-white">{String(transaction.description || "T").trim().charAt(0).toUpperCase()}</div><div className="min-w-0"><h2 className="truncate font-bold text-slate-900 dark:text-white">{transaction.description || "Untitled transaction"}</h2><p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{formatRelativeDate(transaction.date)} · {formatDate(transaction.date)}</p></div></div>{categoryBadge(transaction.category)}</div><div className="mt-4 flex items-end justify-between gap-3 border-t border-slate-100 pt-4 dark:border-white/10"><div><p className="text-xs font-medium text-slate-500 dark:text-slate-400">Amount</p><div className="mt-1">{amountBadge(transaction.amount)}</div></div><div className="flex gap-2"><button type="button" onClick={() => startEditing(transaction)} className="inline-flex h-10 w-10 items-center justify-center rounded-xl bg-blue-500/10 text-blue-600 dark:bg-blue-400/10 dark:text-blue-300" aria-label="Edit transaction"><Pencil className="h-4 w-4" /></button><button type="button" onClick={() => setDeleteTarget(transaction)} className="inline-flex h-10 w-10 items-center justify-center rounded-xl bg-rose-500/10 text-rose-600 dark:bg-rose-400/10 dark:text-rose-300" aria-label="Delete transaction"><Trash2 className="h-4 w-4" /></button></div></div></>}</article>;
        })}</div>
      </>}

      {/* Pagination */}
      {!isRefreshing && sortedTransactions.length > 0 && <div className="flex flex-col gap-4 rounded-2xl border border-slate-200/80 bg-white px-4 py-4 shadow-sm dark:border-white/10 dark:bg-slate-900/70 sm:flex-row sm:items-center sm:justify-between sm:px-5"><p className="text-sm text-slate-500 dark:text-slate-400">Showing <span className="font-bold text-slate-900 dark:text-white">{startIndex + 1}–{Math.min(endIndex, sortedTransactions.length)}</span> of <span className="font-bold text-slate-900 dark:text-white">{sortedTransactions.length}</span></p>{totalPages > 1 && <nav className="flex items-center justify-center gap-1.5" aria-label="Transaction pagination"><button type="button" onClick={() => setCurrentPage((page) => Math.max(1, page - 1))} disabled={safePage === 1} className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-slate-600 disabled:opacity-40 dark:border-white/10 dark:text-slate-300" aria-label="Previous page"><ChevronLeft className="h-4 w-4" /></button>{paginationItems.map((item) => typeof item === "string" ? <span key={item} className="inline-flex h-9 w-7 items-center justify-center text-sm text-slate-400">…</span> : <button type="button" key={item} onClick={() => setCurrentPage(item)} aria-current={safePage === item ? "page" : undefined} className={`inline-flex h-9 min-w-9 items-center justify-center rounded-lg px-2 text-sm font-bold ${safePage === item ? "bg-slate-900 text-white dark:bg-white dark:text-slate-900" : "border border-slate-200 text-slate-600 dark:border-white/10 dark:text-slate-300"}`}>{item}</button>)}<button type="button" onClick={() => setCurrentPage((page) => Math.min(totalPages, page + 1))} disabled={safePage === totalPages} className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-slate-600 disabled:opacity-40 dark:border-white/10 dark:text-slate-300" aria-label="Next page"><ChevronRight className="h-4 w-4" /></button></nav>}</div>}

      {/* Footer */}
      <div className="flex flex-col items-center justify-between gap-2 px-1 pb-3 text-center text-xs text-slate-500 dark:text-slate-400 sm:flex-row sm:text-left"><p>All transaction data is updated securely in your account.</p><p className="inline-flex items-center gap-1.5"><CircleDollarSign className="h-3.5 w-3.5 text-emerald-500" />Financial activity dashboard</p></div>

      {/* Delete modal */}
      {deleteTarget && <div className="fixed inset-0 z-50 flex items-end justify-center bg-slate-950/60 p-4 backdrop-blur-sm sm:items-center" role="dialog" aria-modal="true" aria-labelledby="delete-transaction-title" onMouseDown={(event) => { if (event.target === event.currentTarget && !isDeleting) setDeleteTarget(null); }}><div className="w-full max-w-md rounded-3xl border border-white/10 bg-white p-5 shadow-2xl dark:bg-slate-900 sm:p-7"><div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-rose-500/10 text-rose-600 dark:bg-rose-400/10 dark:text-rose-300"><Trash2 className="h-6 w-6" /></div><h2 id="delete-transaction-title" className="mt-5 text-xl font-bold text-slate-900 dark:text-white">Delete transaction?</h2><p className="mt-2 text-sm leading-6 text-slate-500 dark:text-slate-400">You are about to permanently delete <span className="font-semibold text-slate-700 dark:text-slate-200">{deleteTarget.description || "this transaction"}</span>. This action cannot be undone.</p><div className="mt-6 grid grid-cols-2 gap-3"><button type="button" onClick={() => setDeleteTarget(null)} disabled={isDeleting} className="min-h-11 rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-bold text-slate-700 disabled:opacity-60 dark:border-white/10 dark:text-slate-200">Cancel</button><button type="button" onClick={confirmDelete} disabled={isDeleting} className="inline-flex min-h-11 items-center justify-center gap-2 rounded-xl bg-rose-600 px-4 py-2.5 text-sm font-bold text-white hover:bg-rose-700 disabled:opacity-60">{isDeleting ? <><Loader2 className="h-4 w-4 animate-spin" />Deleting...</> : <><Trash2 className="h-4 w-4" />Delete</>}</button></div></div></div>}
    </section>
  );
};

export default RecentTransactions;
