
import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowDownRight,
  ArrowUpDown,
  ArrowUpRight,
  Calendar,
  CalendarDays,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
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
  MoreHorizontal,
  Plus,
  ShoppingBag,
  Utensils,
  CreditCard,
  Plane,
  HeartPulse,
  Film,
  HelpCircle,
  Landmark,
  AlertTriangle,
} from "lucide-react";
import toast from "react-hot-toast";

import { deleteTransaction, updateTransaction, createTransaction } from "../../api/authApi";

/* ========================================================================== */
/* Constants and helpers                                                       */
/* ========================================================================== */

const TRANSACTIONS_PER_PAGE = 8;

const CATEGORY_STYLES = {
  salary: "bg-emerald-50 text-emerald-700 border-emerald-200/50 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/20",
  food: "bg-orange-50 text-orange-700 border-orange-200/50 dark:bg-orange-500/10 dark:text-orange-400 dark:border-orange-500/20",
  shopping: "bg-pink-50 text-pink-700 border-pink-200/50 dark:bg-pink-500/10 dark:text-pink-400 dark:border-pink-500/20",
  bills: "bg-rose-50 text-rose-700 border-rose-200/50 dark:bg-rose-500/10 dark:text-rose-400 dark:border-rose-500/20",
  travel: "bg-blue-50 text-blue-700 border-blue-200/50 dark:bg-blue-500/10 dark:text-blue-400 dark:border-blue-500/20",
  health: "bg-violet-50 text-violet-700 border-violet-200/50 dark:bg-violet-500/10 dark:text-violet-400 dark:border-violet-500/20",
  entertainment: "bg-amber-50 text-amber-700 border-amber-200/50 dark:bg-amber-500/10 dark:text-amber-400 dark:border-amber-500/20",
  investment: "bg-cyan-50 text-cyan-700 border-cyan-200/50 dark:bg-cyan-500/10 dark:text-cyan-400 dark:border-cyan-500/20",
  other: "bg-slate-50 text-slate-700 border-slate-200/50 dark:bg-slate-500/10 dark:text-slate-400 dark:border-slate-500/20",
};

const CATEGORY_ICONS = {
  salary: TrendingUp,
  food: Utensils,
  shopping: ShoppingBag,
  bills: CreditCard,
  travel: Plane,
  health: HeartPulse,
  entertainment: Film,
  investment: Landmark,
  other: HelpCircle,
};

const inputClass =
  "w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-4 focus:ring-blue-500/10 dark:border-white/10 dark:bg-slate-900/80 dark:text-white dark:placeholder:text-slate-500 dark:focus:border-blue-400";

const toolbarSelectClass =
  "rounded-lg border border-slate-200 bg-white pl-8 pr-8 py-2 text-xs font-semibold text-slate-600 appearance-none outline-none hover:border-slate-300 dark:border-white/10 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-white/20 transition-all cursor-pointer";

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
  const result = `$${Math.abs(amount).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
  return withSign ? `${amount >= 0 ? "+" : "-"}${result}` : result;
};

const formatDate = (value) => {
  const date = getDate(value);
  if (!date) return "No date";
  return new Intl.DateTimeFormat("en-US", {
    day: "numeric",
    month: "short",
    year: "numeric",
  }).format(date);
};

const formatRelativeDate = (value) => {
  const date = getDate(value);
  if (!date) return "Unknown date";
  return formatDate(value);
};

const categoryClass = (category) =>
  CATEGORY_STYLES[String(category || "other").trim().toLowerCase()] ||
  CATEGORY_STYLES.other;

const getCategoryIcon = (category) => {
  const name = String(category || "other").trim().toLowerCase();
  return CATEGORY_ICONS[name] || CATEGORY_ICONS.other;
};

const getCategoryIconStyles = (category) => {
  const name = String(category || "other").trim().toLowerCase();
  switch (name) {
    case "salary":
      return "bg-emerald-500/10 text-emerald-600 dark:bg-emerald-500/20 dark:text-emerald-400";
    case "food":
      return "bg-orange-500/10 text-orange-600 dark:bg-orange-500/20 dark:text-orange-400";
    case "shopping":
      return "bg-pink-500/10 text-pink-600 dark:bg-pink-500/20 dark:text-pink-400";
    case "bills":
      return "bg-red-500/10 text-red-600 dark:bg-red-500/20 dark:text-red-400";
    case "travel":
      return "bg-blue-500/10 text-blue-600 dark:bg-blue-500/20 dark:text-blue-400";
    case "health":
      return "bg-violet-500/10 text-violet-600 dark:bg-violet-500/20 dark:text-violet-400";
    case "entertainment":
      return "bg-amber-500/10 text-amber-600 dark:bg-amber-500/20 dark:text-amber-400";
    case "investment":
      return "bg-cyan-500/10 text-cyan-600 dark:bg-cyan-500/20 dark:text-cyan-400";
    default:
      return "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400";
  }
};

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
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [sortBy, setSortBy] = useState("newest");
  const [currentPage, setCurrentPage] = useState(1);

  /* CRUD modals and states */
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [addData, setAddData] = useState({ description: "", category: "", amount: "", date: "" });
  
  const [editingId, setEditingId] = useState(null);
  const [editData, setEditData] = useState({ description: "", category: "", amount: "", date: "" });
  const [deleteTarget, setDeleteTarget] = useState(null);
  
  const [activeMenuId, setActiveMenuId] = useState(null);
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => setCurrentPage(1), [searchTerm, categoryFilter, sortBy]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key !== "Escape") return;
      if (deleteTarget && !isDeleting) setDeleteTarget(null);
      if (editingId && !isSaving) setEditingId(null);
      if (isAddModalOpen && !isSaving) setIsAddModalOpen(false);
      setActiveMenuId(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [deleteTarget, editingId, isDeleting, isSaving, isAddModalOpen]);

  /* Extract unique categories dynamically */
  const categoriesList = useMemo(() => {
    const list = new Set();
    transactions.forEach((t) => {
      if (t.category) {
        list.add(t.category.trim().toLowerCase());
      }
    });
    return ["all", ...Array.from(list)];
  }, [transactions]);

  /* Filtering */
  const filteredTransactions = useMemo(() => {
    const search = searchTerm.trim().toLowerCase();
    return transactions.filter((transaction) => {
      const description = String(transaction.description || "").toLowerCase();
      const category = String(transaction.category || "").toLowerCase();
      
      if (search && !description.includes(search) && !category.includes(search)) return false;
      if (categoryFilter !== "all" && category !== categoryFilter.toLowerCase()) return false;
      
      return true;
    });
  }, [transactions, searchTerm, categoryFilter]);

  /* Sorting */
  const sortedTransactions = useMemo(() => {
    const sorted = [...filteredTransactions];
    sorted.sort((a, b) => {
      const aDate = getDate(a.date)?.getTime() || 0;
      const bDate = getDate(b.date)?.getTime() || 0;
      const aAmount = toAmount(a.amount);
      const bAmount = toAmount(b.amount);
      if (sortBy === "oldest") return aDate - bDate;
      if (sortBy === "highest") return Math.abs(bAmount) - Math.abs(aAmount);
      if (sortBy === "lowest") return Math.abs(aAmount) - Math.abs(bAmount);
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

  /* CRUD Operations */
  const handleAddSubmit = async (e) => {
    e.preventDefault();
    const description = addData.description.trim();
    const category = addData.category.trim();
    const amount = Number(addData.amount);
    if (!description || !category || !addData.date || !Number.isFinite(amount)) {
      toast.error("Please complete all fields with a valid amount.");
      return;
    }
    try {
      setIsSaving(true);
      await createTransaction({ description, category, amount, date: addData.date });
      toast.success("Transaction added successfully");
      setAddData({ description: "", category: "", amount: "", date: "" });
      setIsAddModalOpen(false);
      fetchTransactions?.();
    } catch (error) {
      console.error(error);
      toast.error("Failed to add transaction");
    } finally {
      setIsSaving(false);
    }
  };

  const startEditing = useCallback((transaction) => {
    setEditingId(getTransactionId(transaction));
    setEditData({
      description: transaction.description || "",
      category: transaction.category || "",
      amount: String(transaction.amount ?? ""),
      date: toDateInput(transaction.date),
    });
    setActiveMenuId(null);
  }, []);

  const cancelEditing = useCallback(() => {
    setEditingId(null);
    setEditData({ description: "", category: "", amount: "", date: "" });
  }, []);

  const saveTransaction = useCallback(async (e) => {
    e.preventDefault();
    const id = editingId;
    const description = editData.description.trim();
    const category = editData.category.trim();
    const amount = Number(editData.amount);
    if (!description || !category || !editData.date || !Number.isFinite(amount)) {
      toast.error("Please complete all fields with a valid amount.");
      return;
    }
    try {
      setIsSaving(true);
      await updateTransaction(id, { description, category, amount, date: editData.date });
      toast.success("Transaction updated successfully");
      cancelEditing();
      fetchTransactions?.();
    } catch (error) {
      console.error(error);
      toast.error("Failed to update transaction");
    } finally {
      setIsSaving(false);
    }
  }, [cancelEditing, editData, editingId, fetchTransactions]);

  const confirmDelete = useCallback(async () => {
    const id = getTransactionId(deleteTarget);
    if (id === undefined || id === null) return;
    try {
      setIsDeleting(true);
      await deleteTransaction(id);
      toast.success("Transaction deleted successfully");
      setDeleteTarget(null);
      fetchTransactions?.();
    } catch (error) {
      console.error(error);
      toast.error("Failed to delete transaction");
    } finally {
      setIsDeleting(false);
    }
  }, [deleteTarget, fetchTransactions]);

  const categoryBadge = (category) => (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-semibold border capitalize ${categoryClass(category)}`}>
      {category || "Other"}
    </span>
  );

  const amountBadge = (amount) => {
    const isIncome = toAmount(amount) >= 0;
    return (
      <span className={`text-xs md:text-sm font-bold tracking-tight shrink-0 ${isIncome ? "text-emerald-600 dark:text-emerald-400" : "text-slate-700 dark:text-slate-300"}`}>
        {isIncome ? "+" : "-"}
        {formatCurrency(amount)}
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {/* Yellow Pending Warning Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-amber-50/70 dark:bg-amber-950/20 border border-amber-200/50 dark:border-amber-800/30 rounded-2xl p-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-amber-100 dark:bg-amber-900/30 rounded-xl text-amber-600 dark:text-amber-400 shrink-0">
            <AlertTriangle className="h-5 w-5" />
          </div>
          <div>
            <h4 className="text-xs font-bold text-slate-800 dark:text-slate-200">
              You have 3 pending items that need your attention.
            </h4>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
              Review and categorize your transactions to keep your finances up to date.
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => setCategoryFilter("other")}
          className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-amber-200 bg-white/80 dark:border-amber-900/30 dark:bg-slate-900 px-3 py-1.5 text-xs font-bold text-amber-700 dark:text-amber-400 shadow-sm hover:bg-amber-50 dark:hover:bg-amber-900/20 transition self-stretch sm:self-center"
        >
          Review Pending Items
          <ChevronRight className="h-3 w-3" />
        </button>
      </div>

      {/* Toolbar / Filters (Mockup Style) */}
      <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center sm:justify-between bg-white dark:bg-slate-900 border border-slate-100 dark:border-white/[0.05] rounded-xl p-3.5 shadow-sm">
        <div className="relative flex-1 max-w-xs">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
          <input
            type="search"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search transactions..."
            className="w-full rounded-lg border border-slate-200 bg-white pl-8 pr-3.5 py-1.5 text-xs font-medium text-slate-700 outline-none transition placeholder:text-slate-400 focus:border-blue-500 dark:border-white/10 dark:bg-slate-900 dark:text-white dark:placeholder:text-slate-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 self-end sm:self-auto">
          {/* Category Dropdown */}
          <div className="relative">
            <Filter className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className={toolbarSelectClass}
            >
              <option value="all">All Categories</option>
              {categoriesList.filter(c => c !== "all").map((cat) => (
                <option key={cat} value={cat}>
                  {cat.charAt(0).toUpperCase() + cat.slice(1)}
                </option>
              ))}
            </select>
            <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
          </div>

          {/* Sort Dropdown */}
          <div className="relative">
            <ArrowUpDown className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className={toolbarSelectClass}
            >
              <option value="newest">Sort: Newest First</option>
              <option value="oldest">Sort: Oldest First</option>
              <option value="highest">Sort: Highest Amount</option>
              <option value="lowest">Sort: Lowest Amount</option>
            </select>
            <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
          </div>

          {/* Add Transaction Button */}
          <button
            type="button"
            onClick={() => setIsAddModalOpen(true)}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 px-3.5 text-xs font-bold text-white shadow-sm shadow-blue-500/15 transition"
          >
            <Plus className="h-3.5 w-3.5" />
            Add Transaction
          </button>
        </div>
      </div>

      {/* Grid of Transaction Cards */}
      {currentTransactions.length === 0 ? (
        <div className="rounded-2xl border border-slate-200/60 bg-white/40 dark:border-white/10 dark:bg-slate-900/40 px-5 py-16 text-center shadow-sm">
          <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-xl bg-slate-100 text-slate-400 dark:bg-white/5">
            <Receipt className="h-5 w-5" />
          </div>
          <h3 className="mt-4 text-sm font-bold text-slate-900 dark:text-white">No transactions found</h3>
          <p className="mx-auto mt-1 max-w-xs text-xs text-slate-500 dark:text-slate-400">Try changing your search or filter settings.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
          {currentTransactions.map((transaction) => {
            const id = getTransactionId(transaction);
            const CategoryIcon = getCategoryIcon(transaction.category);
            
            return (
              <article
                key={id}
                className="relative flex flex-col justify-between overflow-visible rounded-xl border border-slate-100 bg-white p-4 shadow-sm hover:shadow-md dark:border-white/[0.05] dark:bg-slate-900 transition"
              >
                {/* Card Header: Date & Menu */}
                <div className="flex items-center justify-between pb-3">
                  <div className="flex items-center gap-1.5 text-[10px] font-semibold text-slate-400 dark:text-slate-500">
                    <Calendar className="h-3 w-3" />
                    {formatRelativeDate(transaction.date)}
                  </div>
                  
                  {/* Option Popover Trigger */}
                  <div className="relative">
                    <button
                      type="button"
                      onClick={() => setActiveMenuId(activeMenuId === id ? null : id)}
                      className="p-1 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-slate-400 dark:text-slate-500 hover:text-slate-600 transition"
                    >
                      <MoreHorizontal className="h-3.5 w-3.5" />
                    </button>
                    
                    {activeMenuId === id && (
                      <>
                        <div className="fixed inset-0 z-10" onClick={() => setActiveMenuId(null)} />
                        <div className="absolute right-0 mt-1 w-24 rounded-lg border border-slate-100 dark:border-white/[0.08] bg-white p-1 shadow-lg dark:bg-slate-900 z-20">
                          <button
                            type="button"
                            onClick={() => startEditing(transaction)}
                            className="w-full text-left flex items-center gap-2 px-2.5 py-1.5 text-xs font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 rounded-md transition"
                          >
                            <Pencil className="h-3 w-3" />
                            Edit
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setDeleteTarget(transaction);
                              setActiveMenuId(null);
                            }}
                            className="w-full text-left flex items-center gap-2 px-2.5 py-1.5 text-xs font-bold text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/20 rounded-md transition"
                          >
                            <Trash2 className="h-3 w-3" />
                            Delete
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </div>

                {/* Card Middle: Icon, Details & Amount */}
                <div className="flex items-center gap-3 py-1">
                  <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full shadow-sm ${getCategoryIconStyles(transaction.category)}`}>
                    <CategoryIcon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <h4 className="truncate text-xs font-bold text-slate-800 dark:text-slate-100 leading-tight">
                      {transaction.description || "Untitled Transaction"}
                    </h4>
                    <p className="truncate text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 font-medium leading-none">
                      {transaction.category || "General Expense"}
                    </p>
                  </div>
                  {amountBadge(transaction.amount)}
                </div>

                {/* Card Bottom: Category Badge */}
                <div className="mt-3.5 pt-3 border-t border-slate-100/60 dark:border-white/[0.04] flex items-center justify-between">
                  {categoryBadge(transaction.category)}
                  <span className="text-[8px] text-slate-400 dark:text-slate-500 font-mono">
                    #{id?.substring(Math.max(0, id.length - 6)) ?? "—"}
                  </span>
                </div>
              </article>
            );
          })}
        </div>
      )}

      {/* Pagination (Mockup Style) */}
      {sortedTransactions.length > 0 && (
        <div className="flex flex-col gap-3 rounded-xl border border-slate-100 dark:border-white/[0.04] bg-slate-50/10 px-3 py-3 sm:flex-row sm:items-center sm:justify-between text-xs">
          <p className="text-slate-500 dark:text-slate-400 font-medium">
            Showing <span className="font-bold text-slate-700 dark:text-slate-200">{startIndex + 1}–{Math.min(endIndex, sortedTransactions.length)}</span> of <span className="font-bold text-slate-700 dark:text-slate-200">{sortedTransactions.length}</span>
          </p>
          {totalPages > 1 && (
            <nav className="flex items-center justify-center gap-1" aria-label="Transaction pagination">
              <button
                type="button"
                onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
                disabled={safePage === 1}
                className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-200 text-slate-600 disabled:opacity-40 hover:bg-slate-50 dark:border-white/10 dark:text-slate-300 dark:hover:bg-slate-800 transition"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              {paginationItems.map((item, idx) =>
                typeof item === "string" ? (
                  <span key={`ellipsis-${idx}`} className="inline-flex h-8 w-5 items-center justify-center text-xs text-slate-400">
                    …
                  </span>
                ) : (
                  <button
                    type="button"
                    key={`page-${item}`}
                    onClick={() => setCurrentPage(item)}
                    aria-current={safePage === item ? "page" : undefined}
                    className={`inline-flex h-8 min-w-8 items-center justify-center rounded-md px-1.5 text-xs font-bold ${safePage === item ? "bg-blue-600 text-white rounded-md" : "border border-slate-200 text-slate-600 dark:border-white/10 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"} transition`}
                  >
                    {item}
                  </button>
                )
              )}
              <button
                type="button"
                onClick={() => setCurrentPage((page) => Math.min(totalPages, page + 1))}
                disabled={safePage === totalPages}
                className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-200 text-slate-600 disabled:opacity-40 hover:bg-slate-50 dark:border-white/10 dark:text-slate-300 dark:hover:bg-slate-800 transition"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </nav>
          )}
        </div>
      )}

      {/* Add Transaction Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4 backdrop-blur-sm" role="dialog" aria-modal="true">
          <div className="w-full max-w-md rounded-2xl border border-slate-100 dark:border-white/[0.08] bg-white p-5 shadow-2xl dark:bg-slate-900">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-white/[0.04]">
              <h3 className="text-base font-bold text-slate-900 dark:text-white">Add Transaction</h3>
              <button type="button" onClick={() => setIsAddModalOpen(false)} className="rounded-lg p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                <X className="h-4 w-4" />
              </button>
            </div>
            <form onSubmit={handleAddSubmit} className="space-y-3.5 mt-4">
              <div>
                <label className="mb-1 block text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">Description</label>
                <input required className={inputClass} placeholder="e.g. Walmart Supercenter" value={addData.description} onChange={(e) => setAddData({ ...addData, description: e.target.value })} />
              </div>
              <div className="grid grid-cols-2 gap-3.5">
                <div>
                  <label className="mb-1 block text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">Category</label>
                  <input required className={inputClass} placeholder="e.g. Shopping" value={addData.category} onChange={(e) => setAddData({ ...addData, category: e.target.value })} />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">Amount</label>
                  <input required type="number" step="0.01" className={inputClass} placeholder="e.g. -82.47 or 3200" value={addData.amount} onChange={(e) => setAddData({ ...addData, amount: e.target.value })} />
                </div>
              </div>
              <div>
                <label className="mb-1 block text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">Date</label>
                <input required type="date" className={inputClass} value={addData.date} onChange={(e) => setAddData({ ...addData, date: e.target.value })} />
              </div>
              <div className="mt-5 grid grid-cols-2 gap-2">
                <button type="button" onClick={() => setIsAddModalOpen(false)} className="min-h-10 rounded-lg border border-slate-200 px-4 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-white/10 dark:text-slate-200 dark:hover:bg-slate-800 transition">
                  Cancel
                </button>
                <button type="submit" disabled={isSaving} className="inline-flex min-h-10 items-center justify-center gap-1.5 rounded-lg bg-blue-600 px-4 text-xs font-bold text-white hover:bg-blue-700 disabled:opacity-60 transition">
                  {isSaving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
                  Add Transaction
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Transaction Modal */}
      {editingId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4 backdrop-blur-sm" role="dialog" aria-modal="true">
          <div className="w-full max-w-md rounded-2xl border border-slate-100 dark:border-white/[0.08] bg-white p-5 shadow-2xl dark:bg-slate-900">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-white/[0.04]">
              <h3 className="text-base font-bold text-slate-900 dark:text-white">Edit Transaction</h3>
              <button type="button" onClick={cancelEditing} className="rounded-lg p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                <X className="h-4 w-4" />
              </button>
            </div>
            <form onSubmit={saveTransaction} className="space-y-3.5 mt-4">
              <div>
                <label className="mb-1 block text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">Description</label>
                <input required className={inputClass} value={editData.description} onChange={(e) => setEditData({ ...editData, description: e.target.value })} />
              </div>
              <div className="grid grid-cols-2 gap-3.5">
                <div>
                  <label className="mb-1 block text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">Category</label>
                  <input required className={inputClass} value={editData.category} onChange={(e) => setEditData({ ...editData, category: e.target.value })} />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">Amount</label>
                  <input required type="number" step="0.01" className={inputClass} value={editData.amount} onChange={(e) => setEditData({ ...editData, amount: e.target.value })} />
                </div>
              </div>
              <div>
                <label className="mb-1 block text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">Date</label>
                <input required type="date" className={inputClass} value={editData.date} onChange={(e) => setEditData({ ...editData, date: e.target.value })} />
              </div>
              <div className="mt-5 grid grid-cols-2 gap-2">
                <button type="button" onClick={cancelEditing} className="min-h-10 rounded-lg border border-slate-200 px-4 text-xs font-semibold text-slate-700 hover:bg-slate-50 dark:border-white/10 dark:text-slate-200 dark:hover:bg-slate-800 transition">
                  Cancel
                </button>
                <button type="submit" disabled={isSaving} className="inline-flex min-h-10 items-center justify-center gap-1.5 rounded-lg bg-blue-600 px-4 text-xs font-bold text-white hover:bg-blue-700 disabled:opacity-60 transition">
                  {isSaving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="delete-transaction-title" onMouseDown={(event) => { if (event.target === event.currentTarget && !isDeleting) setDeleteTarget(null); }}>
          <div className="w-full max-w-sm rounded-2xl border border-slate-100 dark:border-white/[0.08] bg-white p-5 shadow-xl dark:bg-slate-900">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-rose-500/10 text-rose-600 dark:bg-rose-400/10 dark:text-rose-300">
              <Trash2 className="h-5 w-5" />
            </div>
            <h3 id="delete-transaction-title" className="mt-4 text-base font-bold text-slate-900 dark:text-white">Delete Transaction</h3>
            <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400 leading-normal">
              Are you sure you want to permanently delete <span className="font-semibold text-slate-700 dark:text-slate-200">{deleteTarget.description || "this transaction"}</span>? This action cannot be undone.
            </p>
            <div className="mt-5 grid grid-cols-2 gap-2">
              <button type="button" onClick={() => setDeleteTarget(null)} disabled={isDeleting} className="min-h-9 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-700 disabled:opacity-60 dark:border-white/10 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition">
                Cancel
              </button>
              <button type="button" onClick={confirmDelete} disabled={isDeleting} className="inline-flex min-h-9 items-center justify-center gap-1.5 rounded-lg bg-rose-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-rose-700 disabled:opacity-60 transition">
                {isDeleting ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    Deleting...
                  </>
                ) : (
                  <>
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RecentTransactions;
