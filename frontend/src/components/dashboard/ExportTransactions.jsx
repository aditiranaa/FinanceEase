import { saveAs } from "file-saver";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import {
  Download,
  FileSpreadsheet,
  FileText,
} from "lucide-react";

export default function ExportTransactions({
  transactions,
}) {
  const handleCSVExport = () => {
    const csvRows = [
      [
        "Description",
        "Category",
        "Amount",
        "Date",
      ],

      ...transactions.map((transaction) => [
        transaction.description,
        transaction.category,
        transaction.amount,
        transaction.date,
      ]),
    ];

    const csvContent = csvRows
      .map((row) => row.join(","))
      .join("\n");

    const blob = new Blob(
      [csvContent],
      {
        type: "text/csv;charset=utf-8",
      }
    );

    saveAs(blob, "FinanceEase_Transactions.csv");
  };

  const handlePDFExport = () => {
    const doc = new jsPDF();

    doc.setFontSize(18);
    doc.text("FinanceEase Report", 14, 18);

    autoTable(doc, {
      startY: 28,
      head: [[
        "Description",
        "Category",
        "Amount",
        "Date",
      ]],
      body: transactions.map((transaction) => [
        transaction.description,
        transaction.category,
        transaction.amount,
        transaction.date,
      ]),
    });

    doc.save("FinanceEase_Report.pdf");
  };

  return (
    <section className="rounded-3xl border border-gray-200 bg-white p-7 shadow-sm">
      <div className="flex items-center gap-4">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-emerald-100">
          <FileSpreadsheet
            size={28}
            className="text-emerald-600"
          />
        </div>

        <div>
          <h2 className="text-2xl font-bold text-gray-900">
            Export Reports
          </h2>

          <p className="mt-1 text-sm text-gray-500">
            Download your financial data in CSV or PDF format.
          </p>
        </div>
      </div>

      <div className="mt-8 space-y-4">
        <button
          onClick={handleCSVExport}
          className="flex h-12 w-full items-center justify-center gap-2 rounded-xl bg-emerald-600 font-semibold text-white transition hover:bg-emerald-700"
        >
          <Download size={18} />
          Export CSV
        </button>

        <button
          onClick={handlePDFExport}
          className="flex h-12 w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 font-semibold text-white transition hover:bg-indigo-700"
        >
          <FileText size={18} />
          Export PDF Report
        </button>
      </div>
    </section>
  );
}