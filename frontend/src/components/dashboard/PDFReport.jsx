import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
const generatePDF = () => {

  const doc = new jsPDF();

  doc.text(
    "FinanceEase Report",
    14,
    15
  );

  autoTable(doc, {
    head: [[
      "Description",
      "Category",
      "Amount",
      "Date"
    ]],

    body: transactions.map(
      (transaction) => [

        transaction.description,
        transaction.category,
        transaction.amount,
        transaction.date,

      ]
    ),
  });

  doc.save(
    "FinanceEase_Report.pdf"
  );

};

<button
  onClick={generatePDF}
  className="
    bg-indigo-600
    text-white
    px-5
    py-3
    rounded-lg
  "
>
  Download PDF Report
</button>