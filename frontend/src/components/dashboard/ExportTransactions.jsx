import { saveAs } from "file-saver";

const ExportTransactions = ({
  transactions,
}) => {

  const handleExport = () => {

    const csvRows = [

      [
        "Description",
        "Category",
        "Amount",
        "Date",
      ],

      ...transactions.map(
        (transaction) => [

          transaction.description,
          transaction.category,
          transaction.amount,
          transaction.date,

        ]
      ),

    ];

    const csvContent =
      csvRows
        .map(
          (row) =>
            row.join(",")
        )
        .join("\n");

    const blob =
      new Blob(
        [csvContent],
        {
          type: "text/csv;charset=utf-8",
        }
      );

    saveAs(
      blob,
      "transactions.csv"
    );

  };

  return (

    <button
      onClick={handleExport}
      className="
        bg-emerald-600
        text-white
        px-5
        py-3
        rounded-lg
        hover:bg-emerald-700
      "
    >
      Export CSV
    </button>

  );

};

export default ExportTransactions;