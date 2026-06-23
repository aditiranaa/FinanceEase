const PDFDocument =
require("pdfkit");

const knex =
require("../config/db");

exports.generatePDF =
async (req, res) => {

  try {

    const transactions =
      await knex(
        "transactions"
      )
      .where({
        user_id:
          req.user.id,
      });

    let income = 0;
    let expenses = 0;

    transactions.forEach(
      transaction => {

        const amount =
          Number(
            transaction.amount
          );

        if (
          amount > 0
        ) {

          income += amount;

        }

        else {

          expenses +=
            Math.abs(amount);

        }

      }
    );

    const balance =
      income - expenses;

    const doc =
      new PDFDocument();

    const path =
    require("path");

    const fontPath =
    path.join(
    __dirname,
    "../../fonts/NotoSans-Regular.ttf"
    );

    doc.font(
    fontPath
    );

    res.setHeader(
      "Content-Type",
      "application/pdf"
    );

    res.setHeader(
      "Content-Disposition",
      "attachment; filename=FinanceEase_Report.pdf"
    );

    doc.pipe(res);

    doc
      .fontSize(20)
      .text(
        "FinanceEase Report"
      );

    doc.moveDown();

    doc.text(
    `Income: ₹${income}`
    );

    doc.text(
    `Expenses: ₹${expenses}`
    );

    doc.text(
    `Balance: ₹${balance}`
    );

    doc.moveDown();

    doc.text(
      "Transactions"
    );

    doc.moveDown();

    transactions.forEach(
      transaction => {

        doc.text(
        `${transaction.date} | ${transaction.category} | ₹${transaction.amount}`
        );

      }
    );

    doc.end();

  }

  catch (error) {

    res.status(500).json({

      error:
        error.message,

    });

  }

};