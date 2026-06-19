const express = require("express");

const router = express.Router();

const auth =
require("../middleware/auth");

const transactionController =
require("../controllers/transactionController");

router.post(
  "/",
  auth,
  transactionController.addTransaction
);

router.get(
  "/",
  auth,
  transactionController.getTransactions
);

router.put(
  "/:id",
  auth,
  transactionController.updateTransaction
);

router.delete(
  "/:id",
  auth,
  transactionController.deleteTransaction
);

module.exports = router;
