const nodemailer =
require("nodemailer");

const transporter =
nodemailer.createTransport({

  service: "gmail",

  auth: {

    user:
      process.env.EMAIL_USER,

    pass:
      process.env.EMAIL_PASS,

  },

});

exports.sendReminder =
async (
  email,
  subscription
) => {

  await transporter.sendMail({

    from:
      process.env.EMAIL_USER,

    to:
      email,

    subject:
      "FinanceEase Subscription Reminder",

    text:
      `Your ${subscription.name} subscription is due on ${subscription.next_due}.`,

  });

};