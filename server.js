// KpaKpa backend — payment verification, webhooks, and biker payouts
// Everything that touches the Paystack SECRET KEY lives here, never in the browser.

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const axios = require("axios");

const app = express();

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PORT = process.env.PORT || 4000;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "*";

if (!PAYSTACK_SECRET_KEY) {
  console.warn(
    "\n⚠️  PAYSTACK_SECRET_KEY is not set. Copy .env.example to .env and add your key from dashboard.paystack.com\n"
  );
}

const paystack = axios.create({
  baseURL: "https://api.paystack.co",
  headers: {
    Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
    "Content-Type": "application/json",
  },
});

app.use(cors({ origin: FRONTEND_ORIGIN }));

// Keep the raw body around ONLY for webhook signature verification.
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

// In-memory ledger of verified trips, just for this demo.
// Swap for a real database (Postgres, etc.) before going live.
const verifiedPayments = new Map(); // reference -> { amount, status, at }

/* ---------------------------------------------------------
   HEALTH CHECK
--------------------------------------------------------- */
app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "kpakpa-backend" });
});

/* ---------------------------------------------------------
   VERIFY A PAYMENT
   Called by the frontend right after the Paystack popup
   reports success. Never trust the client-side callback alone —
   always re-check server-side with the secret key.
--------------------------------------------------------- */
app.get("/api/payments/verify/:reference", async (req, res) => {
  const { reference } = req.params;
  try {
    const { data } = await paystack.get(`/transaction/verify/${encodeURIComponent(reference)}`);
    const tx = data.data;
    const success = tx.status === "success";

    if (success) {
      verifiedPayments.set(reference, {
        amount: tx.amount / 100,
        currency: tx.currency,
        status: tx.status,
        at: new Date().toISOString(),
      });
    }

    res.json({
      status: success,
      amount: tx.amount / 100,
      currency: tx.currency,
      paidAt: tx.paid_at,
      reference: tx.reference,
    });
  } catch (err) {
    console.error("Verify error:", err.response?.data || err.message);
    res.status(500).json({ status: false, message: "Could not verify transaction" });
  }
});

/* ---------------------------------------------------------
   WEBHOOK — the reliable source of truth for payment status.
   Paystack calls this directly; register the URL in your
   Paystack dashboard under Settings → API Keys & Webhooks.
--------------------------------------------------------- */
app.post("/api/webhooks/paystack", (req, res) => {
  const signature = req.headers["x-paystack-signature"];
  const expected = crypto
    .createHmac("sha512", PAYSTACK_SECRET_KEY || "")
    .update(req.rawBody)
    .digest("hex");

  if (signature !== expected) {
    console.warn("Webhook signature mismatch — ignoring event");
    return res.sendStatus(401);
  }

  const event = req.body;

  if (event.event === "charge.success") {
    const tx = event.data;
    verifiedPayments.set(tx.reference, {
      amount: tx.amount / 100,
      currency: tx.currency,
      status: "success",
      at: new Date().toISOString(),
    });
    console.log(`✅ Payment confirmed via webhook: ${tx.reference} (₦${tx.amount / 100})`);
  }

  if (event.event === "transfer.success" || event.event === "transfer.failed") {
    console.log(`Transfer event: ${event.event}`, event.data.reference);
  }

  // Always 200 quickly so Paystack doesn't retry unnecessarily.
  res.sendStatus(200);
});

/* ---------------------------------------------------------
   LIST BANKS — populates the bank dropdown for payouts.
--------------------------------------------------------- */
app.get("/api/banks", async (req, res) => {
  try {
    const { data } = await paystack.get("/bank?country=nigeria&currency=NGN");
    const banks = data.data.map((b) => ({ name: b.name, code: b.code }));
    res.json({ status: true, banks });
  } catch (err) {
    console.error("Bank list error:", err.response?.data || err.message);
    res.status(500).json({ status: false, banks: [], message: "Could not fetch bank list" });
  }
});

/* ---------------------------------------------------------
   RESOLVE ACCOUNT NAME — confirms the account number/bank
   combo is real before money gets sent to it.
--------------------------------------------------------- */
app.post("/api/banks/resolve", async (req, res) => {
  const { account_number, bank_code } = req.body;
  if (!account_number || !bank_code) {
    return res.status(400).json({ status: false, message: "account_number and bank_code are required" });
  }
  try {
    const { data } = await paystack.get("/bank/resolve", {
      params: { account_number, bank_code },
    });
    res.json({ status: true, account_name: data.data.account_name });
  } catch (err) {
    console.error("Resolve error:", err.response?.data || err.message);
    res.status(400).json({
      status: false,
      message: err.response?.data?.message || "Could not resolve account",
    });
  }
});

/* ---------------------------------------------------------
   WITHDRAW / PAYOUT — pays a biker's wallet balance out to
   their bank account. Two Paystack calls: create a transfer
   recipient, then initiate the transfer.

   NOTE: In TEST mode, Paystack may require OTP finalization
   for transfers. Turn off "Require OTP for test transfers" in
   Dashboard → Settings → Preferences to let this run end-to-end
   while you're developing.
--------------------------------------------------------- */
app.post("/api/withdraw", async (req, res) => {
  const { account_number, bank_code, account_name, amount } = req.body;

  if (!account_number || !bank_code || !account_name || !amount) {
    return res.status(400).json({
      status: false,
      message: "account_number, bank_code, account_name and amount are required",
    });
  }
  if (amount <= 0) {
    return res.status(400).json({ status: false, message: "Nothing to withdraw" });
  }

  try {
    const recipientRes = await paystack.post("/transferrecipient", {
      type: "nuban",
      name: account_name,
      account_number,
      bank_code,
      currency: "NGN",
    });
    const recipientCode = recipientRes.data.data.recipient_code;

    const transferRes = await paystack.post("/transfer", {
      source: "balance",
      amount: Math.round(amount * 100),
      recipient: recipientCode,
      reason: "KpaKpa biker payout",
    });

    res.json({
      status: true,
      transferCode: transferRes.data.data.transfer_code,
      transferStatus: transferRes.data.data.status, // 'success' | 'pending' | 'otp'
    });
  } catch (err) {
    console.error("Withdraw error:", err.response?.data || err.message);
    res.status(400).json({
      status: false,
      message: err.response?.data?.message || "Transfer failed",
    });
  }
});

app.listen(PORT, () => {
  console.log(`KpaKpa backend running on http://localhost:${PORT}`);
});