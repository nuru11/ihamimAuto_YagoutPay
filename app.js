const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const mysql = require('mysql2');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ------------------------ CONFIG ------------------------
const DEFAULT_MERCHANT_ID = "202508080001";
const DEFAULT_MERCHANT_KEY = "IG3CNW5uNrUO2mU2htUOWb9rgXCF7XMAXmL63d7wNZo=";
const AGGREGATOR_ID = "yagout";
const SUCCESS_URL = "http://192.168.1.69:3000/success";
const FAILURE_URL = "http://192.168.1.69:3000/failure";
const TEST_URL = "https://uatcheckout.yagoutpay.com/ms-transaction-core-1-0/paymentRedirection/checksumGatewayPage";
const CURRENCY_FROM = "ETH";
const CURRENCY_TO = "ETB";

// ------------------------ APP SETUP ------------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ------------------------ DATABASE ------------------------

// MySQL Connection
const db = mysql.createConnection({
  host: '91.204.209.19',
  user: 'easyapim_ihamim_multi_user',       // change this
  password: 'nuru@123456',       // change this
  database: 'easyapim_ihamim_multi' // your database name
});

db.connect(err => {
  if (err) {
    console.error("❌ Database connection failed:", err);
  } else {
    console.log("✅ Connected to MySQL database");
  }
});

// ------------------------ HELPER FUNCTIONS ------------------------
const IV = Buffer.from("0123456789abcdef", "utf-8"); 

function getAesAlgorithm(keyBuffer) {
  const len = keyBuffer.length;
  if (len === 16) return 'aes-128-cbc';
  if (len === 24) return 'aes-192-cbc';
  if (len === 32) return 'aes-256-cbc';
  throw new Error("Invalid key length. Must be 16, 24, or 32 bytes.");
}

function encrypt(text, base64Key) {
  const key = Buffer.from(base64Key, 'base64');
  const algorithm = getAesAlgorithm(key);
  const cipher = crypto.createCipheriv(algorithm, key, IV);
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

function decrypt(encryptedBase64, base64Key) {
  const key = Buffer.from(base64Key, 'base64');
  const algorithm = getAesAlgorithm(key);           
  const decipher = crypto.createDecipheriv(algorithm, key, IV);
  let decrypted = decipher.update(encryptedBase64, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function generateSha256Hash(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

// ------------------------ TEMP USER STORAGE ------------------------
// Stores user info keyed by orderNumber
const userCache = {};

// ------------------------ ROUTES ------------------------
app.get('/', (req, res) => {
  // res.redirect('/transaction');
  res.render('transaction');
});

app.get('/transaction', (req, res) => {
  const { amount, mobile_number, user_id } = req.query;

  const orderNumber = "ORDER_" + crypto.randomBytes(4).toString('hex');
  console.log(`🟡 Starting transaction for user ${user_id} with order ${orderNumber}`);

  // Save pending record to DB
  const pendingSql = `
    INSERT INTO transactions (
      user_id, phone_number, order_id, amount, currency_from, currency_to, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', NOW())
  `;
  db.query(
    pendingSql,
    [user_id, mobile_number, orderNumber, amount, 'ETH', 'ETB'],
    (err) => {
      if (err) console.error("❌ Failed to insert pending transaction:", err);
      else console.log("🕒 Pending transaction created:", orderNumber);
    }
  );

  // Keep user info in cache for callbacks
  userCache[orderNumber] = { userId: user_id, phoneNumber: mobile_number };

  // Prepare encryption data for redirect
  const txnDetails = `${AGGREGATOR_ID}|${DEFAULT_MERCHANT_ID}|${orderNumber}|${amount}|ETH|ETB|SALE|${SUCCESS_URL}|${FAILURE_URL}|WEB`;
  const custDetails = `||${mobile_number || ""}||Y`;
  const fullMessage = [
    txnDetails, "|||", "||||", custDetails, "||||", "||||||", "||", "", "||||"
  ].join("~");

  const encryptedData = encrypt(fullMessage, DEFAULT_MERCHANT_KEY);
  const hashInput = `${DEFAULT_MERCHANT_ID}~${orderNumber}~${amount}~ETH~ETB`;
  const encryptedHash = encrypt(generateSha256Hash(hashInput), DEFAULT_MERCHANT_KEY);

  // Redirect to YagoutPay
  const html = `
    <!DOCTYPE html>
    <html>
      <head><title>Redirecting...</title></head>
      <body onload="document.forms[0].submit()">
        <p>Redirecting to payment gateway...</p>
        <form method="POST" action="${TEST_URL}">
          <input type="hidden" name="me_id" value="${DEFAULT_MERCHANT_ID}">
          <input type="hidden" name="merchant_request" value="${encryptedData}">
          <input type="hidden" name="hash" value="${encryptedHash}">
        </form>
      </body>
    </html>
  `;

  res.send(html);
});


// app.post('/transaction', (req, res) => {
//   const amount = req.body.amount || '100';
//   const mobileNumber = req.body.mobile_number || '';
//   const userId = req.body.user_id || 'UNKNOWN';

//   console.log(`mmmmmmmmmmmmmmmmmmmmmmmmmm: phone: ${mobileNumber} userId: ${userId}`)

//   let orderNumber = req.body.order_number;
//   if (!orderNumber) {
//     orderNumber = "ORDER_" + crypto.randomBytes(4).toString('hex');
//   }

//   // Save user info temporarily
//   userCache[orderNumber] = { userId, phoneNumber: mobileNumber };

//   const txnDetails = `${AGGREGATOR_ID}|${DEFAULT_MERCHANT_ID}|${orderNumber}|${amount}|ETH|ETB|SALE|${SUCCESS_URL}|${FAILURE_URL}|WEB`;
//   const custDetails = `||${mobileNumber}||Y`; 
//   const fullMessage = [
//     txnDetails,
//     "|||",
//     "||||",
//     custDetails,
//     "||||",
//     "||||||",
//     "||",
//     "",
//     "||||"
//   ].join("~");

//   const encryptedData = encrypt(fullMessage, DEFAULT_MERCHANT_KEY);
//   const hashInput = `${DEFAULT_MERCHANT_ID}~${orderNumber}~${amount}~${CURRENCY_FROM}~${CURRENCY_TO}`;
//   const encryptedHash = encrypt(generateSha256Hash(hashInput), DEFAULT_MERCHANT_KEY);

//   res.render('redirect', { 
//     test_url: TEST_URL,
//     me_id: DEFAULT_MERCHANT_ID,
//     encrypted_data: encryptedData,
//     encrypted_hash: encryptedHash
//   });
// });



app.post('/transaction', (req, res) => {
  const amount = req.body.amount || '100';
  const mobileNumber = req.body.mobile_number || '';
  const userId = req.body.user_id || 'UNKNOWN';

  console.log(`ppppppppppppppppppppppp: phone: ${mobileNumber} userId: ${userId}`)

  let orderNumber = req.body.order_number;
  if (!orderNumber) {
    orderNumber = "ORDER_" + crypto.randomBytes(4).toString('hex');
  }

  // Save user info temporarily
  userCache[orderNumber] = { userId, phoneNumber: mobileNumber };

  const txnDetails = `${AGGREGATOR_ID}|${DEFAULT_MERCHANT_ID}|${orderNumber}|${amount}|ETH|ETB|SALE|${SUCCESS_URL}|${FAILURE_URL}|WEB`;
  const custDetails = `||${mobileNumber}||Y`; 
  const fullMessage = [
    txnDetails,
    "|||",
    "||||",
    custDetails,
    "||||",
    "||||||",
    "||",
    "",
    "||||"
  ].join("~");

  const encryptedData = encrypt(fullMessage, DEFAULT_MERCHANT_KEY);
  const hashInput = `${DEFAULT_MERCHANT_ID}~${orderNumber}~${amount}~${CURRENCY_FROM}~${CURRENCY_TO}`;
  const encryptedHash = encrypt(generateSha256Hash(hashInput), DEFAULT_MERCHANT_KEY);

  res.render('redirect', { 
    test_url: TEST_URL,
    me_id: DEFAULT_MERCHANT_ID,
    encrypted_data: encryptedData,
    encrypted_hash: encryptedHash
  });
});

app.post('/success', (req, res) => {
  console.log("✅ Success Callback Received:", req.body);
  const txnResponse = req.body.txn_response;

  if (!txnResponse) {
    return res.render('payment_failure', { error: "No transaction response received.", response: null });
  }

  try {
    const decryptedResponse = decrypt(txnResponse, DEFAULT_MERCHANT_KEY);
    console.log("🟢 Decrypted Response (RAW):", decryptedResponse);

    const parts = decryptedResponse.split('|');
    const txn = {
      aggregator: parts[0],
      merchantId: parts[1],
      orderId: parts[2],
      amount: parseFloat(parts[3]),
      currencyFrom: parts[4],
      currencyTo: parts[5],
      date: parts[6],
      time: parts[7],
      transactionRef: parts[8],
      aggregatorTxnId: parts[9],
      status: parts[10],
      errorCode: parts[11],
      errorDesc: parts[12],
      paidAmount: parseFloat(parts[13])
    };

    // 🔹 Fetch user info (user_id, phone_number) from the DB using order_id
    const getUserQuery = `
      SELECT user_id, phone_number 
      FROM transactions 
      WHERE order_id = ? 
      LIMIT 1
    `;

    db.query(getUserQuery, [txn.orderId], (err, results) => {
      if (err) {
        console.error("❌ Error fetching user info:", err);
        return res.render('payment_failure', { error: "Database error while fetching user info", response: null });
      }

      if (results.length === 0) {
        console.warn("⚠️ No transaction found for order:", txn.orderId);
        return res.render('payment_failure', { error: "Transaction not found for this order ID", response: null });
      }

      const userId = results[0].user_id;
      const phoneNumber = results[0].phone_number;

      console.log(`👤 User found: ${userId}, Phone: ${phoneNumber}`);

      // 🔹 Update user’s balance if transaction is successful
      if (userId) {
        const updateUserBalanceSql = `
          UPDATE users 
          SET balance = balance + ?, 
              number_of_buying = number_of_buying + 1
          WHERE id = ?
        `;
        db.query(updateUserBalanceSql, [txn.paidAmount, userId], (err2) => {
          if (err2) console.error("❌ Failed to update user balance:", err2);
          else console.log(`💰 User ${userId} balance increased by ${txn.paidAmount}`);
        });
      }

      // 🔹 Save or update the transaction record with the final details
      const updateTxnSql = `
        UPDATE transactions 
        SET 
          transaction_ref = ?, 
          aggregator_txn_id = ?, 
          status = ?, 
          error_code = ?, 
          error_desc = ?, 
          paid_amount = ?, 
          txn_date = ?, 
          txn_time = ?
        WHERE order_id = ?
      `;
      db.query(updateTxnSql, [
        txn.transactionRef,
        txn.aggregatorTxnId,
        txn.status,
        txn.errorCode,
        txn.errorDesc,
        txn.paidAmount,
        txn.date,
        txn.time,
        txn.orderId
      ], (err3) => {
        if (err3) {
          console.error("❌ Failed to update transaction record:", err3);
          return res.render('payment_failure', { error: "Database error updating transaction", response: null });
        }

        console.log("✅ Transaction record updated successfully");
        res.render('payment_result', { rawResponse: decryptedResponse });
      });
    });
  } catch (err) {
    console.error("❌ Decryption error (success):", err);
    res.render('payment_failure', { error: `Decryption failed: ${err.message}`, response: null });
  }
});





app.post('/failure', (req, res) => {
  console.log("❌ Failure Callback:", req.body);
  const txnResponse = req.body.txn_response;

  if (!txnResponse) {
    return res.render('payment_failure', { error: "No transaction response received.", response: null });
  }

  try {
    const decryptedResponse = decrypt(txnResponse, DEFAULT_MERCHANT_KEY);
    console.log("Decrypted Failed Response:", decryptedResponse);

    const parts = decryptedResponse.split('|');
    const txn = {
      orderId: parts[2],
      errorCode: parts[11],
      errorDesc: parts[12],
      status: parts[10] || 'FAILED'
    };

    const sqlUpdate = `
      UPDATE transactions
      SET status = ?, error_code = ?, error_desc = ?
      WHERE order_id = ?
    `;
    db.query(sqlUpdate, [txn.status, txn.errorCode, txn.errorDesc, txn.orderId], (err) => {
      if (err) console.error("❌ Failed to update failed transaction:", err);
      else console.log(`⚠️ Transaction ${txn.orderId} marked as FAILED`);
    });

    delete userCache[txn.orderId];
    res.render('payment_failure', { error: null, response: decryptedResponse });
  } catch (err) {
    console.error("Decryption error (failure):", err);
    res.render('payment_failure', { error: `Decryption failed: ${err.message}`, response: null });
  }
});



//  ------------------------ START SERVER ------------------------
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
