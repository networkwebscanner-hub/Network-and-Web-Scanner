/**
 * Google Apps Script Backend for Registration, OTP Verification, and Login
 * Paste this single script into the Extensions > Apps Script editor in your Google Sheet.
 * 
 * Make sure your sheet has a sheet tab named "Users" with these column headers in row 1:
 * User Code | Full Name | Email | Password Hash | OTP | OTP Expiry | Status | Created At
 */

// Configure sheet name
const SHEET_NAME = "Users";

// CORS Headers utility helper
function getCorsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };
}

// Handle OPTIONS preflight request (CORS requirement)
function doOptions(e) {
  return ContentService.createTextOutput(JSON.stringify({status: "CORS_OK"}))
    .setMimeType(ContentService.MimeType.JSON);
}

// Main POST handler
function doPost(e) {
  var result;
  
  try {
    // Parse request data
    var requestData = JSON.parse(e.postData.contents);
    var action = requestData.action;
    
    // Route action
    switch (action) {
      case "registerInit":
        result = handleRegisterInit(requestData);
        break;
      case "registerComplete":
        result = handleRegisterComplete(requestData);
        break;
      case "verifyOTP":
        result = handleVerifyOTP(requestData);
        break;
      case "resendOTP":
        result = handleResendOTP(requestData);
        break;
      case "loginUser":
        result = handleLoginUser(requestData);
        break;
      default:
        result = { success: false, error: "Invalid action specified." };
    }
  } catch (error) {
    result = { success: false, error: "System error: " + error.toString() };
  }
  
  return ContentService.createTextOutput(JSON.stringify(result))
    .setMimeType(ContentService.MimeType.JSON);
}

// --- DATABASE OPERATIONS UTILITIES ---

function getSheet() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) {
    sheet = ss.insertSheet(SHEET_NAME);
    // Initialize headers if new sheet
    sheet.appendRow(["User Code", "Full Name", "Email", "Password Hash", "OTP", "OTP Expiry", "Status", "Created At"]);
  }
  return sheet;
}

// Find a user row index by a key and value (returns 1-indexed row or -1)
function findUserRow(keyName, value) {
  var sheet = getSheet();
  var data = sheet.getDataRange().getValues();
  if (data.length <= 1) return -1;
  
  var headers = data[0];
  var colIndex = headers.indexOf(keyName);
  if (colIndex === -1) return -1;
  
  var searchValue = String(value).trim().toLowerCase();
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][colIndex]).trim().toLowerCase() === searchValue) {
      return i + 1; // 1-indexed row number
    }
  }
  return -1;
}

// Read cells for a specific row as an object
function getUserData(row) {
  var sheet = getSheet();
  var headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
  var values = sheet.getRange(row, 1, 1, sheet.getLastColumn()).getValues()[0];
  var user = {};
  for (var i = 0; i < headers.length; i++) {
    user[headers[i]] = values[i];
  }
  user.rowNumber = row;
  return user;
}

// Update multiple columns in a specific row
function updateUserData(row, updates) {
  var sheet = getSheet();
  var headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
  
  for (var key in updates) {
    var colIndex = headers.indexOf(key);
    if (colIndex !== -1) {
      sheet.getRange(row, colIndex + 1).setValue(updates[key]);
    }
  }
}

// --- CORE UTILITY LOGIC ---

// Generate a unique 6-digit numeric User Code
function generateUniqueUserCode() {
  var code;
  var row;
  var limit = 0;
  
  do {
    // Generate 6-digit number between 100000 and 999999
    code = String(Math.floor(100000 + Math.random() * 900000));
    row = findUserRow("User Code", code);
    limit++;
  } while (row !== -1 && limit < 100); // Guard against infinite loop
  
  return code;
}

// Generate a 6-digit OTP
function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Secure hash function (SHA-256)
function hashPassword(password, salt) {
  var rawHash = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    password + salt,
    Utilities.Charset.UTF_8
  );
  var output = "";
  for (var i = 0; i < rawHash.length; i++) {
    var byteValue = rawHash[i];
    if (byteValue < 0) byteValue += 256;
    var byteString = byteValue.toString(16);
    if (byteString.length == 1) byteString = "0" + byteString;
    output += byteString;
  }
  return output;
}

// Real-time OTP Delivery via GmailApp
function sendOTPEmail(email, name, otp) {
  var subject = "Your Secure OTP Code: " + otp;
  
  // HTML layout matching the Sleek Minimalist Tech design system
  var htmlBody = `
    <div style="background-color: #f3f4f6; padding: 40px 20px; min-height: 100%; width: 100%; box-sizing: border-box;">
      <div style="background-color: #ffffff; color: #334155; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; padding: 40px; border-radius: 16px; max-width: 460px; margin: 0 auto; border: 1px solid #e5e7eb; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.02);">
        <div style="margin-bottom: 28px; text-align: center;">
          <div style="background: linear-gradient(135deg, #38bdf8 0%, #00f5d4 100%); border-radius: 30px; padding: 10px 22px; display: inline-block;">
            <span style="color: #03050c; font-size: 13px; font-weight: 800; letter-spacing: 0.5px; text-transform: uppercase; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;">
              Network & Web Scanner
            </span>
          </div>
        </div>
        
        <h2 style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; font-size: 20px; font-weight: 700; color: #0f172a; margin: 0 0 12px 0; text-align: center;">
          Verify your email address
        </h2>
        
        <p style="font-size: 14px; color: #475569; line-height: 1.5; margin: 0 0 24px 0; text-align: center;">
          Hello <strong>${name}</strong>,<br>
          Please use the secure One-Time Password (OTP) below to verify your identity and complete your account setup.
        </p>
        
        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 24px;">
          <div style="font-family: 'Courier New', Courier, monospace; font-size: 38px; font-weight: 800; color: #0f172a; letter-spacing: 8px; margin-bottom: 6px; text-indent: 8px;">
            ${otp}
          </div>
          <span style="font-size: 10px; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; display: block;">
            One-Time Verification Code
          </span>
        </div>
        
        <p style="font-size: 12px; color: #64748b; line-height: 1.5; margin: 0 0 24px 0; text-align: center;">
          This security code is valid for <strong>5 minutes</strong>. If you did not request this code, you can safely ignore this email.
        </p>
        
        <div style="border-top: 1px solid #e2e8f0; padding-top: 20px; text-align: center;">
          <span style="font-size: 10px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; display: block;">
            Network & Web Scanner Security
          </span>
          <span style="font-size: 9px; color: #cbd5e1; margin-top: 4px; display: block;">
            System Auto-mailer • Please do not reply
          </span>
        </div>
      </div>
    </div>
  `;
  
  GmailApp.sendEmail(email, subject, "Your OTP is " + otp, {
    htmlBody: htmlBody,
    name: "Network & Web Scanner Security"
  });
}

// --- ACTION HANDLERS ---

// Step 1: Register initial info (Check duplicate, generate 6-digit User Code)
function handleRegisterInit(data) {
  var name = String(data.name).trim();
  var email = String(data.email).trim().toLowerCase();
  
  if (!name || !email) {
    return { success: false, error: "Please enter your name and email." };
  }
  
  // Duplicate check
  var existingRow = findUserRow("Email", email);
  if (existingRow !== -1) {
    var existingUser = getUserData(existingRow);
    // If user registration is pending, overwrite. Otherwise reject
    if (existingUser.Status === "ACTIVE") {
      return { success: false, error: "This email address is already registered." };
    }
    
    // overwrite pending row
    var userCode = existingUser["User Code"];
    updateUserData(existingRow, {
      "Full Name": name,
      "Status": "PENDING_PASSWORD",
      "Created At": new Date().toISOString()
    });
    
    return { success: true, userCode: userCode };
  }
  
  // Create new user record
  var userCode = generateUniqueUserCode();
  var sheet = getSheet();
  sheet.appendRow([
    userCode,
    name,
    email,
    "", // Password Hash placeholder
    "", // OTP placeholder
    "", // OTP Expiry placeholder
    "PENDING_PASSWORD",
    new Date().toISOString()
  ]);
  
  return { success: true, userCode: userCode };
}

// Step 2: Set Password & Generate/Send OTP
function handleRegisterComplete(data) {
  var email = String(data.email).trim().toLowerCase();
  var password = data.password;
  
  if (!email || !password) {
    return { success: false, error: "Details missing." };
  }
  
  var row = findUserRow("Email", email);
  if (row === -1) {
    return { success: false, error: "User profile details not found. Please start registration again." };
  }
  
  var user = getUserData(row);
  if (user.Status !== "PENDING_PASSWORD" && user.Status !== "PENDING_OTP") {
    return { success: false, error: "Invalid registration status." };
  }
  
  // Secure password with SHA-256 using user code as salt
  var hashed = hashPassword(password, user["User Code"]);
  
  // Generate OTP
  var otp = generateOTP();
  var expiry = new Date();
  expiry.setMinutes(expiry.getMinutes() + 5); // 5 min expiry duration
  
  updateUserData(row, {
    "Password Hash": hashed,
    "OTP": otp,
    "OTP Expiry": expiry.toISOString(),
    "Status": "PENDING_OTP"
  });
  
  // Deliver Email via GmailApp
  try {
    sendOTPEmail(email, user["Full Name"], otp);
  } catch (mailError) {
    return { success: false, error: "Email delivery failed: " + mailError.toString() };
  }
  
  return { success: true };
}

// Step 3: Validate OTP
function handleVerifyOTP(data) {
  var email = String(data.email).trim().toLowerCase();
  var otp = String(data.otp).trim();
  
  if (!email || !otp) {
    return { success: false, error: "Please enter the OTP." };
  }
  
  var row = findUserRow("Email", email);
  if (row === -1) {
    return { success: false, error: "Account details not found." };
  }
  
  var user = getUserData(row);
  if (user.Status !== "PENDING_OTP") {
    return { success: false, error: "This account has already been verified or registration is incomplete." };
  }
  
  // Check validation
  if (String(user.OTP) !== otp) {
    return { success: false, error: "Incorrect verification code." };
  }
  
  // Expiry check
  var expiryTime = new Date(user["OTP Expiry"]).getTime();
  var now = new Date().getTime();
  if (now > expiryTime) {
    return { success: false, error: "OTP has expired. Please request a new one." };
  }
  
  // Finalize Account status
  updateUserData(row, {
    "Status": "ACTIVE",
    "OTP": "",
    "OTP Expiry": ""
  });
  
  return { success: true, name: user["Full Name"] };
}

// Step 4: Resend verification OTP
function handleResendOTP(data) {
  var email = String(data.email).trim().toLowerCase();
  
  if (!email) {
    return { success: false, error: "Email missing." };
  }
  
  var row = findUserRow("Email", email);
  if (row === -1) {
    return { success: false, error: "Account details not found." };
  }
  
  var user = getUserData(row);
  if (user.Status !== "PENDING_OTP") {
    return { success: false, error: "Action not permitted for this status." };
  }
  
  // Re-generate
  var otp = generateOTP();
  var expiry = new Date();
  expiry.setMinutes(expiry.getMinutes() + 5);
  
  updateUserData(row, {
    "OTP": otp,
    "OTP Expiry": expiry.toISOString()
  });
  
  try {
    sendOTPEmail(email, user["Full Name"], otp);
  } catch (mailError) {
    return { success: false, error: "Resending email failed: " + mailError.toString() };
  }
  
  return { success: true };
}

// Step 5: User verification login
function handleLoginUser(data) {
  var loginInput = String(data.loginInput).trim().toLowerCase(); // user code or email
  var password = data.password;
  var userCodeInput = String(data.userCode).trim();
  
  if (!loginInput || !password || !userCodeInput) {
    return { success: false, error: "Please enter all login credentials." };
  }
  
  // Find row by email or user code
  var row = -1;
  if (loginInput.indexOf("@") !== -1) {
    row = findUserRow("Email", loginInput);
  } else {
    row = findUserRow("User Code", loginInput);
  }
  
  if (row === -1) {
    return { success: false, error: "Invalid credentials entered." };
  }
  
  var user = getUserData(row);
  
  // Security Checks
  if (user.Status !== "ACTIVE") {
    return { success: false, error: "Your account is not fully verified yet. Please register and complete OTP validation." };
  }
  
  if (String(user["User Code"]) !== userCodeInput) {
    return { success: false, error: "Incorrect 6-digit User Code matches." };
  }
  
  var hashed = hashPassword(password, user["User Code"]);
  if (user["Password Hash"] !== hashed) {
    return { success: false, error: "Incorrect password." };
  }
  
  return { 
    success: true, 
    name: user["Full Name"], 
    email: user.Email,
    userCode: user["User Code"] 
  };
}
