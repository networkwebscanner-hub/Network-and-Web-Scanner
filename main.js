/**
 * Client-Side JavaScript Logic for Network & Web Scanner Authentication
 * Handles transitions, validation, and AJAX communications with the Google Apps Script Web App.
 */

// REPLACE THIS PLACEHOLDER WITH YOUR DEPLOYED GOOGLE APPS SCRIPT WEB APP URL!
const APPS_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbz___gHmb5mhe9Y_m1wm4kFmIWTgzko7MW57Ek_auq0usBrgMxSBeJYihea24TKulcp/exec";

// Toast Utilities helper
function showToast(message, type = "success") {
    // Check if toast-container exists
    let container = document.querySelector(".toast-container");
    if (!container) {
        container = document.createElement("div");
        container.className = "toast-container";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `toast toast-${type} bg-glass`;

    const icon = type === "success" ? "fa-circle-check" : "fa-triangle-exclamation";
    toast.innerHTML = `
        <i class="fa-solid ${icon}"></i>
        <div style="flex-grow: 1;">${message}</div>
    `;

    container.appendChild(toast);

    // Animate in
    setTimeout(() => {
        toast.classList.add("show");
    }, 50);

    // Remove toast after duration
    setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => {
            toast.remove();
        }, 400);
    }, 4000);
}

// Check configuration url
function checkConfig() {
    if (!APPS_SCRIPT_URL || APPS_SCRIPT_URL.includes("REPLACE_THIS")) {
        showToast("Configuration Missing: Please deploy your Google Apps Script Web App and paste its URL inside main.js", "error");
        return false;
    }
    return true;
}

// Fetch helper to talk to Google Apps Script
async function callBackend(payload) {
    if (!checkConfig()) return { success: false, error: "Apps Script Web App URL not configured." };

    try {
        const response = await fetch(APPS_SCRIPT_URL, {
            method: "POST",
            mode: "cors",
            headers: {
                "Content-Type": "text/plain;charset=utf-8" // Bypass CORS preflight issues in standard browser requests
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`HTTP network error ${response.status}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Backend Error Details:", error);
        return { success: false, error: "Connection to security backend failed. Please try again." };
    }
}

// Setup live clock in dashboard if present
function initLiveClock() {
    const clockEl = document.getElementById("scanner-clock");
    if (!clockEl) return;

    function updateClock() {
        const now = new Date();
        clockEl.innerHTML = `<i class="fa-regular fa-clock text-blue"></i> ${now.toLocaleTimeString()} | SYSTEM SECURE`;
    }

    updateClock();
    setInterval(updateClock, 1000);
}

// Get user session metadata
function getSessionUser() {
    const session = localStorage.getItem("user_session");
    if (session) {
        try {
            return JSON.parse(session);
        } catch (e) {
            return null;
        }
    }
    return null;
}

// Secure redirect if not logged in (dashboard page check)
function enforceAuth() {
    const user = getSessionUser();
    if (!user) {
        window.location.href = "login.html";
    } else {
        // Show body content now that authorization is verified
        document.body.style.display = "block";

        // Update operator profile panel values
        const nameBadges = document.querySelectorAll(".profile-name");
        nameBadges.forEach(el => {
            el.textContent = user.name;
        });

        const avatarEl = document.querySelector(".profile-avatar");
        if (avatarEl && user.name) {
            avatarEl.textContent = user.name.charAt(0).toUpperCase();
        }

        // Show welcome toast if parameter present
        const params = new URLSearchParams(window.location.search);
        if (params.get("login") === "success") {
            showToast(`Authorization granted. Welcome back, agent ${user.name}!`, "success");
            // Clear URL param without reloading
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }
}

// Handle login page redirect check
function redirectIfAuthenticated() {
    const user = getSessionUser();
    if (user) {
        window.location.href = "index.html";
    }
}

// Handle Logout
function handleLogout() {
    localStorage.removeItem("user_session");
    showToast("Logout successful. Session terminated.", "success");
    setTimeout(() => {
        window.location.href = "login.html";
    }, 1000);
}
