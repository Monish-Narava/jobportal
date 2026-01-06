// Wait until the page loads
document.addEventListener("DOMContentLoaded", function () {

    // Get buttons
    const loginBtn = document.getElementById("loginBtn");
    const registerBtn = document.getElementById("registerBtn");

    // Login button click
    loginBtn.addEventListener("click", function () {
        // Option 1: redirect to login page
        window.location.href = "login.html";

        // Option 2: temporary message
        // alert("Redirecting to Login page...");
    });

    // Register button click
    registerBtn.addEventListener("click", function () {
        // Option 1: redirect to register page
        window.location.href = "register.html";

        // Option 2: temporary message
        // alert("Redirecting to Register page...");
    });

});