document.addEventListener("DOMContentLoaded", function () {

    // Get logged-in user from localStorage
    const user = JSON.parse(localStorage.getItem("loggedInUser"));

    // If no user logged in, redirect to login page
    if (!user) {
        alert("You are not logged in. Please login first.");
        window.location.href = "login.html";
        return;
    }

    // Update dashboard content
    const dashboardContainer = document.querySelector(".dashboard-container");

    const welcomeHeading = dashboardContainer.querySelector("h2");
    welcomeHeading.textContent = `Welcome, ${user.name}!`;

    // Add user role below heading
    const roleInfo = document.createElement("p");
    roleInfo.textContent = `Role: ${user.role}`;
    roleInfo.style.fontWeight = "bold";
    dashboardContainer.insertBefore(roleInfo, dashboardContainer.querySelector("hr"));

    // Logout functionality
    const logoutLink = dashboardContainer.querySelector(".logout");
    logoutLink.addEventListener("click", function (e) {
        e.preventDefault();
        localStorage.removeItem("loggedInUser"); // Clear session
        alert("You have been logged out.");
        window.location.href = "login.html"; // Redirect to login
    });
});