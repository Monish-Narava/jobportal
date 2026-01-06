document.addEventListener("DOMContentLoaded", function () {

    const form = document.querySelector("form");
    const emailInput = form.querySelector("input[type='text'], input[type='email']");
    const passwordInput = form.querySelector("input[type='password']");

    form.addEventListener("submit", function (event) {
        event.preventDefault(); // Prevent page reload

        const email = emailInput.value.trim();
        const password = passwordInput.value.trim();

        // Basic validation
        if (!email || !password) {
            alert("Please fill in both email and password.");
            return;
        }

        // Get users from localStorage
        let users = JSON.parse(localStorage.getItem("users")) || [];

        // Find matching user
        const user = users.find(user => user.email === email && user.password === password);

        if (user) {
            alert(`Login successful! Welcome, ${user.name}.`);
            // Optional: save logged-in user for dashboard
            localStorage.setItem("loggedInUser", JSON.stringify(user));

            // Redirect to dashboard page
            window.location.href = "dashboard.html";
        } else {
            alert("Invalid email or password. Please try again.");
        }

        // Clear form
        form.reset();
    });
    // Forgot Password feature
    const forgotLink = document.getElementById("forgot-password");

    forgotLink.addEventListener("click", function (e) {
        e.preventDefault();

    // Ask for registered email
        const email = prompt("Enter your registered email:");
        if (!email) {
            alert("Email is required.");
            return;
        }

        // Get users from localStorage
        let users = JSON.parse(localStorage.getItem("users")) || [];

        // Find the user
        const userIndex = users.findIndex(user => user.email === email.trim());
        if (userIndex === -1) {
            alert("No user found with this email.");
            return;
        }

        // Ask for new password
        const newPassword = prompt("Enter your new password:");
        if (!newPassword) {
            alert("Password cannot be empty.");
            return;
        }

        // Update password in localStorage
        users[userIndex].password = newPassword;
        localStorage.setItem("users", JSON.stringify(users));

        alert("Password updated successfully! You can now login with the new password.");
    });


});