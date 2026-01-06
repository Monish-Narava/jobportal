document.addEventListener("DOMContentLoaded", function () {

    const form = document.querySelector("form");
    const nameInput = form.querySelector("input[type='text']");
    const emailInput = form.querySelector("input[type='email']");
    const passwordInput = form.querySelector("input[type='password']");
    const roleSelect = form.querySelector("select");

    form.addEventListener("submit", function (event) {
        event.preventDefault(); // Prevent page reload

        const name = nameInput.value.trim();
        const email = emailInput.value.trim();
        const password = passwordInput.value.trim();
        const role = roleSelect.value;

        // Basic validation
        if (!name || !email || !password) {
            alert("Please fill in all fields.");
            return;
        }

        // Check if email is already registered
        let users = JSON.parse(localStorage.getItem("users")) || [];

        const emailExists = users.some(user => user.email === email);
        if (emailExists) {
            alert("This email is already registered. Try logging in.");
            return;
        }

        // Save user in localStorage
        users.push({
            name: name,
            email: email,
            password: password, // For real projects, never store plain passwords!
            role: role
        });

        localStorage.setItem("users", JSON.stringify(users));

        alert("Registration successful! You can now log in.");

        // Clear form
        form.reset();

        // Redirect to login page
        window.location.href = "login.html";
    });

});