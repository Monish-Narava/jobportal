document.addEventListener("DOMContentLoaded", function () {

    // Check if user is logged in
    const user = JSON.parse(localStorage.getItem("loggedInUser"));
    if (!user) {
        alert("You are not logged in. Please login first.");
        window.location.href = "login.html";
        return;
    }

    // Only allow Employers to post jobs
    if (user.role !== "Employer") {
        alert("Only Employers can post jobs.");
        window.location.href = "dashboard.html";
        return;
    }

    const form = document.querySelector("form");
    const titleInput = form.querySelector("input[placeholder='Enter job title']");
    const companyInput = form.querySelector("input[placeholder='Enter company name']");
    const locationInput = form.querySelector("input[placeholder='Enter job location']");
    const descriptionInput = form.querySelector("textarea");

    form.addEventListener("submit", function (e) {
        e.preventDefault(); // Prevent page reload

        const title = titleInput.value.trim();
        const company = companyInput.value.trim();
        const location = locationInput.value.trim();
        const description = descriptionInput.value.trim();

        // Basic validation
        if (!title || !company || !location || !description) {
            alert("Please fill in all fields.");
            return;
        }

        // Get existing jobs from localStorage
        let jobs = JSON.parse(localStorage.getItem("jobs")) || [];

        // Add new job
        jobs.push({
            title: title,
            company: company,
            location: location,
            description: description,
            postedBy: user.name,
            date: new Date().toLocaleString()
        });

        // Save back to localStorage
        localStorage.setItem("jobs", JSON.stringify(jobs));

        alert("Job posted successfully!");

        // Clear the form
        form.reset();
    });

});