document.addEventListener("DOMContentLoaded", function () {

    const jobsContainer = document.getElementById("jobs");
    const jobs = JSON.parse(localStorage.getItem("jobs")) || [];

    if (jobs.length === 0) {
        jobsContainer.innerHTML = "<p>No jobs available.</p>";
        return;
    }

    jobs.forEach(job => {
        const div = document.createElement("div");
        div.className = "job";
        div.innerHTML = `
            <h3>${job.title}</h3>
            <p><strong>Company:</strong> ${job.company}</p>
            <p><strong>Location:</strong> ${job.location}</p>
            <p>${job.description}</p>
        `;
        jobsContainer.appendChild(div);
    });

});