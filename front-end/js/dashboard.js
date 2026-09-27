async function loadCurrentUser() {
    try {
        const response = await fetch(
            "http://127.0.0.1:8000/auth/me",
            {
                method: "GET",
                credentials: "include"
            }
        );

        if (!response.ok) {
            window.location.href = "index.html";
            return;
        }

        const user = await response.json();

        document.getElementById("username").textContent = user.username;
        document.getElementById("user-role").textContent = user.role;

    } catch (error) {
        console.error("Error loading current user:", error);
        window.location.href = "index.html";
    }
}


async function loadSecurityEvents() {
    try {
        const response = await fetch(
            "http://127.0.0.1:8000/security/events?limit=5",
            {
                method: "GET",
                credentials: "include"
            }
        );

        if (!response.ok) {
            console.error("Failed to load security events");
            return;
        }

        const data = await response.json();

        const events = data["security events"];

        const eventsContainer = document.getElementById("recent-events");
        const eventsCount = document.getElementById("events-count");

        eventsCount.textContent = events.length;

        if (events.length === 0) {
            eventsContainer.innerHTML = "<p>No security events found.</p>";
            return;
        }

        eventsContainer.innerHTML = "";

        events.forEach(event => {
            const eventElement = document.createElement("div");

            eventElement.innerHTML = `
                <p>
                    <strong>${event.event_type}</strong>
                    — IP: ${event.ip_address || "Unknown"}
                </p>
            `;

            eventsContainer.appendChild(eventElement);
        });

    } catch (error) {
        console.error("Error loading security events:", error);
    }
}
async function logout() {
    try {
        const response = await fetch(
            "http://127.0.0.1:8000/auth/logout",
            {
                method: "POST",
                credentials: "include"
            }
        );

        if (response.ok) {
            window.location.href = "index.html";
        } else {
            console.error("Logout failed");
        }

    } catch (error) {
        console.error("Error during logout:", error);
    }
}

loadCurrentUser();
loadSecurityEvents();
document.getElementById("logout-btn").addEventListener("click",logout)