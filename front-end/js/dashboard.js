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



async function loadAlerts() {
    try {
        const response = await fetch(
            "http://127.0.0.1:8000/alerts?severity=HIGH&limit=5",
            {
                method: "GET",
                credentials: "include"
            }
        );

        if (!response.ok) {
            console.error("Failed to load alerts");
            return;
        }

        const data = await response.json();

        const alerts = data["alerts"];

        const alertsContainer = document.getElementById("recent-alerts");
        const alertsCount = document.getElementById("alerts-count");

        alertsCount.textContent = alerts.length;

        if (alerts.length === 0) {
            alertsContainer.innerHTML = "<p>No alerts found.</p>";
            return;
        }

        alertsContainer.innerHTML = "";

        alerts.forEach(alert => {
            const alertElement = document.createElement("div");    

            alertElement.innerHTML = `
                <p>
                    <strong>${alert.user_id}</strong>
                    — IP: ${alert.ip_address || "Unknown"}
                </p>
            `;

        alertsContainer.appendChild(alertElement);
        });

    } catch (error) {
        console.error("Error loading alerts:", error);
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
loadAlerts();
document.getElementById("logout-btn").addEventListener("click",logout)