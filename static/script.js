const API_URL = "http://127.0.0.1:5000";

async function scanIP() {
    let ip = document.getElementById("ipInput").value;
    if (!ip) {
        alert("Please enter an IP address");
        return;
    }

    let response = await fetch(`${API_URL}/scan_ip`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip })
    });

    let data = await response.json();
    alert(data.message);
    fetchThreats();
}

async function scanURL() {
    let url = document.getElementById("urlInput").value;
    if (!url) {
        alert("Please enter a URL");
        return;
    }

    let response = await fetch(`${API_URL}/scan_url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
    });

    let data = await response.json();
    alert(data.message);
    fetchThreats();
}

async function fetchThreats() {
    let response = await fetch(`${API_URL}/get_threats`);
    let threats = await response.json();

    let tableBody = document.getElementById("threatTable");
    tableBody.innerHTML = "";
    
    threats.forEach(threat => {
        let row = `<tr>
            <td>${threat.id}</td>
            <td>${threat.type}</td>
            <td>${threat.value}</td>
            <td>${threat.severity}</td>
            <td>${threat.description}</td>
            <td>${threat.source}</td>
        </tr>`;
        tableBody.innerHTML += row;
    });
}

document.addEventListener("DOMContentLoaded", fetchThreats);

function toggleScan(type) {
    document.getElementById("ipScan").style.display = type === "ip" ? "block" : "none";
    document.getElementById("urlScan").style.display = type === "url" ? "block" : "none";
}
