const STATUS_COLORS = {
    up: "#28a745",
    down: "#dc3545",
    "error-disabled": "#ffc107",
    pending: "#ccc",
    done: "#28a745",
    failed: "#dc3545"
};

function pollState() {
    fetch("/api/state")
        .then(r => r.json())
        .then(data => {
            console.log("State updated:", data);
            updateSwitches(data.switches);
        })
        .catch(e => console.error("Poll error:", e));
}

function updateSwitches(switches) {
    const app = document.getElementById("app");
    if (!app) return;

    app.innerHTML = '<div class="switches">';
    for (const sw of switches) {
        const color = STATUS_COLORS[sw.status] || "#999";
        const card = `
            <div class="switch-card" style="border-left: 4px solid ${color}">
                <h3>${sw.name}</h3>
                <p>IP: ${sw.ip}</p>
                <p>Vendor: ${sw.vendor}</p>
                <p>Status: <span style="color: ${color}">${sw.status}</span></p>
                <button onclick="showDetail(${sw.id})">Details</button>
            </div>
        `;
        app.innerHTML += card;
    }
    app.innerHTML += "</div>";
}

function showDetail(switchId) {
    fetch(`/api/switches/${switchId}/detail`)
        .then(r => r.json())
        .then(data => {
            renderDetail(data);
        })
        .catch(e => console.error("Detail error:", e));
}

function renderDetail(data) {
    const app = document.getElementById("app");
    app.innerHTML = `
        <div class="switch-detail">
            <button onclick="pollState()">Back</button>
            <h2>${data.switch.name}</h2>

            <div class="tabs">
                <button class="tab-btn active" onclick="switchTab(event, 'ports')">Ports</button>
                <button class="tab-btn" onclick="switchTab(event, 'macs')">MAC</button>
                <button class="tab-btn" onclick="switchTab(event, 'arps')">ARP</button>
            </div>

            <div id="ports" class="tab-content active">
                <table>
                    <tr><th>Port</th><th>Status</th><th>VLAN</th><th>Desc</th></tr>
                    ${data.ports.map(p => `<tr><td>${p.name}</td><td>${p.status}</td><td>${p.vlan}</td><td>${p.description}</td></tr>`).join("")}
                </table>
            </div>

            <div id="macs" class="tab-content">
                <table>
                    <tr><th>VLAN</th><th>MAC</th><th>Port</th></tr>
                    ${data.macs.map(m => `<tr><td>${m.vlan}</td><td>${m.mac}</td><td>${m.port}</td></tr>`).join("")}
                </table>
            </div>

            <div id="arps" class="tab-content">
                <table>
                    <tr><th>IP</th><th>MAC</th><th>Interface</th></tr>
                    ${data.arps.map(a => `<tr><td>${a.ip}</td><td>${a.mac}</td><td>${a.interface}</td></tr>`).join("")}
                </table>
            </div>
        </div>
    `;
}

function switchTab(event, tabName) {
    const contents = document.querySelectorAll(".tab-content");
    contents.forEach(c => c.classList.remove("active"));

    const btns = document.querySelectorAll(".tab-btn");
    btns.forEach(b => b.classList.remove("active"));

    document.getElementById(tabName).classList.add("active");
    event.target.classList.add("active");
}

function collectSwitch(switchId) {
    fetch(`/api/switches/${switchId}/collect`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({})
    })
    .then(r => r.json())
    .then(data => {
        console.log("Collect started:", data);
        alert("Collection started");
    })
    .catch(e => {
        console.error("Collect error:", e);
        alert("Error: " + e);
    });
}

document.addEventListener("DOMContentLoaded", () => {
    pollState();
    setInterval(pollState, 3000);
});
