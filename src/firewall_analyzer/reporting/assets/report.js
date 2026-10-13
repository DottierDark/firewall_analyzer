/* Firewall Analyzer report behaviour.
 * Reads render-time data from the global REPORT_CONFIG object, which
 * _get_enhanced_javascript() emits immediately before this file.
 */
// ==========================================================
// Existing rule details
// ==========================================================

var allRulesExpanded = false;

// ==========================================================
// External Communications Discovery
// ==========================================================

var externalZones = [];
var externalDiscoveryResults = [];
var portAnalysisResults = [];

function analyzeExternalPorts() {

    if (externalDiscoveryResults.length === 0) {
        alert("Run External Discovery first.");
        return;
    }

    let portCounts = {};

    externalDiscoveryResults.forEach(function(rule) {

        let services = rule.services || [];

        services.forEach(function(service) {

            service.split(";").forEach(function(item) {

                if (
                    item.toLowerCase().startsWith("g_")
                ) {
                    return;
                }

                if (
                    !item ||
                    item.toLowerCase() === "any" ||
                    item.toLowerCase() === "application-default"
                ) {
                    return;
                }

                if (!portCounts[item]) {
                    portCounts[item] = 0;
                }

                portCounts[item]++;
            });
        });
    });

    portAnalysisResults =
        Object.entries(portCounts)
            .sort(function(a, b) {
                return b[1] - a[1];
            });

    let html = `
        <h3>External Ports</h3>

        <table>
            <tr>
                <th>Port / Service</th>
                <th>Rules</th>
            </tr>
    `;

    portAnalysisResults.forEach(function(row) {

        html += `
            <tr>
                <td>${row[0]}</td>
                <td>${row[1]}</td>
            </tr>
        `;
    });

    html += "</table>";

    document.getElementById(
        "externalPortsTable"
    ).innerHTML = html;
}

function findInsecurePorts() {

    if (externalDiscoveryResults.length === 0) {

        alert(
            "Run External Discovery first."
        );

        return;
    }

    const insecurePorts = {
        "20": "FTP Data",
        "21": "FTP",
        "23": "Telnet",
        "25": "SMTP",
        "53": "DNS",
        "69": "TFTP",
        "80": "HTTP",
        "110": "POP3",
        "111": "RPC",
        "135": "Microsoft RPC",
        "137": "NetBIOS Name Service",
        "138": "NetBIOS Datagram",
        "139": "NetBIOS Session",
        "143": "IMAP",
        "161": "SNMP",
        "162": "SNMP Trap",
        "389": "LDAP",
        "445": "SMB",
        "2049": "NFS",
        "3389": "RDP",
        "5900": "VNC"
    };

    let findings = [];

    externalDiscoveryResults.forEach(function(rule) {

        let services = rule.services || [];

        services.forEach(function(service) {

            Object.keys(
                insecurePorts
            ).forEach(function(port) {

                var portRegex = new RegExp(
                    "(^|[^0-9])" + port + "([^0-9]|$)"
                );

                if (
                    portRegex.test(
                        service.toLowerCase()
                    )
                ) {

                    findings.push({
                        rule: rule.name,
                        service: service,
                        risk: insecurePorts[port]
                    });
                }
            });
        });
    });

    let html = `
        <h3>
            Potentially Insecure Ports
        </h3>

        <table>
            <tr>
                <th>Rule</th>
                <th>Service</th>
                <th>Risk</th>
            </tr>
    `;

    findings.forEach(function(item) {

        html += `
            <tr>
                <td>${item.rule}</td>
                <td>${item.service}</td>
                <td>${item.risk}</td>
            </tr>
        `;
    });

    html += "</table>";

    document.getElementById(
        "insecurePortsTable"
    ).innerHTML = html;
}




function normalizeZone(zone) {
    return String(zone || "")
        .replace("[Disabled]", "")
        .trim()
        .toLowerCase();
}

function escapeHtml(value) {
    return String(value || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function addExternalZone() {
    var input = document.getElementById("externalZoneInput");

    if (!input) {
        return;
    }

    var zone = input.value.trim();

    if (!zone) {
        return;
    }

    var alreadyExists = externalZones.some(function(existingZone) {
        return normalizeZone(existingZone) === normalizeZone(zone);
    });

    if (!alreadyExists) {
        externalZones.push(zone);
    }

    renderExternalZones();
    input.value = "";
}

function removeExternalZone(index) {
    externalZones.splice(index, 1);
    renderExternalZones();
}

function renderExternalZones() {
    var container = document.getElementById("externalZonesList");

    if (!container) {
        return;
    }

    var html = "";

    externalZones.forEach(function(zone, index) {
        html += `
            <span style="
                background:#EB8C00;
                color:white;
                padding:8px 12px;
                margin:5px;
                display:inline-block;
                border-radius:6px;
                font-weight:bold;
            ">
                ${escapeHtml(zone)}

                <button
                    type="button"
                    onclick="removeExternalZone(${index})"
                    style="
                        margin-left:8px;
                        padding:0;
                        background:transparent;
                        color:white;
                        border:none;
                        cursor:pointer;
                        font-size:16px;
                        font-weight:bold;
                    "
                    title="Remove zone"
                >
                    ×
                </button>
            </span>
        `;
    });

    container.innerHTML = html;
}

function runExternalDiscovery() {
    if (externalZones.length === 0) {
        alert("Please add at least one external zone.");
        return;
    }

    var rules = window.externalDiscoveryRules || [];

    if (rules.length === 0) {
        alert("No firewall rules are available in the report.");
        return;
    }

    var normalizedExternalZones = externalZones.map(normalizeZone);

    var activeAllowRules = rules.filter(function(rule) {

    var action = String(rule.action || "")
        .trim()
        .toLowerCase();

    var sourceZones = rule.source_zones || [];
    var destinationZones = rule.destination_zones || [];

    var disabledInSourceZone = sourceZones.some(function(zone) {
        return String(zone)
            .trim()
            .toLowerCase()
            .includes("[disabled]");
    });

    var disabledInDestinationZone =
        destinationZones.some(function(zone) {
            return String(zone)
                .trim()
                .toLowerCase()
                .includes("[disabled]");
        });

    return (
        !rule.disabled &&
        !action.includes("[disabled]") &&
        !disabledInSourceZone &&
        !disabledInDestinationZone &&
        ["allow", "accept", "permit"].includes(action)
    );
});


    var confirmedExternal = [];
    var potentialExternal = [];
    var internalRules = [];

    activeAllowRules.forEach(function(rule) {
        var sourceZones = (rule.source_zones || []).map(normalizeZone);
        var destinationZones =
            (rule.destination_zones || []).map(normalizeZone);

        var sourceMatch = sourceZones.some(function(zone) {
            return normalizedExternalZones.includes(zone);
        });

        var destinationMatch = destinationZones.some(function(zone) {
            return normalizedExternalZones.includes(zone);
        });

        var sourceAny = sourceZones.includes("any");
        var destinationAny = destinationZones.includes("any");

        var result = Object.assign({}, rule);

        if (sourceMatch || destinationMatch) {
            result.match_type = "Confirmed External";

            var matchedDirections = [];

            if (sourceMatch) {
                matchedDirections.push("Source Zone");
            }

            if (destinationMatch) {
                matchedDirections.push("Destination Zone");
            }

            result.match_reason =
                matchedDirections.join(" and ") +
                " matched an entered external zone";

            confirmedExternal.push(result);

        } else if (sourceAny || destinationAny) {
            result.match_type = "Potential External";

            var anyDirections = [];

            if (sourceAny) {
                anyDirections.push("Source Zone is Any");
            }

            if (destinationAny) {
                anyDirections.push("Destination Zone is Any");
            }

            result.match_reason = anyDirections.join(" and ");

            potentialExternal.push(result);

        } else {
            result.match_type = "Internal";
            result.match_reason =
                "No source or destination zone matched an external zone";

            internalRules.push(result);
        }
    });

    externalDiscoveryResults =
        confirmedExternal.concat(potentialExternal);

    var totalElement =
        document.getElementById("totalAllowRulesCount");

    var confirmedElement =
        document.getElementById("confirmedExternalCount");

    var potentialElement =
        document.getElementById("potentialExternalCount");

    var internalElement =
        document.getElementById("internalRulesCount");

    if (totalElement) {
        totalElement.textContent = activeAllowRules.length;
    }

    if (confirmedElement) {
        confirmedElement.textContent = confirmedExternal.length;
    }

    if (potentialElement) {
        potentialElement.textContent = potentialExternal.length;
    }

    if (internalElement) {
        internalElement.textContent = internalRules.length;
    }

    var messageContainer =
        document.getElementById("externalDiscoveryMessage");

    if (messageContainer) {
        messageContainer.innerHTML = `
            <div style="
                padding:15px;
                background:#F5F5F5;
                border-left:5px solid #EB8C00;
                border-radius:6px;
            ">
                Analysis completed using external zones:
                <strong>
                    ${externalZones.map(escapeHtml).join(", ")}
                </strong>
            </div>
        `;
    }

    renderExternalResultsTable(externalDiscoveryResults);

    var downloadButton =
        document.getElementById("downloadExternalCsvButton");

    if (downloadButton) {
        downloadButton.style.display =
            externalDiscoveryResults.length > 0
                ? "inline-block"
                : "none";
    }
}

function renderExternalResultsTable(results) {
    var container =
        document.getElementById("externalResultsTable");

    if (!container) {
        return;
    }

    if (results.length === 0) {
        container.innerHTML = `
            <div style="
                padding:20px;
                background:#E8F5E9;
                border-left:5px solid #2E7D32;
                border-radius:6px;
            ">
                No external communication rules were found.
            </div>
        `;

        return;
    }

    var rows = "";

    results.forEach(function(rule) {
        var badgeColor =
            rule.match_type === "Confirmed External"
                ? "#F44336"
                : "#FF9800";

        rows += `
            <tr>
                <td>${escapeHtml(rule.id)}</td>

                <td>${escapeHtml(rule.name)}</td>

                <td>
                    ${escapeHtml(
                        (rule.source_zones || []).join("; ")
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        (rule.destination_zones || []).join("; ")
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        (rule.applications || []).join("; ")
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        (rule.services || []).join("; ")
                    )}
                </td>

                <td>${escapeHtml(rule.action)}</td>

                <td>
                    <span style="
                        display:inline-block;
                        padding:5px 10px;
                        border-radius:5px;
                        background:${badgeColor};
                        color:white;
                        font-weight:bold;
                    ">
                        ${escapeHtml(rule.match_type)}
                    </span>
                </td>

                <td>${escapeHtml(rule.match_reason)}</td>
            </tr>
        `;
    });

    container.innerHTML = `
        <h3>
            External Communication Rules
            (${results.length})
        </h3>

        <table>
            <thead>
                <tr>
                    <th>Rule ID</th>
                    <th>Rule Name</th>
                    <th>Source Zones</th>
                    <th>Destination Zones</th>
                    <th>Applications</th>
                    <th>Services</th>
                    <th>Action</th>
                    <th>Match Type</th>
                    <th>Reason</th>
                </tr>
            </thead>

            <tbody>
                ${rows}
            </tbody>
        </table>
    `;
}

function csvSafe(value) {
    var text = String(value || "");
    return '"' + text.replace(/"/g, '""') + '"';
}

function downloadExternalCommunicationsCSV() {
    if (externalDiscoveryResults.length === 0) {
        alert("No external communication results to download.");
        return;
    }

    var csvRows = [];

    csvRows.push([
        "Rule ID",
        "Rule Name",
        "Source Zones",
        "Destination Zones",
        "Source Addresses",
        "Destination Addresses",
        "Applications",
        "Services",
        "Action",
        "Match Type",
        "Match Reason"
    ].map(csvSafe).join(","));

    externalDiscoveryResults.forEach(function(rule) {
        csvRows.push([
            rule.id,
            rule.name,
            (rule.source_zones || []).join("; "),
            (rule.destination_zones || []).join("; "),
            (rule.source_addresses || []).join("; "),
            (rule.destination_addresses || []).join("; "),
            (rule.applications || []).join("; "),
            (rule.services || []).join("; "),
            rule.action,
            rule.match_type,
            rule.match_reason
        ].map(csvSafe).join(","));
    });

    var csvContent = csvRows.join("\\n");

    var blob = new Blob(
        [csvContent],
        { type: "text/csv;charset=utf-8;" }
    );

    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");

    link.href = url;
    link.download = "OUTPUT_external_communications.csv";

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
}

// ==========================================================
// Existing rule details functions
// ==========================================================

function toggleRuleDetails(ruleIdx) {
    var detailsDiv =
        document.getElementById("rule-details-" + ruleIdx);

    if (!detailsDiv) {
        return;
    }

    if (detailsDiv.classList.contains("collapsed")) {
        detailsDiv.classList.remove("collapsed");
        detailsDiv.classList.add("expanded");
    } else {
        detailsDiv.classList.remove("expanded");
        detailsDiv.classList.add("collapsed");
    }
}

function toggleAllRules() {
    var ruleSections =
        document.querySelectorAll('[id^="rule-details-"]');

    allRulesExpanded = !allRulesExpanded;

    ruleSections.forEach(function(section) {
        if (allRulesExpanded) {
            section.classList.remove("collapsed");
            section.classList.add("expanded");
        } else {
            section.classList.remove("expanded");
            section.classList.add("collapsed");
        }
    });
}

// ==========================================================
// Initialize DataTables
// ==========================================================

$(document).ready(function() {
    var tables =
        document.querySelectorAll("table.findings-datatable");

    tables.forEach(function(table) {
        if (!$.fn.DataTable.isDataTable(table)) {
            $(table).DataTable({
                "paging": true,
                "pageLength": 10,
                "searching": true,
                "ordering": true,
                "info": true,
                "autoWidth": false,
                "lengthChange": true,
                "lengthMenu": [
                    [10, 25, 50, 100],
                    [10, 25, 50, 100]
                ],
                "dom": '<"top"lf>rt<"bottom"ip>',
                "language": {
                    "search": "Filter findings:",
                    "lengthMenu": "Show _MENU_ entries",
                    "info":
                        "Showing _START_ to _END_ of _TOTAL_ findings",
                    "paginate": {
                        "previous": "Previous",
                        "next": "Next"
                    }
                },
                "columnDefs": [
                    { "width": "10%", "targets": 0 },
                    { "width": "20%", "targets": 1 },
                    { "width": "18%", "targets": 2 },
                    { "width": "30%", "targets": 3 },
                    { "width": "8%", "targets": 4 },
                    { "width": "14%", "targets": 5 }
                ],
                "order": [[4, "desc"]]
            });
        }
    });
});

// ==========================================================
// Risk Distribution Chart
// ==========================================================

var riskCtx = document.getElementById("riskChart");

if (riskCtx && typeof Chart !== "undefined") {
    new Chart(riskCtx.getContext("2d"), {
        type: "doughnut",

        data: {
            labels: [
                "Critical",
                "High",
                "Medium",
                "Low",
                "Info"
            ],

            datasets: [{
                data: [
                    REPORT_CONFIG.riskCounts.critical,
                    REPORT_CONFIG.riskCounts.high,
                    REPORT_CONFIG.riskCounts.medium,
                    REPORT_CONFIG.riskCounts.low,
                    REPORT_CONFIG.riskCounts.info
                ],

                backgroundColor: [
                    REPORT_CONFIG.colors.risk_critical,
                    REPORT_CONFIG.colors.risk_high,
                    REPORT_CONFIG.colors.risk_medium,
                    REPORT_CONFIG.colors.risk_low,
                    REPORT_CONFIG.colors.risk_info
                ],

                borderWidth: 3,
                borderColor: "#fff"
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: true,

            plugins: {
                legend: {
                    position: "bottom",

                    labels: {
                        padding: 20,

                        font: {
                            size: 13,
                            weight: "600"
                        }
                    }
                }
            }
        }
    });
}

// ==========================================================
// Type Distribution Chart
// ==========================================================

var typeCtx = document.getElementById("typeChart");

if (typeCtx && typeof Chart !== "undefined") {
    var typeLabels = REPORT_CONFIG.typeLabels;

    var typeValues = REPORT_CONFIG.typeValues;

    new Chart(typeCtx.getContext("2d"), {
        type: "bar",

        data: {
            labels: typeLabels,

            datasets: [{
                label: "Number of Issues",
                data: typeValues,

                backgroundColor:
                    REPORT_CONFIG.colors.signature_orange,

                borderColor:
                    REPORT_CONFIG.colors.dark_grey,

                borderWidth: 2,
                borderRadius: 5
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: true,

            plugins: {
                legend: {
                    display: false
                }
            },

            scales: {
                y: {
                    beginAtZero: true,

                    ticks: {
                        stepSize: 1
                    }
                },

                x: {
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45
                    }
                }
            }
        }
    });
}