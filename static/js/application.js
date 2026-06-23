var firebase = window.firebase || {
    apps: []
};

var db = null;

// Shared dashboard state
var socket;
var messages_received = [];
var currentPage = 1;
var itemsPerPage = 10;
var myChart = null;

// Firebase is optional on this page. These helpers keep the dashboard usable
// when the browser SDK is loaded but not initialized.
function isFirebaseInitialized() {
    return typeof firebase !== "undefined" && Array.isArray(firebase.apps) && firebase.apps.length > 0;
}

function getFirestoreDb() {
    if (db && typeof db.collection === "function") {
        return db;
    }

    if (isFirebaseInitialized() && typeof firebase.firestore === "function") {
        db = firebase.firestore();
        return db;
    }

    return null;
}

function getFirebaseAuth() {
    if (isFirebaseInitialized() && typeof firebase.auth === "function") {
        return firebase.auth();
    }

    return null;
}

function getServerTimestamp() {
    if (
        isFirebaseInitialized() &&
        firebase.firestore &&
        firebase.firestore.FieldValue &&
        typeof firebase.firestore.FieldValue.serverTimestamp === "function"
    ) {
        return firebase.firestore.FieldValue.serverTimestamp();
    }

    return new Date();
}

const loadStoredFlows = function() {
    try {
        const userId = "anonymous";
        const key = `rnids_flows_${userId}`;
        const savedFlows = localStorage.getItem(key);
        
        if (savedFlows) {
            messages_received = JSON.parse(savedFlows);
            console.log(`Loaded ${messages_received.length} flows from local storage for user ${userId}`);
            if (typeof updateTable === 'function') {
                updateTable(currentPage);
            }
        }
    } catch (e) {
        console.error("Failed to load flows from localStorage:", e);
    }
};

$(document).ready(function () {
    socket = io('/test');
    initializeSocketHandlers();
    initializeChart();
    loadStoredFlows();
});

function initializeFirebaseListeners() {
    updateNotificationBadge();
    updateHighRiskCounter();
    setupGlobalStatsListener();
}

function initializeChart() {
    var chartElement = document.getElementById("myChart");
    if (!chartElement || typeof Chart === "undefined") {
        return;
    }

    var ctx = chartElement.getContext("2d");
    myChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Flow Count',
                data: [],
                backgroundColor: 'rgba(75,192,192,0.2)',
                borderColor: 'rgba(75,192,192,1)',
                borderWidth: 1
            }]
        }
    });
}

function setupGlobalStatsListener() {
    const firestoreDb = getFirestoreDb();
    if (!firestoreDb) {
        return;
    }

    firestoreDb.collection("global_stats").doc("realtime")
        .onSnapshot((doc) => {
            try {
                const data = doc.data();
                if (data) {
                    $("#active-sessions").text(data.active_sessions || 0);
                    $("#current-threats").text(data.threats_last_hour || 0);

                    if (myChart && data.active_sessions) {
                        if (myChart.data.datasets[0].data.length <= 1) {
                            myChart.data.datasets[0].data = [data.active_sessions];
                            myChart.update();
                        }
                    }
                }
            } catch (error) {
                console.error("Error processing realtime stats:", error);
                toastr.error("Unable to get real-time statistics");
            }
        }, (error) => {
            handleFirebaseError(error, "global_stats");
        });
}

function checkRiskLevel(riskLevel, flowData) {
        const classification = flowData[flowData.length - 3];
        const isNonBenign = classification !== "Benign";
        const isHighRisk = riskLevel === "high" || riskLevel === "very_high";
        
        if (isHighRisk) {
            let highRiskCount = parseInt($('#high-risk-flows').text()) || 0;
            $('#high-risk-flows').text(highRiskCount + 1);
        }
        
        if (isHighRisk || isNonBenign) {
            let toastrType = 'warning';
            let alertTitle = 'Security Alert';
            
            if (riskLevel === "very_high") {
                toastrType = 'error';
                alertTitle = 'CRITICAL SECURITY ALERT';
            } else if (!isHighRisk && isNonBenign) {
                toastrType = 'info';
                alertTitle = 'Suspicious Flow Detected';
            }
            
            const message = `
                <strong>${classification}</strong> traffic detected!<br>
                <span class="notification-detail">Source: ${flowData[1]}</span><br>
                <span class="notification-detail">Destination: ${flowData[3]}</span><br>
                <span class="notification-detail">Protocol: ${flowData[5]}</span><br>
                <span class="notification-detail">Risk Level: ${riskLevel.replace('_', ' ')}</span>
            `;
            
            toastr.options = {
                closeButton: true,
                progressBar: true,
                timeOut: isHighRisk ? 10000 : 5000,
                extendedTimeOut: 3000,
                positionClass: "toast-top-right",
                showEasing: "swing",
                hideEasing: "linear",
                showMethod: "fadeIn",
                hideMethod: "fadeOut",
                escapeHtml: false
            };
            
            toastr[toastrType](message, alertTitle);

            if (isHighRisk) {
                const alertSound = document.getElementById("alert-sound");
                if (alertSound) {
                    alertSound.pause();
                    alertSound.currentTime = 0;
                    alertSound.volume = 0.7;    
                    
                    const playPromise = alertSound.play();
                    if (playPromise !== undefined) {
                        playPromise.catch(e => {
                            console.error("Failed to play alert sound:", e);
                            $(document).one('click', function() {
                                alertSound.play().catch(e => console.error("Still failed to play sound:", e));
                            });
                        });
                    }
                } else {
                    console.error("Alert sound element not found");
                }
            }
            
            const firestoreDb = getFirestoreDb();
            if (firestoreDb) {
                firestoreDb.collection("notifications").add({
                    type: isHighRisk ? "high_risk_flow" : "suspicious_flow",
                    risk_level: riskLevel,
                    classification: classification,
                    source_ip: flowData[1],
                    dest_ip: flowData[3],
                    protocol: flowData[5],
                    timestamp: getServerTimestamp(),
                    viewed: false
                }).catch(error => {
                    console.error("Error sending notification:", error);
                });
            }
        }
    }

    // The dashboard table is rebuilt from the current page of messages_received.
    function updateTable(page) {
        var start = (page - 1) * itemsPerPage;
        var end = start + itemsPerPage;
        var paginatedData = messages_received.slice(start, end);
    
        var messages_string = `
            <tr>
                <th>Flow ID</th>
                <th>Src IP</th>
                <th>Src Port</th>
                <th>Dst IP</th>
                <th>Dst Port</th>
                <th>Protocol</th>
                <th>Flow Start</th>
                <th>Flow End</th>
                <th>App Name</th>
                <th>PID</th>
                <th>Prediction</th>
                <th>Prob</th>
                <th>Risk</th>
                <th>Details</th>
            </tr>`;
    
        for (var i = 0; i < paginatedData.length; i++) {
            var riskLevel = paginatedData[i][paginatedData[i].length - 1].toLowerCase().replace(" ", "_");
            var rowClass = riskLevel.includes("high") ? 'high-risk-row' : '';
            
            messages_string += `<tr class="${rowClass}" data-risk="${riskLevel}">`;
            for (var j = 0; j < paginatedData[i].length; j++) {
                messages_string += `<td>${paginatedData[i][j].toString()}</td>`;
            }
            messages_string += `<td><a href="/detail?flow_id=${paginatedData[i][0]}" class="btn btn-sm btn-primary">Details</a></td></tr>`;
        }
        $('#details').html(messages_string);
    
        var totalPages = Math.ceil(messages_received.length / itemsPerPage);
        var paginationHtml = '';
        for (var p = 1; p <= totalPages; p++) {
            paginationHtml += `
                <li class="page-item${p === currentPage ? ' active' : ''}">
                    <a class="page-link" href="#" data-page="${p}">${p}</a>
                </li>`;
        }
        $('#pagination').html(paginationHtml);
        updateFilteredCount();
    }
    
    function updateFilteredCount() {
        const visibleRows = $("#details tr:visible").length - 1;
        $("#filtered-count").text(visibleRows);
    }

$(document).on('click', '#logout-button', function(e) {
    e.preventDefault();
    
    toastr.info("Logging out...", "", {timeOut: 2000});
    
    if (clearAllFlowStorage()) {
        const auth = getFirebaseAuth();
        if (!auth) {
            window.location.href = '/logout';
            return;
        }

        auth.signOut().then(() => {
            fetch('/clear-local-flows')
                .then(response => response.json())
                .then(data => {
                    console.log("Server cleanup response:", data);
                    window.location.href = '/logout';
                })
                .catch(error => {
                    console.error("Error calling server cleanup:", error);
                    window.location.href = '/logout';
                });
        }).catch(error => {
            console.error("Sign out error:", error);
            toastr.error("Logout failed. Please try again.");
        });
    } else {
        toastr.error("Failed to clear local data. Logout aborted.");
    }
});

    
    $(document).on('click', '.page-link', function (e) {
        e.preventDefault();
        currentPage = $(this).data('page');
        updateTable(currentPage);
    });

function initializeSocketHandlers() {
    if (!socket || typeof socket.on !== "function") {
        console.error("Socket.IO is not initialized");
        return;
    }

    socket.on('newresult', function (msg) {
        try {
            if (messages_received.length >= 100) {
                messages_received.shift();
            }
            messages_received.push(msg.result);
            updateTable(currentPage);
            
            saveFlowsToLocal();
            checkRiskLevel(msg.risk_level, msg.result);

            var chartLabels = [];
            var chartData = [];
            for (var i = 0; i < msg.ips.length; i++) {
                chartLabels.push(msg.ips[i].SourceIP);
                chartData.push(msg.ips[i].count);
            }
            if (myChart) {
                myChart.data.labels = chartLabels;
                myChart.data.datasets[0].data = chartData;
                myChart.update();
            }
            
            console.log("Received classification:", msg.classification);
            
            if (msg.classification && msg.classification !== "Benign") {
                console.log("Non-benign traffic detected:", msg.classification);
                let currentThreats = parseInt($("#current-threats").text()) || 0;
                $("#current-threats").text(currentThreats + 1);
            }
        } catch (error) {
            console.error("Error processing new result:", error);
        }
    });

    socket.on('connect_error', function (error) {
        console.error('Socket.IO connection error:', error);
        toastr.error("Connection lost. Attempting to reconnect...");
        setTimeout(function() {
            socket.connect();
        }, 3000);
    });

    socket.on('reconnect', function() {
        toastr.success("Connection reestablished", "Success");
    });
}

    function updateNotificationBadge() {
        const firestoreDb = getFirestoreDb();
        if (!firestoreDb) {
            $("#notification-badge").hide();
            return;
        }

        firestoreDb.collection("notifications")
            .where("viewed", "==", false)
            .onSnapshot((snapshot) => {
                const count = snapshot.size;
                const badge = $("#notification-badge");
                
                if (count > 0) {
                    badge.text(count).show();
                } else {
                    badge.hide();
                }
            }, (error) => {
                handleFirebaseError(error, "notification_badge");
            });
    }

    function updateHighRiskCounter() {
        const firestoreDb = getFirestoreDb();
        if (!firestoreDb) {
            return;
        }

        firestoreDb.collection("malicious_flows")
            .where("risk.level", "in", ["high", "very_high"])
            .onSnapshot((snapshot) => {
                try {
                    $("#high-risk-flows").text(snapshot.size || 0);
                } catch (error) {
                    console.error("Error updating high risk counter:", error);
                }
            }, (error) => {
                handleFirebaseError(error, "high_risk_counter");
            });
    }

    $("#risk-filter").on("change", function() {
        const selectedRisk = $(this).val().toLowerCase();
        
        $("#details tr").show();
        
        if (selectedRisk !== "all") {
            $("#details tr:not(:first-child)").each(function() {
                const riskCell = $(this).find("td:nth-child(13)").text().toLowerCase();
                const normalizedRisk = selectedRisk.replace("_", " ");
                
                if (!riskCell.includes(normalizedRisk)) {
                    $(this).hide();
                }
            });
        }
        
        updateFilteredCount();
    });

  $("#download-report").on("click", function() {
    try {
        const selectedRisk = $("#risk-filter").val().toLowerCase();
        let filteredData = messages_received;
        
        if (selectedRisk !== "all") {
            const normalizedRisk = selectedRisk.replace("_", " ");
            filteredData = messages_received.filter(row => {
                const riskCell = row[row.length - 1].toLowerCase();
                return riskCell.includes(normalizedRisk);
            });
        }

        if (filteredData.length === 0) {
            toastr.warning("No data to download with current filter");
            return;
        }

        const headers = [
            'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 
            'Protocol', 'Flow Start', 'Flow End', 'App Name', 'PID',
            'Prediction', 'Prob', 'Risk'
        ];

        const csvRows = [headers.join(",")];
        
        filteredData.forEach(row => {
            const rowData = [];
            for (let j = 0; j < 13; j++) {
                let text = String(row[j]).replace(/<[^>]*>/g, '');
                text = text.replace(/,/g, ' ');
                text = text.replace(/\n/g, ' ');
                rowData.push(`"${text}"`);
            }
            csvRows.push(rowData.join(","));
        });

        const csvContent = csvRows.join("\n");
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        
        const filename = selectedRisk === "all" ? 
            `rnids-full-report-${timestamp}.csv` : 
            `rnids-${selectedRisk}-risk-${timestamp}.csv`;
            
        link.setAttribute("href", url);
        link.setAttribute("download", filename);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        toastr.success(`Downloaded ${filteredData.length} rows`);
    } catch (e) {
        console.error("Error downloading report:", e);
        toastr.error("Failed to download report: " + e.message);
    }
});

    $("#notifications-link").on("click", function(e) {
        e.preventDefault();
        toastr.info("Notifications panel functionality coming soon");
    });
    
    setTimeout(updateFilteredCount, 1000);

    function handleFirebaseError(error, context) {
        console.error(`Firebase error in ${context}:`, error);
        
        const errorKey = `shown_${context}_error`;
        if (!window[errorKey]) {
            if (error.code === 'permission-denied') {
                toastr.warning("Firebase permission error. Please check authentication.", "Access Denied");
            } else {
                toastr.error("Error connecting to database. Some features may not work.", "Connection Error");
            }
            window[errorKey] = true;
        }
    }



function saveFlowsToLocal() {
    try {
        const userId = "anonymous";
        const key = `rnids_flows_${userId}`;
        localStorage.setItem(key, JSON.stringify(messages_received));
        console.log(`Saved ${messages_received.length} flows to local storage for user ${userId}`);
    } catch (e) {
        console.error("Failed to save flows to localStorage:", e);
    }
}

function clearAllFlowStorage() {
    try {
        localStorage.removeItem('rnids_flows');
        
        const userId = "anonymous";
        localStorage.removeItem(`rnids_flows_${userId}`);
        
        messages_received = [];
        updateTable(1);
        
        console.log("Cleared all flow data from storage");
        return true;
    } catch (e) {
        console.error("Error clearing flow storage:", e);
        return false;
    }
}


function clearUserFlows() {
    try {
        const userId = "anonymous";
        const key = `rnids_flows_${userId}`;
        localStorage.removeItem(key);
        console.log(`Cleared flows for user ${userId}`);
        messages_received = [];
    } catch (e) {
        console.error("Failed to clear user flows:", e);
    }
}
