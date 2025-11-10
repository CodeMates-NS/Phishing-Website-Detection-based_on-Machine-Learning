// =============== CONFIGURATION ===============
const backendURL = "https://phishing-website-detection-based-on.onrender.com/predict";
// Change this only if you redeploy your backend on a different Render URL
// =============================================

// Wait for DOM to load
document.addEventListener("DOMContentLoaded", () => {

    const form = document.getElementById("phishForm");
    const urlField = document.getElementById("url");
    const urlDisplay = document.getElementById("urlDisplay");
    const enteredUrl = document.getElementById("enteredUrl");
    const resultBox = document.getElementById("result");
    const predictionText = document.getElementById("predictionText");
    const resetBtn = document.getElementById("resetBtn");

    const extraContainer = document.getElementById("extraReasonsContainer");
    const extraList = document.getElementById("extraReasons");
    const toggleBtn = document.getElementById("toggleDetails");
    const detailsBox = document.getElementById("detailsBox");

    // ========== FORM SUBMIT HANDLER ==========
    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const urlValue = urlField.value.trim();

        // Basic validation
        if (!urlValue) {
            alert("Please enter a URL.");
            return;
        }
        if (urlValue.split(/\s+/).length > 1) {
            alert("Please enter only one URL at a time.");
            return;
        }

        // Display the entered URL
        enteredUrl.textContent = urlValue;
        urlDisplay.style.display = "block";

        // Show loading state
        predictionText.textContent = "⏳ Checking...";
        resultBox.style.display = "block";
        extraContainer.style.display = "none";
        detailsBox.style.display = "none";

        try {
            // Send request to backend
            const response = await fetch(backendURL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: urlValue }),
            });

            const data = await response.json();

            // Expecting backend to return: { prediction_text: "...", extra_reasons: [...] }
            const prediction = data.prediction_text || "Unable to determine result.";
            const reasons = data.extra_reasons || [];

            // Update UI with prediction
            predictionText.textContent = prediction;
            resultBox.style.display = "block";

            // Color coding
            if (prediction.includes("Phishing")) {
                resultBox.className = "result danger";
            } else {
                resultBox.className = "result success";
            }

            // Show extra reasons if available
            if (reasons.length > 0 && prediction.includes("Phishing")) {
                extraList.innerHTML = "";
                reasons.forEach(reason => {
                    const li = document.createElement("li");
                    li.textContent = `• ${reason}`;
                    extraList.appendChild(li);
                });
                extraContainer.style.display = "block";
            }

        } catch (err) {
            console.error("Error:", err);
            predictionText.textContent = "⚠️ Unable to connect to the backend.";
        }
    });

    // ========== RESET BUTTON ==========
    resetBtn.addEventListener("click", () => {
        urlField.value = "";
        urlDisplay.style.display = "none";
        resultBox.style.display = "none";
        extraContainer.style.display = "none";
        detailsBox.style.display = "none";
    });

    // ========== TOGGLE EXTRA DETAILS ==========
    if (toggleBtn) {
        toggleBtn.addEventListener("click", () => {
            if (detailsBox.style.display === "none") {
                detailsBox.style.display = "block";
                toggleBtn.textContent = "▲ Hide Details";
            } else {
                detailsBox.style.display = "none";
                toggleBtn.textContent = "▼ Show More Details";
            }
        });
    }

});
