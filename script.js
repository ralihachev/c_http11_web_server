console.log("Custom Web Server - JavaScript loaded successfully!");

// Add some interactive functionality
document.addEventListener("DOMContentLoaded", function () {
  console.log("DOM loaded - Web server is working!");

  // Add click handlers to buttons
  const buttons = document.querySelectorAll(".btn");
  buttons.forEach((button) => {
    button.addEventListener("mouseover", function () {
      console.log("Button hovered:", this.textContent);
    });
  });

  // Display server info in console
  console.log("=== Server Information ===");
  console.log("Server: CustomWebServer/1.0");
  console.log("Built with: Raw C sockets");
  console.log("Protocol: HTTP/1.1");
  console.log("Features: Header parsing, MIME types, File serving");

  // Add a simple animation
  const title = document.querySelector("h1");
  if (title) {
    let colors = ["#e74c3c", "#3498db", "#2ecc71", "#f39c12", "#9b59b6"];
    let index = 0;

    setInterval(() => {
      title.style.color = colors[index];
      index = (index + 1) % colors.length;
    }, 2000);
  }

  // Test AJAX request to JSON file
  fetch("/data.json")
    .then((response) => response.json())
    .then((data) => {
      console.log("JSON data loaded:", data);
    })
    .catch((error) => {
      console.log("JSON file not found (expected for testing 404)");
    });
});

// Function to test POST request
function testPOST() {
  fetch("/", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "test=Hello from JavaScript POST request",
  })
    .then((response) => response.text())
    .then((data) => {
      console.log("POST response:", data);
    });
}

// Expose function globally
window.testPOST = testPOST;
