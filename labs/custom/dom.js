const message = new URLSearchParams(window.location.search).get("message") || "";
document.getElementById("output").innerHTML = message;
