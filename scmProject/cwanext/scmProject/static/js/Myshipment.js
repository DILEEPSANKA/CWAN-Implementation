function searchTable() {
    let input = document.getElementById("searchInput").value.toUpperCase();
    let table = document.querySelector("table tbody");
    let rows = table.getElementsByTagName("tr");

    for (let i = 0; i < rows.length; i++) {
        let rowText = rows[i].textContent || rows[i].innerText; 
        if (rowText.toUpperCase().includes(input)) {
            rows[i].style.display = ""; 
        } else {
            rows[i].style.display = "none";
        }
    }
}

const searchInput = document.getElementById("searchInput");
const searchIcon = document.querySelector(".search-icon");

searchInput.addEventListener("input", () => {
    searchIcon.style.opacity = searchInput.value.trim() ? "0" : "1";
});

function logout(event) {
    event.preventDefault();

    localStorage.removeItem("access_token");

    fetch("/logout", { 
        method: "POST",
        credentials: "same-origin",
        headers: {
            "Content-Type": "application/json"
        }
    })
    .then(response => {
        if (response.ok) {
            window.location.href = "/login"; 
        } else {
            throw new Error("Logout failed");
        }
    })
    .catch(error => {
        console.error("Logout error:", error);
    });
}
