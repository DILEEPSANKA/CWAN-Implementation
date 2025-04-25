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
  
  