let captchaCode = "";

function generateCaptcha() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let code = "";
  for (let i = 0; i < 6; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  captchaCode = code;
  document.getElementById("captchaPreview").textContent = captchaCode; 
}

window.addEventListener('load', () => {
  generateCaptcha(); 
});

document.getElementById("login-form").addEventListener("submit", async function (event) {
  event.preventDefault(); 

  const captchaInput = document.getElementById("captcha").value;

  if (captchaInput !== captchaCode) {
    const captchaErrorElement = document.getElementById("captchaError");
    captchaErrorElement.style.display = "block";
    return;
  }

  const form = document.getElementById("login-form");
  const formData = new FormData(form);

  try {
    const response = await fetch("/login", { 
      method: "POST",
      body: formData,
    });

    if (response.ok) {
      const data = await response.json();
      const token = data.access_token;
      localStorage.setItem("access_token", token);
      console.log(data)
      let url = data.redirect_url
      window.location.href = url;  
    }
    else {
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.includes("application/json")) {
          const errorData = await response.json();
          displayError(errorData.detail || "Invalid username or password.");
        } else {
          displayError("An unexpected error occurred. Please try again.");
        }
      }
  } catch (error) {
    displayError("An error occurred during the login process. Please try again.");
    console.error("Login error:", error);
  }
});

function displayError(message) {
  const errorMessage = document.createElement("div");
  errorMessage.classList.add("form-alert", "alert-error");
  errorMessage.textContent = message;
  const form = document.getElementById("login-form");
  form.insertBefore(errorMessage, form.firstChild); 
  
  setTimeout(() => {
    errorMessage.style.display = "none";
  }, 5000);
}

document.getElementById("forgot-password-link").addEventListener("click", function (event) {
  event.preventDefault();
  document.getElementById("login-form").style.display = "none";
  document.getElementById("forgot-password-form").style.display = "block";
});

document.getElementById("back-to-login").addEventListener("click", function (event) {
  event.preventDefault();
  document.getElementById("forgot-password-form").style.display = "none";
  document.getElementById("login-form").style.display = "block";
});

document.getElementById("reset-password-btn").addEventListener("click", async function () {
  const username = document.getElementById("reset-username").value;
  const email = document.getElementById("reset-email").value;
  const newPassword = document.getElementById("new-password").value;
  const confirmPassword = document.getElementById("confirm-password").value;
  
  if (newPassword !== confirmPassword) {
    alert("New password and Confirm password do not match!");
    return;
  }

  const response = await fetch("/reset-password", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ username, email, new_password: newPassword })
  });

  const data = await response.json();

  if (response.ok) {
    alert("Password reset successful! You can now log in.");
    document.getElementById("forgot-password-form").style.display = "none";
    document.getElementById("login-form").style.display = "block";
  } else {
    alert(data.detail || "Password reset failed. Please try again.");
  }
});