function validateForm(event) {
    event.preventDefault();
    
    clearErrors();
  
    let valid = true;
  
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();
    const confirmPassword = document.getElementById('confirm-password').value.trim();
    const terms = document.getElementById('terms').checked;
  
    if (username === '') {
        document.getElementById('usernameError').textContent = 'Username is required.';
        valid = false;
    } else if (username.length < 3 || username.length > 20) {
        document.getElementById('usernameError').textContent = 'Username must be between 3 and 20 characters.';
        valid = false;
    }

    if (email === '') {
        document.getElementById('emailError').textContent = 'Email is required.';
        valid = false;
    }

    if (password === '') {
        document.getElementById('passwordError').textContent = 'Password is required.';
        valid = false;
    } else if (password.length < 8) {  
        document.getElementById('passwordError').textContent = 'Password should be at least 8 characters long.';
        valid = false;
    }

    if (confirmPassword === '') {
        document.getElementById('confirmPasswordError').textContent = 'Please confirm your password.';
        valid = false;
    } else if (confirmPassword !== password) {
        document.getElementById('confirmPasswordError').textContent = 'Passwords do not match.';
        valid = false;
    }
      
    if (!terms) {
        document.getElementById('termsError').textContent = 'You must agree to the Terms & Conditions.';
        valid = false;
    }
  
    if (valid) {
        document.getElementById('signupForm').reset();
    }
}

function clearErrors() {
    document.getElementById('usernameError').textContent = '';
    document.getElementById('emailError').textContent = '';
    document.getElementById('passwordError').textContent = '';
    document.getElementById('confirmPasswordError').textContent = '';
    document.getElementById('termsError').textContent = ''; 
}
