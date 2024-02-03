const username = document.getElementById("username");
const password = document.getElementById("password");
const password_confirm = document.getElementById("password-confirm");
const tacbox = document.getElementById("tacbox");
const signupForm = document.getElementById("signup-form");
const loginForm = document.getElementById("login-form");
const loginEmail = document.getElementById("login-email");
const loginPassword = document.getElementById("login-password");
const minimumPasswordLength = 8;
console.log("==== PASSWORD TESTING QUICK STRINGS ====")
console.log("TOO SHORT: longer")
console.log("NO CAPITAL: longerthantwelve")
console.log("NO NUMBER: Longerthantwelve")
console.log("NO SYMBOL: Longerthantw3lve")
console.log("MEETS REQ.: Longerth@ntw3lve")

function validateSignupForm() {
    /* GOOD REFERENCES FOR STRONG PASSWORD RULES */
    /* https://support.google.com/accounts/answer/32040 */
    /* https://support.microsoft.com/en-us/windows/create-and-use-strong-passwords-c5cebb49-8c53-4f5e-2bc4-fe357ca048eb */
    if (password.value.length <= minimumPasswordLength /* Check that the password length is higher than the minimum password length */) {
        password.setCustomValidity(`Password must be ${minimumPasswordLength} or more characters long.`);
        return false;
    } else if (/^\s/.test(password.value) || /\s$/.test(password.value) /* Check whether the password begins or ends with whitespace */) {
        password.setCustomValidity(`Password cannot start or end with an empty character.`);
        return false;
    } else if (!(/[A-Z]/.test(password.value) /* Use a regular expression whether the string contains a capital letter */)) {
        password.setCustomValidity(`Password must contain at least one capital letter.`);
        return false;
    } else if (!(/\d/.test(password.value) /* Test whether the string contains a number */)) {
        password.setCustomValidity(`Password must contain at least one number.`);
        return false;
    }
    else if (!(/[ `!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/.test(password.value) /* Test whether the string contains a special character */)) {
        password.setCustomValidity(`Password must contain at least one special character.`);
        return false;
    }
    else {
        password.setCustomValidity(``);
    }
    if (password.value !== password_confirm.value /* Make sure that the initial password is the same as the confirmed password */) {
        password_confirm.setCustomValidity(`Confirmed password does not match.`);
        return false;
    } else {
        password_confirm.setCustomValidity(``);
    }
    if (!tacbox.checked /* Make sure that the user accepted the terms and conditions */) {
        tacbox.setCustomValidity(`You must accept the terms and conditions to sign up.`);
        return false;
    } else {
        tacbox.setCustomValidity(``);
    }
    return true
}
function validateLoginForm() {
    if (loginPassword.value.length <= 0) {
        loginPassword.setCustomValidity(`Type your password.`)
        return false
    }
    else if (loginEmail.value <= 0) {
        loginEmail.setCustomValidity(`Type your email.`)
        return false
    }
    else {
        loginPassword.setCustomValidity(``)
        loginEmail.setCustomValidity(``)
    }
    return true
}
function submitSignup() {
    let isFormValid = validateSignupForm() /* Run the validateForm() function and pipe the validity into a boolean variable */;
    if (!isFormValid) /* If the form is not valid, show the invalidity on screen */ {
        password.reportValidity();
        password_confirm.reportValidity();
        tacbox.reportValidity();
    }
    else {
        signupForm.submit();
    }
}
async function handleSubmit(event) {
    let isFormValid = validateLoginForm() /* Run the validateForm() function and pipe the validity into a boolean variable */;
    if (!isFormValid) /* If the form is not valid, show the invalidity on screen */ {
        loginPassword.reportValidity();
        loginEmail.reportValidity();
    }
    else {
        event.preventDefault();
        var data = new FormData(loginForm);
        fetch("../login", {
            method: "post",
            body: data,
            headers: {
                'Accept': 'application/json'
            }
        })
            .then(response => response.json())
            .then(data => {
                if (data["status"] == "success") {
                    console.log(data["cookie"]);
                    document.cookie = data["cookie"];
                } else {
                    console.log("Login failed: " + data["reason"])
                }
            })
    }

}
/* Some event listeners to reliably trigger the form validation */
document.getElementById("signup-form").addEventListener('change', validateSignupForm);
document.getElementById("signup-form").addEventListener('keyup', validateSignupForm);
document.getElementById("login-form").addEventListener('keypress', (e) => {
    if (e.key == "Enter") {
        loginAction(e);
    }
});


const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const shouldSignup = urlParams.get('signup') == "true" ? true : false;
if (shouldSignup == false) {
    loginForm.style.display = "flex"
    signupForm.style.display = "none"
} else {
    signupForm.style.display = "flex"
    loginForm.style.display = "none"
}

var loggingIn = !shouldSignup;
function signupAction() {
    if (loggingIn) {
        signupForm.style.display = "flex"
        loginForm.style.display = "none"
        loggingIn = false;
    } else {
        submitSignup();
    }
}

function loginAction(event) {
    if (loggingIn) {
        handleSubmit(event);
    } else {
        loginForm.style.display = "flex";
        signupForm.style.display = "none";
        loggingIn = true;
    }
    window.location.href = 'my_home_page.html';
}