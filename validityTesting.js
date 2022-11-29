// function to check if a string is valid email

export function validateEmail(email) {
    const re = /\S+@\S+\.\S+/;
    return re.test(email);
}

// check if a string is valid phone number
export function validatePhone(phone) {
    const re = /^\d{10}$/;
    return re.test(phone);
}

export function isValidUser(user) {
    return validateEmail(user) || validatePhone(user);
}