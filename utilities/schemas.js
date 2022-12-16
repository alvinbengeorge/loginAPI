import yup from 'yup';

const validateEmail = (email) => {
    if (!email) return false;
    if (yup.string().email().isValidSync(email)) {
        return true;
    }
    return false;
}

const validatePhone = (phone) => {
    return /^\d{10}$/.test(phone);
}

const validateUser = (user) => {
    return validateEmail(user) || validatePhone(user);
}

const schema = yup.object().shape({
    user: yup.string().test('user', 'Invalid User', validateUser),
    password: yup.string().trim().required()
});
const updateSchema = yup.object().shape({
    user: yup.string().test('user', 'Invalid User', validateUser),
    password: yup.string().trim().required(),
    userID: yup.string().trim().required()
});

export {
    schema,
    updateSchema
}