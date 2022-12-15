import yup from 'yup';

const validateEmail = (email) => {
    return yup.string().trim().required().email().isValid(email);
}

const validatePhone = (phone) => {
    return yup.string().trim().required().matches(/^\d{10}$/).isValid(phone);
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