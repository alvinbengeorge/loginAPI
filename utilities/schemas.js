import yup from 'yup';

const schema = yup.object().shape({
    user: yup.string().trim().required(),
    password: yup.string().trim().required()
});
const updateSchema = yup.object().shape({
    user: yup.string().trim().required(),
    password: yup.string().trim().required(),
    userID: yup.string().trim().required()
});

export {
    schema,
    updateSchema
}