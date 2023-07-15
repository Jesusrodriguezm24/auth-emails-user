const { getAll, create, getOne, remove, update, login, verifyCode, getLoggedUser, setPassword, getResetPassword } = require('../controllers/user.controllers');
const express = require('express');
const verifyJWT = require('../utils/verifyJWT');

const userRouter = express.Router();

userRouter.route('/')
    .get(verifyJWT, getAll)
    .post(create);

userRouter.route('/verify/:code')
    .get(verifyCode);

userRouter.route('/login')
    .post(login);

userRouter.route('/me')
    .get(verifyJWT, getLoggedUser); 

userRouter.route('/reset_password')
    .post(getResetPassword);

userRouter.route('/reset_password/:code')
    .post(setPassword);

userRouter.route('/:id')
    .get(verifyJWT, getOne)
    .delete(verifyJWT, remove)
    .put(verifyJWT, update);

module.exports = userRouter;
