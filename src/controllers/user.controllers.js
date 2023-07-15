const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');
const jwt = require('jsonwebtoken');
const EmailCode = require('../models/EmailCode');

const getAll = catchError(async(req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async(req, res) => {
    const { firstName, lastName, email, password, country, image, frontBaseUrl } = req.body;

    const encryptedPassword = await bcrypt.hash(password, 10);
    const result = await User.create({ firstName, lastName, email, password: encryptedPassword, country, image, frontBaseUrl });

    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/auth/verify_email/${code}`;

    await EmailCode.create({
        code: code,
        userId: result.id
    });

    await sendEmail({
		to: email, 
		subject: "Verificate Email",
		html: ` <h1>Hello ${firstName} ${lastName}</h1>
                <p>verify your account clicking this link </p>
                <a href=${link}>${link}</a>
                <hr>
				<b>Thamks for sing up in this App</b>
		` 
    });

    return res.status(201).json(result);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if(!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const { firstName, lastName, country, image, frontBaseUrl } = req.body;
    const result = await User.update(
        { firstName, lastName, country, image, frontBaseUrl },
        { where: {id}, returning: true }
    );
    if(result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyCode = catchError(async(req, res) => {
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({where:{code}});
    if(!emailCode) return res.status(401).json({message:"Invalid code"});

    const user = await User.findByPk(emailCode.userId);
    user.isVerified = true;
    await user.save();
    await emailCode.destroy();

    return res.json(user);
});

const login = catchError(async(req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: {email} });
    if(!user) return res.status(401).json({ error: "Invalid credentials"})

    const isValid = await bcrypt.compare(password, user.password)
    if(!isValid) return res.status(401).json({ error: "Invalid credentials"});

    if(!user.isVerified) return res.status(401).json({ error: "User is not verified" });

    const token = jwt.sign(
        {user},
        process.env.TOKEN_SECRET,
        { expiresIn: '1d' }
    )

    return res.json({user, token}); 
});

const getLoggedUser = catchError(async(req, res) => {
    const user = req.user;
    return res.json(user);

});

const getResetPassword = catchError(async(req, res) => {
    const { email, frontBaseUrl} = req.body;

    const user = await User.findOne({ where: {email} });
    if(!user) return res.status(401).json({ error: "Invalid credentials"});

    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/auth/reset_password/${code}`;

    await EmailCode.create({
        code: code,
        userId: user.id
    });

    await sendEmail({
		to: email, 
		subject: "Change password",
		html: ` <h1>Hello ${user.firstName} ${user.lastName}</h1>
                <p>Change the password clicking this link </p>
                <a href=${link}>${link}</a>
                <hr>
				<b>Thamks</b>
		` 
    });

    return res.status(201).json(user);
 
});

const setPassword = catchError(async(req, res) => {
    const { password } = req.body;
    const { code } = req.params;

    const emailCode = await EmailCode.findOne({where:{code}});
    if(!emailCode) return res.status(401).json({message:"Invalid code"});

    const encryptedNewPassword = await bcrypt.hash(password, 10);

    const result = await User.update(
        { password: encryptedNewPassword },
        { where: {id:emailCode.userId}, returning: true }
    );

    if(result[0] === 0) return res.sendStatus(404);

    return res.json(result[1][0]);

});

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update, 
    verifyCode,
    login, 
    getLoggedUser,
    getResetPassword,
    setPassword
}