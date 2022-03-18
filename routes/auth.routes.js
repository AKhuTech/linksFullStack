const {Router} = require('express');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const {check, validationResult} = require('express-validator');
const User = require('../models/User');
const router = Router();

// /api/auth/register
router.post(
    '/register',
    [
        check("email", "Incorrect email").isEmail(),
        check("password", "Minimal length of password is 6 symbols").isLength({min: 6}), 
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);

            console.log(errors);

            if(!errors.isEmpty()){
                return res.status(400).json({
                    errors: errors.array(),
                    message: "Invalid registration data",
                })
            }

            const {email, password} = req.body;


            const candidate = await User.findOne({email});

            if (candidate){
                return res.status(400).json({ message: "User is already registered" });
            } else {
                const hashedPassword = await bcrypt.hash(password, 12);
                const user = new User({email, password: hashedPassword});

                await user.save();
                res.status(200).json({message: "User successfully created"});
            }
        } catch (e) {
            res.status(500).json({message: "Internal Server Error"});
            console.log(e);
        }
});

// /api/auth/login
router.post(
    '/login',
    [
        check('email', "Enter correct email").normalizeEmail().isEmail(),
        check('password', "Enter password").exists(),
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);

            if(!errors.isEmpty()){
                return res.status(400).json({
                    errors: errors.array(),
                    message: "Invalid login data",
                })
            }

            const {email, password} = req.body;

            const user = await User.findOne({email});

            if(!user){
                return res.status(400).json({message: "User not found"});
            }

            const passMatch = await bcrypt.compare(password, user.password);

            if (!passMatch){
                return res.status(400).json({message: "Invalid password"});
            }

            const token = jwt.sign(
                {userId: user.id},
                config.get("jwtSecret"),
                {expiresIn: "1h"}
            );

            res.json({token, userId: user.id});
            
        } catch (e) {
            res.status(500).json({message: "Internal Server Error"});
        }
});

module.exports = router;