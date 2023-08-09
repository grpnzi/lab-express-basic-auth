//----------------- ALL THE REQUIRES HERE ------------------
const express = require('express');
const User = require('../models/User.model');
const router = express.Router();
const bcryptjs = require('bcryptjs');
const saltRounds = 10;

// --------------------- ALL THE ROUTES HERE ---------------------
router.get("/signup", (req, res, next) => {
    res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
    // WE DESTUCTURE THE BODY AND WE HAVE DIFFERNT VARIABLES
    const { username, password } = req.body;

    bcryptjs
        .genSalt(saltRounds)
        .then(salt => bcryptjs.hash(password, salt))
        .then(hashedPassword => {
            return User.create({
                username,
                // if our variable name is different from the one in the model we can do this:
                passwordHash: hashedPassword
            })
        })
        .then(userFromDB => {
            console.log('Newly created user is: ', userFromDB);
            res.redirect("/userProfile");
        })
        .catch(error => next(error));
})

router.get("/userProfile", (req, res) => {
    res.render("users/user-profile")
})

module.exports = router;
