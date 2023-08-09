//----------------- ALL THE REQUIRES HERE ------------------
const express = require('express');
const User = require('../models/User.model');
const router = express.Router();
const bcryptjs = require('bcryptjs');
const saltRounds = 10;
const mongoose = require('mongoose')

// --------------------- ALL THE ROUTES HERE ---------------------
router.get("/signup", (req, res, next) => {
    res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
    // WE DESTUCTURE THE BODY AND WE HAVE DIFFERNT VARIABLES
    const { username, password } = req.body;

    // make sure users fill all mandatory fields:
    if (!username || !password) {
        res.render('auth/signup', { errorMessage: 'All fields are mandatory. Please provide your username, email and password.' });
        return;
    }

    // make sure passwords are strong:
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
    if (!regex.test(password)) {
        res
            .status(500)
            .render('auth/signup', { errorMessage: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
        return;
    }

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
        .catch(error => {
            if (error instanceof mongoose.Error.ValidationError) {
                res.status(500).render('auth/signup', { errorMessage: error.message });
            } else if (error.code === 11000) {

                console.log(" Username need to be unique. Either username is already used. ");

                res.status(500).render('auth/signup', {
                    errorMessage: 'User not found and/or incorrect password.'
                });
            } else {
                next(error);
            }
        });
})

router.get("/userProfile", (req, res) => {
    res.render("users/user-profile")
})


//////////// L O G I N ///////////

router.get("/login", (req, res) => {
    res.render('auth/login')
})
 
// POST login route ==> to process form data
router.post('/login', (req, res, next) => {
    const { username, password } = req.body;
   
    if (username === '' || password === '') {
      res.render('auth/login', {
        errorMessage: 'Please enter both, username and password to login.'
      });
      return;
    }
   
    User.findOne({ username })
      .then(user => {
        if (!user) {
          console.log("Username not registered. ");
          res.render('auth/login', { errorMessage: 'User not found and/or incorrect password.' });
          return;
        } else if (bcryptjs.compareSync(password, user.passwordHash)) {
          res.render('users/user-profile', { user });
        } else {
          console.log("Incorrect password. ");
          res.render('auth/login', { errorMessage: 'User not found and/or incorrect password.' });
        }
      })
      .catch(error => next(error));
  });
   

module.exports = router;
