//jshint esversion:6
import 'dotenv/config';
import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import passportLocalMongoose from 'passport-local-mongoose';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import findOrCreate from 'mongoose-findorcreate';

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());  // Added to parse JSON

app.use(session({
    secret: process.env.SESSION_SECRET || 'Our little secret.',  // Moved to environment variable
    resave: false,
    saveUninitialized: true,
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGODB_URI, {useNewUrlParser: true, useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,  // Added googleId
    secret: String,
    facebookId: String  // Added facebookId
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
    
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log("access TGoken ; ", accessToken);
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
    res.render("home");
});

// Fixed this route to actually call passport.authenticate
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});


app.get("/auth/facebook", passport.authenticate("facebook"));

app.get("/auth/facebook/secrets",
    passport.authenticate("facebook", { failureRedirect: "/login" }),
    function(req, res) {
        res.redirect("/secrets");
})


app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});


// Simplified logout route
app.get("/logout", function(req, res) {
    req.logout(function(err) {
        if(err) {
            return next(err);
        }
    });
    res.redirect("/");
})

app.get("/submit", function(req, res) {
    if(req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})

app.get("/secrets", async function(req, res) {
    try {
        const allSecrets = await User.find({secret : {$ne: null}});

        res.render("secrets", {usersWithSecrets: allSecrets});
    } catch(err) {
        console.log(err);
        res.status(500).send("An error occurred");
    }
});


app.post("/register", function(req, res) {
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if(err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function(req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err) {
        if(err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});


app.post("/submit", async function(req, res) {
    const submittedSecret = req.body.secret;
    
    try {
        const user = await User.findById(req.user.id);
        user.secret = submittedSecret;
        await user.save();
        res.redirect("/secrets");

    }catch(err) {
        console.log(err);
    }
})
app.listen(3000, function() {
    console.log("Server started on port 3000");
});
