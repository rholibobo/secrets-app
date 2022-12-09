require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocal = require("passport-local");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const bodyParser = require('body-parser');

const app = express();
const saltRounds = 10;

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended:true}));

app.use(
  session({
    secret: "our secret to greatness",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// SCHEMA
mongoose.connect(process.env.MONGODB_URL || "mongodb://0.0.0.0:27017/user_authDB");
mongoose.connection
  .once("open", () => console.log("Connected"))
  .on("error", (err) => console.log(err));

  // Secrets Schema
  const userSecretSM = new mongoose.Schema({
    secret: String
  }, {timestamps: true})

//   UserSchema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  facebookId: String,
  name: String,
  secrets: [userSecretSM],
});

// Use Plugin to salt passwords
userSchema.plugin(passportLocalMongoose);

// Plugin for mongoose findOrCreate
userSchema.plugin(findOrCreate);

// Create user model
const Users = mongoose.model("Users", userSchema);

// Create passport Strategy
passport.use(Users.createStrategy());

// Serialize passport
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  })
//  Deserialize passport
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});

// // Serialize
// passport.serializeUser(Users.serializeUser());

// // Deserialize
// passport.deserializeUser(Users.deserializeUser());


// Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRETS,
      callbackURL: "http://localhost:3050/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      Users.findOrCreate({ googleId: profile.id, name: profile.displayName }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

// Facebook OAuth
passport.use(
  new FacebookStrategy(
    {
  clientID: process.env.FACEBOOK_CLIENT_ID,
  clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
  callbackURL: "http://localhost:3050/auth/facebook/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  Users.findOrCreate({ facebookId: profile.id , name: profile.displayName}, function (err, user) {
    // console.log(profile)
    return cb(err, user);
  });
}
));

// EXPRESS METHODS
// google auth
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

// facebook auth
app.get('/auth/facebook',
  passport.authenticate('facebook'));

// homepage
app.get("/", (req, res) => {
  res.render("home");
});

// google oauth callback
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secret page.
    res.redirect("/secrets");
  }
);

// facebook oauth callback
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});



app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  Users.register(
    { username: req.body.username },
    req.body.password,
    (err, result) => {
      if (err) {
        console.log(err);
        res.render("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.get("/login", (req, res) => {
  res.render("login", { response: "great" });
});

app.post("/login", (req, res) => {
  const newUser = new Users({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(newUser, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/secrets", (req, res)=>{
  // console.log(req.user);
  if(req.isAuthenticated()){
    Users.findOne({_id: req.user.id}, function(err, result){
      res.render("secrets", {secrets: result.secrets})
      // console.log(result);
    })
  }else{
    res.redirect("/login");
  }
})


app.get("/submit", (req, res)=>{
  if(req.isAuthenticated()){
  res.render("submit");
  }else{
    res.redirect("/login");
  }
})

app.post("/submit", (req, res)=>{
  
 if(req.isAuthenticated()){
  Users.findOne({_id: req.user.id}, function(err, result){
    result.secrets.push(req.body);
    result.save();
    res.redirect("/secrets")
  })
 }else{
  res.redirect("/login");
 }
})

// Edit route
app.get("/edit", (req, res)=>{
  if(req.isAuthenticated()){
      Users.findOne({_id: req.user.id}, function(err, respo){
        res.render("edit", {edits: respo.secrets})
        // console.log(result);
      })
  }
})
 
app.post("/edit", (req, res)=>{
  if(req.isAuthenticated()) {
    Users.findOneAndUpdate({_id: req.user.id, "secrets._id": req.body.deletebtn}, {$set: {"secrets.$.secret": req.body.edit}},  (err, done)=>{
      console.log(req.body.edit)
      console.log(req.body.deletebtn)
      if(!err){
        res.redirect("/secrets")
      }else {
        console.log(err)
      }
    })
  }
})


// Delete Route
app.post("/delete", (req, res)=>{
 
  if(req.isAuthenticated()) {
   
      Users.findOneAndUpdate({_id: req.user.id}, {$pull: {secrets : {_id: req.body.delete}}}, (err, gone)=>{

        if(!err){
          res.redirect("/secrets")
        }else {
          console.log(err)
        }
      })
      
      
    
  }
 
})





app.get("/logout", (req, res) => {
  req.logout((err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});

app.listen(3050, () => console.log("App running at port 3050"));
