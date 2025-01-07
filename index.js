import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import env from "dotenv";

const app = express();
const port = 3000;
const saltround = 10;
env.config();

app.use(session({
  secret: process.env.SECRET_MY,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 72,
    secure: false,               
    httpOnly: true
  },
}))

const db = new pg.Client({
  user: process.env.USER,
  host: process.env.HOST,
  database: process.env.DD,
  password: process.env.PP,
  port: process.env.PORT,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/new" , (req,res)=>{
  if(req.isAuthenticated()){
    res.render("add.ejs");
  }else{
    res.redirect("/");
  }
});

app.get("/logout", (req, res)=>{
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets" , async (req,res)=>{
  if(req.isAuthenticated()){
    
    const email = req.user[0].email;
    const secret = req.user[0].secret;
    // console.log(email +" "+ secret);
  
    if (!email) {
      return res.redirect("/login");
    }
  
    if (!secret || secret===null){
      return res.render("secrets.ejs",{
        secret : "Please Add Your Secret by Click on New Secret button  :)"
      });
    }
  
    const userx = await db.query("SELECT * FROM login WHERE email=$1",[email]);
    const sect = userx.rows[0].secret;
    // console.log(sect);

    res.render("secrets.ejs",{
      secret : sect,
    });
  }else{
    res.redirect("/");
  }
});

app.get("/submit" , async (req,res)=>{
  if(req.isAuthenticated()){
    const email = req.user[0].email;

    const data = await db.query("SELECT * FROM login WHERE email=$1",[email]);
    const secret = data.rows[0].secret;
    if(!secret){
      res.render("secrets.ejs", {
        secret : "Please Add Your Secret by Click on New Secret button  :)"
      });
    }else{
      res.render("secrets.ejs", {
        secret : secret
      });
    }
  }else{
    res.redirect("/");
  }
});

app.get("/auth/google" ,passport.authenticate("google",{
  scope: ["profile" , "email"],
}));

app.get("/auth/google/secrets" , passport.authenticate("google",{
  successRedirect : "/secrets",
  failureRedirect: "/"
}));

app.post("/login", passport.authenticate("local",{
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));

app.post("/submit" ,async(req,res) => {
  const secret = req.body.secret;
  const email =req.user[0].email;
  // console.log(secret + " " + email);

  await db.query("UPDATE login SET secret=$1 WHERE email=$2",[secret, email]);
  const userx = await db.query("SELECT * FROM login WHERE email=$1",[email]);
  const secretx = userx.rows[0].secret;
  req.session.secret = secretx ;
  res.redirect("/submit");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const pass = req.body.password;
  // console.log(email + " " + pass);

  const check = await db.query ("SELECT * FROM login WHERE email=$1",[email]);
  const checked = check.rows;
  // console.log(checked);

  if(checked.length>0){
    res.send("Email already exists. Try log in");
  }else{
    bcrypt.hash(pass , saltround , async (err,hash)=>{
      if(err){
        console.log("Error hashing password");
      }else{
        try{
          const ree = await db.query(
            "INSERT INTO login (email , password) VALUES ($1, $2) RETURNING *",
          [email , hash]);
          const user = ree.rows;
          // console.log(user);
          req.login(user ,(err) =>{
            if(err){
            console.log(err);
            res.redirect("/login");
            }else{
              res.redirect("/secrets")
            } 
          })
        }catch(err){
          console.log(err);
          res.status(500).send("An error occurred");
        }
      }
    })  
  }
});

passport.use("local",
  new Strategy (async function verify (username, password, cb){
  try{
    const checked = await db.query("SELECT * FROM login"); 
    const user = checked.rows;
    // console.log(username);
  
    const x = user.find((e) => e.email === username);
    // console.log(x.email + " " + x.password);

    if(x.email){
      bcrypt.compare(password, x.password , async (err,hash)=>{
        if(err){
          console.log("Error in hashing compare");
          return cb(err);
        }else{
          if(hash){
            const checker = await db.query("SELECT * FROM login WHERE email=$1",[x.email]); 
            const check = checker.rows;
            // console.log(check)
            return cb(null , check);
          }else{
            return cb("worng password");
          }
        }
      })
      return ;
    }
  }catch(err){
    return cb("User not found");
  }
}));

passport.use("google", 
  new GoogleStrategy ({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  },
  async (accessToken, refreshToken ,profile , cb) => {
    try{
      // console.log(profile.emails[0].value);
      // console.log(profile);
      const sec = await db.query("SELECT * FROM login WHERE email=$1",[profile.emails[0].value]);
      const secc = sec.rows ;
      if (secc.length === 0){
        await db.query("INSERT INTO login (email, password) VALUES ($1, $2)",[profile.emails[0].value , "google"]);
        const news = await db.query("SELECT * FROM login WHERE email=$1",[profile.emails[0].value]);
        const newuser = news.rows; 
        return cb (null , newuser);
      }else {
        return cb (null , secc);
      }
    }catch(err){
      return cb(err)
    }
  }
)
)

passport.serializeUser((user, cb)=>{
  cb(null , user);
});

passport.deserializeUser((user, cb)=>{
  cb(null , user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
