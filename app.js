//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { Pool } = require("pg");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

const pool = new Pool({
  user: "",
  host: "",
  database: "",
  password: "",
  port: 5432,
});

// Create user table (use async/await for better readability)
(async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255),
        password VARCHAR(255),
        googleId VARCHAR(255),
        secret VARCHAR(255)
      );
    `);
  } finally {
    client.release();
  }
})();

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async function (email, password, done) {
      try {
        const result = await pool.query(
          "SELECT * FROM users WHERE email = $1",
          [email]
        );
        const user = result.rows[0];
        if (!user || user.password !== password) {
          return done(null, false, { message: "Incorrect email or password." });
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = result.rows[0];
    done(null, user);
  } catch (err) {
    done(err);
  }
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:4000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async function (accessToken, refreshToken, profile, cb) {
      try {
        const result = await pool.query(
          "SELECT * FROM users WHERE googleId = $1",
          [profile.id]
        );
        const user = result.rows[0];
        if (!user) {
          // User doesn't exist, create a new user
          const newUserResult = await pool.query(
            "INSERT INTO users (googleId) VALUES ($1) RETURNING *",
            [profile.id]
          );
          const newUser = newUserResult.rows[0];
          return cb(null, newUser);
        } else {
          return cb(null, user);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// Routes

app.get("/", function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", async function (req, res) {
  try {
    // Assuming you have a 'secrets' table in your PostgreSQL database
    const query = `
      SELECT users.id, users.email, secrets.secret_text
      FROM users
      LEFT JOIN secrets ON users.id = secrets.user_id
      WHERE secrets.secret_text IS NOT NULL
    `;

    const result = await pool.query(query);
    const foundUsers = result.rows;
    res.render("secrets", { usersWithSecrets: foundUsers });
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;

  // Assuming you have a 'secrets' table in your PostgreSQL database
  const userId = req.user.id;

  // Insert a new secret for the user in the 'secrets' table
  const insertQuery = `
    INSERT INTO secrets (user_id, secret_text) VALUES ($1, $2) RETURNING *
  `;

  pool.query(insertQuery, [userId, submittedSecret], (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).send("Internal Server Error");
    } else {
      res.redirect("/secrets");
    }
  });
});

app.get("/logout", function (req, res) {
  req.logout();
  console.log("User logged out");
  res.redirect("/");
});

app.post("/register", async function (req, res) {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
      [email, password]
    );
    const newUser = result.rows[0];
    passport.authenticate("local")(req, res, function () {
      res.redirect("/secrets");
    });
  } catch (err) {
    console.error(err);
    res.redirect("/register");
  }
});

app.post("/login", async function (req, res) {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1 AND password = $2",
      [email, password]
    );
    const user = result.rows[0];
    if (user) {
      req.login(user, function (err) {
        if (err) {
          console.error(err);
          res.status(500).send("Internal Server Error");
        } else {
          res.redirect("/secrets");
        }
      });
    } else {
      res.redirect("/login");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

app.listen(4000, function () {
  console.log("Server started on port 4000.");
});
