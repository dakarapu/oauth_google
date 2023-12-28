import https from 'node:https';
import fs from 'node:fs';
import express from 'express';
import helmet from 'helmet';
import dotenv from 'dotenv';
import passport from 'passport';
import { Strategy } from 'passport-google-oauth20';
import cookieSession from 'cookie-session';

dotenv.config();

const app = express();

app.use(helmet());

passport.use(
  new Strategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: '/auth/google/callback',
    },
    verifyAuthCallback
  )
);

function verifyAuthCallback(accessToken, refreshToken, profile, done) {
  console.log(`Profile:${JSON.stringify(profile, null, 4)}`);
  console.log(`Access Token: ${accessToken}`);
  done(null, profile);
}

function checkAuthentication(req, res, next) {
  const isAuthenticated = req.isAuthenticated() && req.user;
  console.log(`isAuthenticated: ${isAuthenticated}`);
  if (!isAuthenticated) {
    return res.status(401).json({
      error: `You must login!`,
    });
  }
  next();
}

passport.serializeUser((user, done) => {
  //console.log(`Serialized user: ${JSON.stringify(user)}`);
  done(null, user.id); // only passing userID into deserialize user
});

passport.deserializeUser((userId, done) => {
  //console.log(`Deserialized user: ${JSON.stringify(user)}`);
  done(null, userId);
});

app.use(
  cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [process.env.COOKIE_KEY, process.env.COOKIE_ROTATION_KEY],
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
  res.send(`This is home page. Please login with your Google ID.`);
});

app.get('/user', checkAuthentication, (req, res) => {
  console.log(`User endpoint reached....`);
  return res.send(`You are now authenticated with Oauth2.0`);
});

app.get('/login/failed', (req, res) => {
  return res.send(`You authentication failed with Google`);
});

app.get('/logout', (req, res) => {
  req.logOut();
  return res.redirect(`/`);
});

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['email'],
  })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/login/failed',
    successRedirect: '/user',
    session: true,
  }),
  (req, res) => {
    console.log(`Successfully authenticated with Google-OAuth`);
  }
);

https
  .createServer(
    {
      cert: fs.readFileSync('cert.pem'),
      key: fs.readFileSync('key.pem'),
    },
    app
  )
  .listen(process.env.PORT, () => {
    console.log(`App listening on port ${process.env.PORT}..`);
  });
