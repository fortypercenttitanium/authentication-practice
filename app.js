require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');
const flash = require('connect-flash');

const mongoDb = process.env.MONGODB_URL;

mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'mongo connection error'));

const User = mongoose.model(
	'User',
	new Schema({
		username: { type: String, require: true },
		password: { type: String, require: true },
	})
);

// set up view engine
const app = express();
app.set('views', __dirname);
app.set('view engine', 'ejs');

// set up session
app.use(session({ secret: 'cats', resave: false, saveUninitialized: true }));

// set up passport
passport.use(
	new LocalStrategy((username, password, done) => {
		User.findOne(
			{
				username,
			},
			(err, user) => {
				if (err) {
					return done(err);
				}
				if (!user) {
					return done(null, false, { msg: 'Incorrect username' });
				}
				bcrypt.compare(password, user.password, (err, res) => {
					if (err) {
						return next(err);
					}
					if (res) {
						return done(null, user);
					} else {
						return done(null, false, { msg: 'Incorrect password' });
					}
				});
			}
		);
	})
);

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.findById(id, function (err, user) {
		done(err, user);
	});
});

app.use(flash());

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
	res.locals.currentUser = req.user;
	next();
});

app.get('/', (req, res) => {
	const errors = req.flash().error;
	res.render('index', { user: req.user, errors });
});
app.get('/sign-up', (req, res) => res.render('sign-up-form'));

app.post('/sign-up', (req, res, next) => {
	const { username, password } = req.body;
	bcrypt.hash(password, 10, (err, hashedPass) => {
		if (err) {
			return next(err);
		}
		const user = new User({
			username,
			password: hashedPass,
		}).save((err) => {
			if (err) {
				return next(err);
			} else {
				res.redirect('/');
			}
		});
	});
});

app.post(
	'/log-in',
	passport.authenticate('local', {
		successRedirect: '/',
		failureRedirect: '/',
		failureFlash: 'Authentication failed',
	})
);

app.get('/log-out', (req, res, next) => {
	req.logout();
	res.redirect('/');
});

app.listen(3000, () => console.log('Server started on port 3000!'));
