require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const fs = require('fs');
const flash = require('connect-flash');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// MongoDB Connection
mongoose
	.connect(
		process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/memoryWall',
		{
			useNewUrlParser: true,
			useUnifiedTopology: true,
		}
	)
	.then(() => console.log('Connected to MongoDB'))
	.catch((err) => console.error('MongoDB connection error:', err));

// Models
const Post = mongoose.model(
	'Post',
	new mongoose.Schema({
		text: { type: String, required: true, trim: true },
		media: [String],
		createdAt: { type: Date, default: Date.now },
		user: {
			type: mongoose.Schema.Types.ObjectId,
			ref: 'User',
			required: true,
		},
	})
);

const User = mongoose.model(
	'User',
	new mongoose.Schema({
		username: { type: String, unique: true, required: true, trim: true },
		password: { type: String, required: true },
	})
);

// Middleware & EJS Setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(
	express.static('public', {
		maxAge: '1d',
	})
);

// Session setup
app.use(
	session({
		secret: process.env.SESSION_SECRET || 'your-secret-key',
		resave: false,
		saveUninitialized: false,
		cookie: {
			secure: process.env.NODE_ENV === 'production',
			httpOnly: true,
			maxAge: 24 * 60 * 60 * 1000, // 1 day
		},
	})
);

// Flash messages
app.use(flash());

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Passport Configuration
passport.use(
	new LocalStrategy(async (username, password, done) => {
		try {
			const user = await User.findOne({ username });
			if (!user) {
				return done(null, false, { message: 'Incorrect username.' });
			}

			const isMatch = await bcrypt.compare(password, user.password);
			if (!isMatch) {
				return done(null, false, { message: 'Incorrect password.' });
			}

			return done(null, user);
		} catch (err) {
			return done(err);
		}
	})
);

passport.serializeUser((user, done) => {
	done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
	try {
		const user = await User.findById(id);
		done(null, user);
	} catch (err) {
		done(err);
	}
});

// File Upload Setup
const storage = multer.diskStorage({
	destination: (req, file, cb) => {
		const dir = 'public/uploads/';
		if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
		cb(null, dir);
	},
	filename: (req, file, cb) => {
		const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
		cb(null, uniqueSuffix + path.extname(file.originalname));
	},
});

const fileFilter = (req, file, cb) => {
	const filetypes = /jpeg|jpg|png|gif|mp4|mov|avi|webm/;
	const mimetype = filetypes.test(file.mimetype);
	const extname = filetypes.test(
		path.extname(file.originalname).toLowerCase()
	);

	if (mimetype && extname) {
		return cb(null, true);
	}
	cb(new Error('Error: Only images and videos are allowed!'));
};

const upload = multer({
	storage,
	fileFilter,
	limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
});

// Middleware
function isLoggedIn(req, res, next) {
	if (req.isAuthenticated()) return next();
	req.flash('error', 'Please login first');
	res.redirect('/login');
}

// Routes
app.get('/', isLoggedIn, async (req, res) => {
	try {
		const posts = await Post.find()
			.populate('user', 'username')
			.sort({ createdAt: -1 });
		res.render('index', {
			posts,
			user: req.user,
			messages: {
				success: req.flash('success'),
				error: req.flash('error'),
			},
		});
	} catch (err) {
		console.error('Error loading posts:', err);
		req.flash('error', 'Error loading posts');
		res.redirect('/');
	}
});

app.post('/post', isLoggedIn, upload.array('media', 10), async (req, res) => {
	try {
		if (!req.body.text || req.body.text.trim() === '') {
			req.flash('error', 'Post text cannot be empty');
			return res.redirect('/');
		}

		const media =
			req.files?.map((file) => `/uploads/${file.filename}`) || [];
		const newPost = new Post({
			text: req.body.text.trim(),
			media,
			user: req.user._id,
		});
		await newPost.save();
		req.flash('success', 'Post created successfully');
		res.redirect('/');
	} catch (err) {
		console.error('Error creating post:', err);
		req.flash('error', 'Error creating post');
		res.redirect('/');
	}
});

app.get('/login', (req, res) => {
	if (req.isAuthenticated()) return res.redirect('/');
	res.render('login', {
		messages: {
			error: req.flash('error'),
			success: req.flash('success'),
		},
	});
});

app.post(
	'/login',
	passport.authenticate('local', {
		failureRedirect: '/login',
		failureFlash: true,
	}),
	(req, res) => {
		req.flash('success', 'Successfully logged in');
		res.redirect('/');
	}
);

app.get('/register', (req, res) => {
	if (req.isAuthenticated()) return res.redirect('/');
	res.render('register', {
		messages: {
			error: req.flash('error'),
			success: req.flash('success'),
		},
	});
});

app.post('/register', async (req, res) => {
	try {
		const { username, password } = req.body;

		if (!username || !password) {
			req.flash('error', 'Username and password are required');
			return res.redirect('/register');
		}

		if (password.length < 6) {
			req.flash('error', 'Password must be at least 6 characters');
			return res.redirect('/register');
		}

		const existingUser = await User.findOne({ username });
		if (existingUser) {
			req.flash('error', 'Username already exists');
			return res.redirect('/register');
		}

		const hashedPassword = await bcrypt.hash(password, 10);
		const newUser = new User({
			username,
			password: hashedPassword,
		});
		await newUser.save();

		req.flash('success', 'Registration successful! Please login');
		res.redirect('/login');
	} catch (err) {
		console.error('Registration error:', err);
		req.flash('error', 'Registration failed');
		res.redirect('/register');
	}
});

app.get('/logout', (req, res) => {
	req.logout((err) => {
		if (err) {
			console.error('Logout error:', err);
			req.flash('error', 'Error logging out');
			return res.redirect('/');
		}
		req.flash('success', 'Successfully logged out');
		res.redirect('/login');
	});
});

app.get('/edit/:id', isLoggedIn, async (req, res) => {
	try {
		const post = await Post.findOne({
			_id: req.params.id,
			user: req.user._id,
		});

		if (!post) {
			req.flash('error', 'Post not found or you dont have permission');
			return res.redirect('/');
		}

		res.render('edit', { post });
	} catch (err) {
		console.error('Error finding post:', err);
		req.flash('error', 'Error loading post');
		res.redirect('/');
	}
});

app.post(
	'/edit/:id',
	isLoggedIn,
	upload.array('media', 10),
	async (req, res) => {
		try {
			const post = await Post.findOne({
				_id: req.params.id,
				user: req.user._id,
			});

			if (!post) {
				req.flash(
					'error',
					'Post not found or you dont have permission'
				);
				return res.redirect('/');
			}

			post.text = req.body.text.trim();

			if (req.files && req.files.length > 0) {
				// Remove old media files
				post.media.forEach((file) => {
					const filePath = path.join(__dirname, 'public', file);
					if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
				});

				// Add new media files
				post.media = req.files.map(
					(file) => `/uploads/${file.filename}`
				);
			}

			await post.save();
			req.flash('success', 'Post updated successfully');
			res.redirect('/');
		} catch (err) {
			console.error('Error updating post:', err);
			req.flash('error', 'Error updating post');
			res.redirect('/');
		}
	}
);

// Correct route (POST only)
app.post('/delete/:id', isLoggedIn, async (req, res) => {
	try {
		const post = await Post.findOneAndDelete({
			_id: req.params.id,
			user: req.user._id, // Ensure user owns the post
		});

		if (!post) {
			req.flash('error', 'Post not found or no permission');
			return res.redirect('/');
		}

		// Delete associated files (if any)
		post.media.forEach((file) => {
			const filePath = path.join(__dirname, 'public', file);
			if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
		});

		req.flash('success', 'Post deleted');
		res.redirect('/');
	} catch (err) {
		console.error('Delete error:', err);
		req.flash('error', 'Server error');
		res.redirect('/');
	}
});

// Error handling middleware
app.use((err, req, res, next) => {
	console.error(err.stack);
	req.flash('error', 'Something went wrong!');
	res.status(500).redirect('/');
});

// 404 handler
app.use((req, res) => {
	res.status(404).render('error', { message: 'Page not found' });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
	console.log(`Server running on http://localhost:${PORT}`);
	if (process.env.NODE_ENV !== 'production') {
		console.log('Development mode - not for production use');
	}
});
