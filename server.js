const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const app = express();

// MongoDB Connection (Replace with Atlas URI later)
mongoose
	.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/memoryWall')
	.then(() => console.log('Connected to MongoDB'))
	.catch((err) => console.error('MongoDB error:', err));

// Middleware & EJS Setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Image Upload Setup (Multer)
const storage = multer.diskStorage({
	destination: (req, file, cb) => cb(null, 'public/uploads/'),
	filename: (req, file, cb) =>
		cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// Database Model
const Post = mongoose.model('Post', {
	text: String,
	image: String,
	createdAt: { type: Date, default: Date.now },
});

// Routes
app.get('/', async (req, res) => {
	const posts = await Post.find().sort({ createdAt: -1 });
	res.render('index', { posts });
});

app.post('/post', upload.single('image'), async (req, res) => {
	const newPost = new Post({
		text: req.body.text,
		image: req.file ? `/uploads/${req.file.filename}` : null,
	});
	await newPost.save();
	res.redirect('/');
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
	console.log(`Server running on http://localhost:${PORT}`)
);
