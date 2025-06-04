const express = require("express");
const app = express();
const mongose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { default: mongoose } = require("mongoose");

require("dotenv").config();
const URI = process.env.MONGODB_URI;
mongoose.Promise = global.Promise;
mongoose.set("strictQuery", false);
mongose
	.connect(URI)
	.then(console.log("Connected to database"))
	.catch((err) => console.log(err));

app.use(express.json());

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
	console.log("Server is running on http://localhost:3000");
});

const tokenSecret = process.env.TOKEN_SECRET;

app.get("/", (req, res) => {
	res.send(
		`
      <!DOCTYPE html>
<html lang="en">
   <head>
      <title>Document</title>
   </head>
   <body style="height: 100%; background-color: #161622">
      <div style="display: flex; justify-content: center; align-items: center">
         <h1 style="font-weight: bold; font-size: large; color: #ff5757">
            Welcome to Aquaflow Server
         </h1>
      </div>
   </body>
</html>
`
	);
});

require("./models/userModel");
const user = mongose.model("User");

function generateAccessToken(id) {
	return jwt.sign(id, tokenSecret, { expiresIn: "43200s" });
}

async function authenticateToken(req, res, next) {
	const authHeader = req.headers["authorization"];
	const token = authHeader && authHeader.split(" ")[1];
	if (token == null) return res.status(401).json({ message: "Unauthorized" });

	jwt.verify(token, tokenSecret, (err, user) => {
		if (err)
			return res.status(403).json({ message: "Token expired", data: err });
		req.user = user;
		next();
	});
}

app.post("/api/authentication", authenticateToken, async (req, res) => {
	const userExists = await user.findOne({ _id: req.user.id });
	const data = {
		id: userExists._id,
		name: userExists.name,
		email: userExists.email,
	};

	if (userExists) {
		return res.status(200).json({ message: "Authenticated", user: data });
	}
	return res.status(400).json({ message: "User does not exist" });
});

app.get("/api/auth/logout", async (res) => {
	return res.status(200).json({ message: "Logged out successfully" });
});

app.post("/api/auth/login", async (req, res) => {
	const { email, password } = req.body;

	if (!email || !password) {
		return res.status(400).json({ message: "All fields are required" });
	}
	const userExists = await user.findOne({ email });

	if (userExists) {
		const isPasswordCorrect = await bcrypt.compare(
			password,
			userExists.password
		);
		const token = generateAccessToken({
			id: userExists._id,
		});
		if (isPasswordCorrect) {
			return res.status(200).json({ message: "Login successful", token });
		} else {
			return res.status(400).json({ message: "Invalid email or password" });
		}
	}

	return res.status(400).json({ message: "User does not exist" });
});

app.post("/api/auth/register", async (req, res) => {
	const { name, email, password } = req.body;

	const userExists = await user.findOne({ email });
	if (userExists) {
		return res.status(400).json({ message: "Email already taken" });
	}

	if (!name || !email || !password) {
		return res.status(400).json({ message: "All fields are required" });
	}

	const validEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+[.com]$/;
	if (!email.match(validEmail)) {
		return res.status(400).json({ message: "Invalid email" });
	}

	if (password.length <= 7) {
		return res
			.status(400)
			.json({ message: "Password must be at least 8 characters" });
	}

	const encryptedPassword = await bcrypt.hash(password, 10);

	try {
		await user.create({
			name: name,
			email: email,
			password: encryptedPassword,
		});
		return res.status(201).json({ message: "User created successfully" });
	} catch (error) {
		return res.status(500).json({ message: "Internal server error" });
	}
});
