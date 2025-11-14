// backend/index.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require("./config/mongodb");
const authRouter = require('./routes/authRoutes');
const userRouter = require('./routes/userRoutes');

connectDB();
const app = express();
const PORT = process.env.PORT || 5000;


// Middleware
app.use(cors({credentials: true}));
app.use(express.json()); // To parse JSON request bodies


// Define your routes and API endpoints here
app.get('/', (req, res) => {
  res.send('MERN Backend is running!');
});
app.use('/api/auth', authRouter)
app.use('/api/user', userRouter)

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});