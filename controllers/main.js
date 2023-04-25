const { BadRequest } = require("../errors");
const jwt = require("jsonwebtoken");

const login = async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    throw new BadRequest("Please provide email and password");
  }
  const id = new Date().getDate();
  const token = jwt.sign({ id, username }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });

  res.status(200).json({ msg: "fake login", token });
};

const dashboard = async (req, res) => {
  console.log(req.user);
  res.status(200).json({ msg: `Hello, user: ${req.user.username}` });
};

module.exports = {
  login,
  dashboard,
};
