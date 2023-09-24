import { Router } from "express";
import User from "../models/User.js";
import bcrypt from "bcrypt";
import { generateJWTToken } from "../service/token.js";
import loginMiddleware from "../middleware/login.js";

const router = Router();

router.get("/login", loginMiddleware, (req, res) => {
  res.render("login", {
    title: "Login | WebDev",
    isLogin: true,
    loginError: req.flash("loginError"),
  });
});

router.get("/register", loginMiddleware, (req, res) => {
  res.render("register", {
    title: "Register | WebDev",
    isRegister: true,
    registerError: req.flash("registerError"),
  });
});

router.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    req.flash("loginError", "All fields is required");
    res.redirect("/login");
    return;
  }

  const existUser = await User.findOne({ email });
  if (!existUser) {
    console.log("User not found");
    req.flash("loginError", "User not found");
    res.redirect("/login");
    return;
  }

  const isPassEqual = await bcrypt.compare(password, existUser.password);
  if (!isPassEqual) {
    console.log("Password wrong");
    req.flash("loginError", "Password wrong");
    res.redirect("/login");
    return;
  }

  const token = generateJWTToken(existUser._id);
  res.cookie("token", token, { httpOnly: true, secure: true });

  res.redirect("/");
});

router.post("/register", async (req, res) => {
  const { firstname, lastname, email, password } = req.body;

  if (!firstname || !lastname || !email || !password) {
    req.flash("registerError", "All fields is required");
    res.redirect("/register");
    return;
  }

  const candidate = await User.findOne({ email });
  if (candidate) {
    req.flash("registerError", "User already exist");
    res.redirect("/register");
    return;
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const userData = {
    firstName: firstname,
    lastName: lastname,
    email,
    password: hashedPassword,
  };

  const user = await User.create(userData);
  const token = generateJWTToken(user._id);
  res.cookie("token", token, { httpOnly: true, secure: true });
  res.redirect("/");
});

export default router;
