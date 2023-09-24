import express from "express";
import { create } from "express-handlebars";
import mongoose from "mongoose";
import * as dotenv from "dotenv";
import cookieParser from "cookie-parser";
import flash from "connect-flash";
import session from "express-session";
import hbsHelper from "./utils/index.js";

import varMiddleware from "./middleware/var.js";
import userMiddleware from "./middleware/user.js";

// ROUTES
import AuthRoutes from "./routes/auth.js";
import ProductsRoutes from "./routes/products.js";
dotenv.config();

const app = express();

const hbs = create({
  defaultLayout: "main",
  extname: "hbs",
  helpers: hbsHelper,
});
app.use(express.static("public"));
app.engine("hbs", hbs.engine);
app.set("view engine", "hbs");
app.set("views", "./views");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(session({ secret: "Webdev", resave: false, saveUninitialized: false }));
app.use(flash());
app.use(varMiddleware);
app.use(userMiddleware);

app.use(AuthRoutes);
app.use(ProductsRoutes);

const startApp = () => {
  try {
    mongoose.set("strictQuery", false);
    mongoose
      .connect(process.env.MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      })
      .then(() => {
        console.log("Mongo DB connected");
      })
      .catch((error) => {
        console.error("MongoDB ga ulanishda xato:", error);
      });
    const PORT = process.env.PORT || 4100;
    app.listen(PORT, () => console.log(`Server is running: ${PORT}`));
  } catch (error) {
    console.log(error);
  }
};

startApp();
