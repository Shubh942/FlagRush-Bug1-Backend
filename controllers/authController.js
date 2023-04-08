const dotenv = require("dotenv");
const catchAsync = require("./../utils/catchAsync");
const Shivkant = require("./../models/userModel");
const jwt = require("jsonwebtoken");
const AppError = require("./../utils/appError");

dotenv.config();

const signToken = (id) => {
  return jwt.sign({ id }, process.env.SECRET_KEY, {
    expiresIn: process.env.EXPIRES,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + Number(process.env.EXPIRES_IN) * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  res.cookie("jwt", token, cookieOptions);

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await Shivkant.create(req.body);
  // console.log(newUser);
  const url = `${req.protocol}://${req.get("host")}/me`;

  res.json({
    status: "success",
    data: newUser,
  });
});

exports.login = catchAsync(async (req, res, next) => {
  // console.log(req.body)
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError("Please provide email and password", 400));
  }

  const user = await Shivkant.findOne({ email }).select("+password");

  if (!user) {
    return next(new AppError("Invalid email or password", 401));
  }

  const correct = await user.correctPassword(password, user.password);

  if (!correct) {
    return next(new AppError("Invalid email or password", 401));
  }
  createSendToken(user, 200, res);
});

exports.logout = (req, res) => {
  res.cookie("jwt", "loggedout", {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  res.status(200).json({ status: "success" });
};

exports.protect = catchAsync(async (req, res, next) => {
  let token;
  //Checking if it contain token or not
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }
  // console.log(token);
  if (!token) {
    return next(new AppError("You are not logged in! Please login first", 401));
  }

  const decoded = jwt.verify(token, process.env.SECRET_KEY);
  // console.log(decoded);

  const freshUser = await Shivkant.findById(decoded.id);
  if (!freshUser) {
    return next(
      new AppError(
        "Shivkant belonging to this token does no longer exists",
        401
      )
    );
  }

  req.user = freshUser;

  next();
});

exports.isLoggedIn = async (req, res, next) => {
  if (req.cookies.jwt) {
    try {
      const decoded = await jwt.verify(req.cookies.jwt, "mysecretkey");

      const currentUser = await Shivkant.findById(decoded.id);
      if (!currentUser) {
        return next();
      }

      res.locals.user = currentUser;
      return next();
    } catch (err) {
      return next();
    }
  }
  next();
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // console.log(req.user);
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError("You do not permission to perform this action", 403)
      );
    }
    next();
  };
};
