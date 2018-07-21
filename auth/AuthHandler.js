const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs-then");
const connectToDatabase = require("../db");
const User = require("../user/User");

module.exports.register = (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  return connectToDatabase()
    .then(() => register(JSON.parse(event.body)))
    .then(session => ({
      statusCode: 200,
      body: JSON.stringify(session)
    }))
    .catch(err => ({
      statusCode: err.statusCode || 500,
      header: { "Content-Type": "text/plain" },
      body: err.message
    }));
};

module.exports.login = (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  return connectToDatabase()
    .then(() => login(JSON.parse(event.body)))
    .then(session => ({
      statusCode: 200,
      body: JSON.stringify(session)
    }))
    .catch(err => ({
      statusCode: err.statusCode || 500,
      header: { "Content-Type": "text/plain" },
      body: err.message
    }));
};

module.exports.me = (event, context) => {
  context.callbackWaitsForEmptyEventLoop = false;

  return connectToDatabase()
    .then(() => me(JSON.parse(event.requestContext.authorizer.principalId))) // the decoded.id from the VerifyToken.auth will be passed along as the principalId under the authorizer
    .then(session => ({
      statusCode: 200,
      body: JSON.stringify(session)
    }))
    .catch(err => ({
      statusCode: err.statusCode || 500,
      header: { "Content-Type": "text/plain" },
      body: { stack: err.stack, message: err.message }
    }));
};

// Helper function

function signToken(id) {
  return jwt.sign({ id: id }, process.env.JWT_SECRET, {
    expiresIn: 86400 // expires in 24 hours
  });
}

function register(eventBody) {
  return User.findOne({ email: eventBody.email }) // check it if user exists
    .then(
      user =>
        user
          ? Promise.reject(new Error("User with that email exists."))
          : bcrypt.hash(eventBody.password)
    )
    .then(
      hash =>
        User.create({
          name: eventBody.name,
          email: eventBody.email,
          password: hash
        }) // create the new user
    )
    .then(user => ({ auth: true, token: signToken(user._id) })); // sign the token and send it back
}

function login(eventBody) {
  return User.findOne({ email: eventBody.email })
    .then(
      user =>
        !user
          ? Promise.reject(new Error("User with that email does not exists."))
          : comaparePassword(eventBody.password, user.password, user._id)
    )
    .then(token => ({ auth: true, token: token }));
}

function comaparePassword(eventPassword, userPassword, userId) {
  return bcrypt
    .compare(eventPassword, userPassword)
    .then(
      passwordValid =>
        !passwordValid
          ? Promise.reject(new Error("The credentials do not match."))
          : signToken(userId)
    );
}

function me(userId) {
  return User.findById(userId, { password: 0 })
    .then(user => (!user ? Promise.reject(new Error("No user found.")) : user))
    .catch(err => Promise.reject(new Error(err)));
}
