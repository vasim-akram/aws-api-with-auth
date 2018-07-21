const jwt = require("jsonwebtoken");

// Policy helper function
const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.version = '2012-10-17';
    policyDocument.statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
};

module.exports.auth = (event, context, callback) => {
  // check header or url parameter or post parameter for token
  const token = event.authorizationToken;
  if (!token) return callback(null, "Unauthorized");
  // verifies secret and check exp
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return callback(null, "Unauthorized");
    // if everything good, save to request for use in other routes
    return callback(null, generatePolicy(decoded.id, "Allow", event.methodArn));
  });
};
