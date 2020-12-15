const scmp = require('scmp');

const pbkdf2 = require('./pbkdf2');
const errors = require('./errors');

module.exports = function(user, password, options, cb) {
  // the implementation in the schema means this callback is never called now
  if (cb) {
    return authenticate(user, password, options, cb);
  }

  return new Promise((resolve, reject) => {
    authenticate(user, password, options, (err, user, error) => (err ? reject(err) : resolve({ user, error })));
  });
};

async function authenticate(user, password, options, cb) {
  if (!user.get(options.saltField)) {
    return cb(null, false, new errors.NoSaltValueStoredError(options.errorMessages.NoSaltValueStoredError));
  }

  try {
    if (options.limitAttempts) {
      if (user.get(options.attemptsField) >= options.maxAttempts) {
        return cb(null, false, new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError));
      }

      // Check how recently login was attempted
      const attemptsInterval = Math.pow(options.interval, Math.log(user.get(options.attemptsField) + 1));
      const calculatedInterval = attemptsInterval < options.maxInterval ? attemptsInterval : options.maxInterval;

      if (Date.now() - user.get(options.lastLoginField) < calculatedInterval) {
        user.set(options.lastLoginField, Date.now());
        await user.save();
        return cb(null, false, new errors.AttemptTooSoonError(options.errorMessages.AttemptTooSoonError));
      }
    }

    const hashBuffer = await pbkdf2Promisified(password, user.get(options.saltField), options);
    if (scmp(hashBuffer, Buffer.from(user.get(options.hashField), options.encoding))) {
      // Password matches
      if (options.limitAttempts) {
        user.set(options.lastLoginField, Date.now());
        await user.resetAttempts();
      }
      return cb(null, user);
    }

    // Password does not match
    if (options.limitAttempts) {
      user.set(options.lastLoginField, Date.now());
      user.set(options.attemptsField, user.get(options.attemptsField) + 1);
      await user.save();

      if (user.get(options.attemptsField) >= options.maxAttempts) {
        return cb(null, false, new errors.TooManyAttemptsError(options.errorMessages.TooManyAttemptsError));
      }
    }
    cb(null, false, new errors.IncorrectPasswordError(options.errorMessages.IncorrectPasswordError));
  } catch (mongoError) {
    cb(mongoError);
  }
}

function pbkdf2Promisified(password, salt, options) {
  return new Promise((resolve, reject) => pbkdf2(password, salt, options, (err, hashRaw) => (err ? reject(err) : resolve(hashRaw))));
}
