# JSON web token helper

A helper that aims to easily manage multiple secrets for your tokens.

## Installation

### NPM

```
npm install --save jsonwebtoken-helper
```

### Yarn

```
yarn add jsonwebtoken-helper
```

## Dependencies

- **jsonwebtoken**: https://github.com/auth0/node-jsonwebtoken

## How to use?

### Import the helper

```javascript
const jwtHelper = require('jsonwebtoken-helper').default;
```

or with ES6

```javascript
import jwtHelper from 'jsonwebtoken-helper';
```

### Sign a payload

```javascript
const payload = {
  name: 'John Doe'
};

const text = jwtHelper.sign(payload);
```

### Verify your token

```javascript
const text = jwtHelper.verify(token);
```

## Customization

To customize the library, you need to use environement variables.

The **bold value** are mandatary.

- **JWT_SECRET_SEPARATOR**

The separator used to split the secrets and corresponding key ids.

Example

    JWT_SECRET_SEPARATOR='######'

- **JWT_SECRET_TOKEN**

The list of secrets.

Example

    JWT_SECRET_TOKEN='oldsecret######ceciestuntest######asupersecret'

- **JWT_KEY_IDS**

The list of the corresponding key ids.

Example

    JWT_KEY_IDS='######keyidxyz######fjkal79r879sdf'

- **JWT_ISSUER**

The issuer that will provide the token.

Example

    JWT_ISSUER='JohnDoeCorp'

- JWT_DEFAULT_EXPIRES

The default expire value for the token. If you don't provide it. The token will don't have a default expire value and never expire if you give anything.

  Eg: 60, "2 days", "10h", "7d". A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default ("120" is equal to "120ms").

Example

    JWT_DEFAULT_EXPIRES=60

## Author

Guillaume Quittet

[https://www.linkedin.com/in/gquittet/](https://www.linkedin.com/in/gquittet/)

## Give me a coffee ☕

[https://paypal.me/gquittet](https://paypal.me/gquittet)
