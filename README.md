# OAuth 2.0 #

[![Build Status](https://api.travis-ci.org/electricimp/OAuth-2.0.svg?branch=master)](https://travis-ci.org/electricimp/OAuth-2.0)

This library provides OAuth 2.0 authentication and authorization flows. It supports the following flows:

- [OAuth2.JWTProfile.Client](#oauth2jwtprofileclient) &mdash; OAuth 2.0 with the JSON Web Token (JWT) Profile for Client Authentication and Authorization Grants as defined in [IETF RFC 7523](https://tools.ietf.org/html/rfc7523).
- [OAuth2.DeviceFlow.Client](#oauth2deviceflowclient) &mdash; OAuth 2.0 Device Flow for browserless and input-constrained devices. The implementation conforms to the [IETF draft device flow specification](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-05).

The library exposes retrieved access tokens for applications and hides provider-specific operations, including the renewal of expired tokens.

**To add this library to your project, add** `#require "OAuth2.agent.lib.nut:2.0.0"` **to the top of your agent code.**

**NOTE:** Please note the current OAuth library implementation uses the native platform [crypto](https://developer.electricimp.com/api/crypto) APIs, which are supported on developer devices’ agents only. Support for production deveices' agents is coming. If you need to test this feature in production, please contact Electric Imp [support](https://support.electricimp.com/access).

## OAuth2.JWTProfile.Client ##

This class implements an OAuth 2.0 client flow using a JSON Web Token (JWT) as the means for requesting access tokens and for client authentication.

## OAuth2.JWTProfile.Client Usage ##

### constructor(*providerSettings, userSettings*) ###

The constructor creates an instance of the *OAuth2.JWTProfile.Client* class. The first parameter, *providerSettings*, is a table that contains provider-specific settings:

| *providerSettings* Key | Type | Required | Description |
| --- | --- | --- | --- |
| *tokenHost* | String | Yes | The token endpoint. This is used by the client to exchange an authorization grant for an access token, typically with client authentication |

The second parameter, *userSettings*, defines a table with user- and application-specific settings:

| *userSettings* Key | Type | Required | Description |
| --- | --- | --- | --- |
| *iss* | String | Yes | The JWT issuer |
| *scope* | String | Yes | A scope. Scopes enable your application to request access only to the resources that it needs while also enabling users to control the amount of access that they grant to your application |
| *jwtSignKey* | String | Yes | A JWT sign secret key |
| *sub* | String | No | The subject of the JWT. Google seems to ignore this field (Default: the value of *iss*) |

#### JWT Profile Client Creation Example ####

```squirrel
// OAuth 2.0 library
#require "OAuth2.agent.lib.nut:2.0.0"

// Substitute with real values
const GOOGLE_ISS        = "rsalambda@quick-cacao-168121.iam.gserviceaccount.com";
const GOOGLE_SECRET_KEY = "-----BEGIN PRIVATE KEY-----\nprivate key goes here\n-----END PRIVATE KEY-----\n";

local providerSettings = { "tokenHost" : "https://www.googleapis.com/oauth2/v4/token" };

local userSettings = { "iss"        : GOOGLE_ISS,
                       "jwtSignKey" : GOOGLE_SECRET_KEY,
                       "scope"      : "https://www.googleapis.com/auth/pubsub" };

local client = OAuth2.JWTProfile.Client(providerSettings, userSettings);
```

## OAuth2.JWTProfile.Client Methods ##

### acquireAccessToken(*tokenReadyCallback*) ###

This method begins the access-token acquisition procedure. It invokes the provided callback function immediately if the access token is already available and valid.

#### Parameters ####

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| *tokenReadyCallback* | Function | Yes | Called when the token is ready for use |

The function passed into *tokenReadyCallback* should have two parameters of its own:

| Parameter | Type | Description |
| --- | --- | --- |
| *token* | String | The access token |
| *error* | String | Error details, or `null` in the case of success |

#### Return Value ####

Nothing.

#### Example ####

```squirrel
client.acquireAccessToken(
  // The token ready callback
  function(token, error) {
    if (error) {
      server.error(error);
    } else {
      server.log("The access token has the value: " + token);
    }
  }
);
```

### getValidAccessTokenOrNull() ###

This method provides an access token string in a non-blocking way. It returns `null` if the client is not authorized or the token has expired.

#### Return Value ####

String &mdash; the access token, or `null`.

#### Example ####

```squirrel
local token = client.getValidAccessTokenOrNull();

if (token) {
  server.log("The access token is valid and has the value: " + token);
} else {
  server.log("The access token has either expired or the client is not authorized");
}
```

### isTokenValid() ###

This method checks if the access token is valid by comparing its expiry time with current time. 

#### Return Value ####

Boolean &mdash; `true` if the token is valid, or `false` if the token has expired.

#### Example ####

```squirrel
server.log("The access token is " + (client.isTokenValid() ? "" : "in") + "valid");
```

### Complete Example ###

```squirrel
#require "OAuth2.agent.lib.nut:2.0.0

// Substitute with real values
const GOOGLE_ISS        = "rsalambda@quick-cacao-168121.iam.gserviceaccount.com";
const GOOGLE_SECRET_KEY = "-----BEGIN PRIVATE KEY-----\nprivate key goes here\n-----END PRIVATE KEY-----\n";

local providerSettings = { "tokenHost" : "https://www.googleapis.com/oauth2/v4/token"};

local userSettings = { "iss"        : GOOGLE_ISS,
                       "jwtSignKey" : GOOGLE_SECRET_KEY,
                       "scope"      : "https://www.googleapis.com/auth/pubsub" };

local client = OAuth2.JWTProfile.Client(providerSettings, userSettings);

local token = client.getValidAccessTokenOrNull();
if (token != null) {
  // We have a valid token already
  server.log("Valid access token is: " + token);
} else {
  // Acquire a new access token
  client.acquireAccessToken(
    function(newToken, err) {
      if (err) {
        server.error("Token acquisition error: " + err);
      } else {
        server.log("Received a new token: " + newToken);
      }
    }
  );
}
```

**Note** The JSON Web Token (JWT) Profile for OAuth 2.0 was verified and tested with the Google [PubSub](https://cloud.google.com/pubsub/docs/) authorization flow.

## OAuth2.DeviceFlow.Client ##

This class implements an OAuth 2.0 authorization flow for browserless and/or input-constrained devices. Often referred to as the [device flow](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-05), this flow enables OAuth clients to request user authorization from devices that have an Internet connection but lack a suitable input method or web browser required for a more traditional OAuth flow. This authorization flow therefore instructs the user to perform the authorization request on a secondary device, such as a smartphone.

## OAuth2.DeviceFlow.Client Usage ##

### constructor(*providerSettings, userSettings*) ###

This constructor creates an instance of the *OAuth2.DeviceFlow.Client* class. The first parameter, *providerSettings*, is a table that contains provider-specific settings:

| *providerSettings* Key | Type | Required | Description |
| --- | --- | --- | --- |
| *loginHost* | String | Yes | The authorization endpoint. This is used by the client to obtain authorization from the resource owner via user-agent redirection |
| *tokenHost* | String | Yes | The token endpoint. This is used by the client to exchange an authorization grant for an access token, typically with client authentication |
| *grantType* | String | No | The grant type identifier supported by the provider (Default: `"urn:ietf:params:oauth:grant-type:device_code"`) |

The second parameter, *userSettings*, takes a table containing user- and application-specific settings:

| *userSettings* Key | Type | Required | Description |
| --- | --- | --- | --- |
| *clientId* | String | Yes | The OAuth client ID |
| *clientSecret* | String | Yes | The project's client secret |
| *scope* | String | Yes | A scope. Scopes enable your application to only request access to the resources that it needs while also enabling users to control the amount of access that they grant to your application |

The library provides predefined configuration settings for the Google Device Auth flow. These settings are defined in the provider-specific settings map: *OAuth2.DeviceFlow.GOOGLE*. This table provides pre-populated *loginHost, tokenHost* and *grantType* values.

#### Device Flow Client Creation Example ####

```squirrel
local providerSettings = { "loginHost" : "https://accounts.google.com/o/oauth2/device/code",
                           "tokenHost" : "https://www.googleapis.com/oauth2/v4/token",
                           "grantType" : "http://oauth.net/grant_type/device/1.0" };

local userSettings = { "clientId"     : "<USER_FIREBASE_CLIENT_ID>",
                       "clientSecret" : "<USER_FIREBASE_CLIENT_SECRET>",
                       "scope"        : "email profile" };

client <- OAuth2.DeviceFlow.Client(providerSettings, userSettings);
```

## OAuth2.DeviceFlow.Client Methods ##

### acquireAccessToken(*tokenReadyCallback, notifyUserCallback, force*) ###

This method begins the access-token acquisition procedure. Depending on the client state, it may start a full client authorization procedure or just refresh a token that has already been acquired. The access token is delivered through the function passed into the *tokenReadyCallback* function.

#### Parameters ####

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| *tokenReadyCallback* | Function | Yes | The handler that will be called when the access token has been acquired, or an error has occurred. The function’s parameters are described below |
| *notifyUserCallback* | Function | Yes | The handler that will be called when user action is required. See [RFE, device flow, section 3.3](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-05#section-3.3) for information on what user action might be needed when this callback is executed. The function’s parameters are described below |
| *force* | Boolean | No | This flag forces the token acquisition process to start from the beginning even if a previous request has not yet completed. Any previous session will be terminated (Default: `false`) |

The *tokenReadyCallback* function should have the following parameters:

| Parameter | Type | Description |
| --- | --- | --- |
| *token* | String | String representation of the access token |
| *error* | String | Error details, or `null` in the case of success |

The *notifyUserCallback* function should have the following parameters:

| Parameter | Type | Description |
| --- | --- | --- |
| *url*  | String | The URL the user needs to use for client authorization |
| *code* | String | The code for the authorization server |

#### Return Value ####

String &mdash; `null` in the case of success, or an error message if the client is already performing a request and the *force* directive is set. 

#### Example ####

```squirrel
client.acquireAccessToken(
  // Token Ready Callback
  function(token, error) {
    if (error) {
      server.error("Token retrieval error: " + error);
    } else {
      server.log("The access token: " + token);
    }
  },
  // User notification callback
  function(url, code) {
    server.log("Authorization is pending. Please grant access");
    server.log("URL: " + url);
    server.log("Code: " + code);
  }
);
```

### getValidAccessTokenOrNull() ###

This method immediately returns either an existing access token if it is valid, or `null` if the token has expired or the client is yet not authorized.

#### Return Value ####

String &mdash; an existing valid access token, or `null`.

#### Example ####

```squirrel
local token = client.getValidAccessTokenOrNull();

if (token) {
  server.log("Token is valid: " + token);
} else {
  server.log("Token has expired or client is not authorized");
}
```

### isTokenValid() ###

This method checks if the current access token is valid.

#### Return Value ####

Boolean &mdash; `true` if the current access token is valid, otherwise `false`.

#### Example ####

```squirrel
server.log("The access token is " + (client.isTokenValid() ? "" : "in") + "valid");
```

### isAuthorized() ###

This method checks if the client is authorized and able to refresh an expired access token.

#### Return Value ####

Boolean &mdash; `true` if the client is authorized, otherwise `false`.

#### Example ####

```squirrel
server.log("The client is " + (client.isAuthorized() ?  "" : "un") + "authorized");
```

### refreshAccessToken(*tokenReadyCallback*) ###

This method asynchronously refreshes the access token and invokes the callback function when this has been completed or an error occurs. 

#### Parameters ####

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| *tokenReadyCallback* | Function | Yes | Called when the token is ready for use |

The function passed into *tokenReadyCallback* should have two parameters of its own:

| Parameter | Type | Description |
| --- | --- | --- |
| *token* | String | The access token |
| *error* | String | Error details, or `null` in the case of success |

#### Return Value ####

Nothing.

#### Example ####

```squirrel
client.refreshAccessToken(
  // Token Ready Callback
  function(token, error) {
    if (error) {
      server.error("Token refresh error: " + error);
    } else {
      server.log("The access token has been refreshed. It has the value: " + token);
    }
  }
);
```

### Complete Example ###

```squirrel
#require "OAuth2.agent.lib.nut:2.0.0

// Fill CLIENT_ID and CLIENT_SECRET with correct values
local userConfig = { "clientId"     : "<CLIENT_ID>",
                     "clientSecret" : "<CLIENT_SECRET>",
                     "scope"        : "email profile" };

// Initialize client with provided Google Firebase config
client <- OAuth2.DeviceFlow.Client(OAuth2.DeviceFlow.GOOGLE, userConfig);

local token = client.getValidAccessTokenOrNull();

if (token != null) {
  server.log("Valid access token is: " + token);
} else {
  // Acquire a new access token
  local error = client.acquireAccessToken(
    // Token received callback function
    function(response, error) {
      if (error) {
        server.error("Token acquisition error: " + error);
      } else {
        server.log("Received token: " + response);
      }
    },
    // User notification callback function
    function(url, code) {
      server.log("Authorization is pending. Please grant access");
      server.log("URL: " + url);
      server.log("Code: " + code);
    }
  );

  if (error != null) server.error("Client is already performing request (" + error + ")");
}
```

**Note** The DeviceFlow Client was verified and tested using the Google [Firebase](https://firebase.google.com) authorization flow.

# License #

The OAuth library is licensed under the [MIT License](LICENSE).
