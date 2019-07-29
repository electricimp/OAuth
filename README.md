# OAuth 2 2.1.0 #

This library provides OAuth 2.0 authentication and authorization flows. It supports the following flows:

- [OAuth2.JWTProfile.Client](#oauth2jwtprofileclient) &mdash; OAuth 2.0 with the JSON Web Token (JWT) Profile for Client Authentication and Authorization Grants as defined in [IETF RFC 7523](https://tools.ietf.org/html/rfc7523).
- [OAuth2.DeviceFlow.Client](#oauth2deviceflowclient) &mdash; OAuth 2.0 Device Flow for browserless and input-constrained devices. The implementation conforms to the [IETF draft device flow specification](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-05).

The library exposes retrieved access tokens for applications and hides provider-specific operations, including the renewal of expired tokens.

**To include this library in your project, add** `#require "OAuth2.agent.lib.nut:2.1.0"` **at the top of your agent code.**

![Build Status](https://cse-ci.electricimp.com/app/rest/builds/buildType:(id:OAuth2_BuildAndTest)/statusIcon)

## Examples ##

A complete, step-by-step recipe can be found in the [examples](./examples) folder.

## OAuth2.JWTProfile.Client ##

This class implements an OAuth 2.0 client flow using a JSON Web Token (JWT) as the means for requesting access tokens and for client authentication.

The JSON Web Token (JWT) Profile for OAuth 2.0 was verified and tested with the Google [PubSub](https://cloud.google.com/pubsub/docs/) authorization flow.

## OAuth2.JWTProfile.Client Usage ##

<a id="jwt-flow-constructor"></a>

### constructor(*providerSettings, userSettings[, configSettings]*) ###

The constructor creates an instance of the *OAuth2.JWTProfile.Client* class. The first parameter, *providerSettings*, must be passed a table containing provider-specific settings:

| *providerSettings*&nbsp;Key | Type | Required? | Description |
| --- | --- | --- | --- |
| *tokenHost* | String | Yes | The token endpoint. This is used by the client to exchange an authorization grant for an access token, typically with client authentication |

The second parameter, *userSettings*, must be passed a table containing user- and application-specific settings:

| *userSettings*&nbsp;Key | Type | Required? | Description |
| --- | --- | --- | --- |
| *iss* | String | Yes | The JWT issuer |
| *jwtSignKey* | String | Yes | A JWT sign secret key |
| *scope* | String | No | A scope. Scopes enable your application to request access only to the resources that it needs while also enabling users to control the amount of access that they grant to your application. Unless the authorization server has a pre-configured scope, requests should include a scope |
| *sub* | String | No | The subject of the JWT. Google appears to ignore this field. Default: the value of *iss* |

The third parameter, *configSettings*, is optional: it can take a table containing class configuration settings. If no table is passed in, the default settings will be applied:

| *configSettings*&nbsp;Key | Type | Required? | Description |
| --- | --- | --- | --- |
| *includeResp* | Boolean | No | Whether to include the HTTP response in the token ready callback. Default: `false` |
| *enLogging* | Boolean | No | Whether to enable debug logging. Default: `false` |

#### Example ####

```squirrel
// Import the OAuth 2.0 library
#require "OAuth2.agent.lib.nut:2.1.0"

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

This method begins the access token acquisition procedure. It invokes the provided callback function immediately if the access token is already available and valid.

#### Parameters ####

| Parameter | Type | Required? | Description |
| --- | --- | --- | --- |
| *tokenReadyCallback* | Function | Yes | Called when the token is ready for use |

The function passed into the *tokenReadyCallback* parameter should include the first two of the following parameters. It should include the third only if you passed a table into the [constructor's configSettings parameter](#jwt-flow-constructor) and set the *includeResp* key's value to `true`.

| Parameter | Type | Description |
| --- | --- | --- |
| *token* | String | The access token |
| *error* | String | Error details, or `null` in the case of success |
| *resp*  | Table  | Only required if the *includeResp* flag is set to `true`. An HTTP response table with keys *statuscode*, *headers* and *body*, or `null` if no HTTP response is available |

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

This method immediately provides either an existing access token if it is valid, or `null` if the client is not authorized or the token has expired.

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

Boolean &mdash; `true` if the current access token is valid, otherwise `false`.

#### Example ####

```squirrel
server.log("The access token is " + (client.isTokenValid() ? "" : "in") + "valid");
```

### Complete JWT Profile Example ###

```squirrel
// Import the OAuth 2.0 library
#require "OAuth2.agent.lib.nut:2.1.0"

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
        function(newToken, error) {
            if (error) {
                server.error("Token acquisition error: " + error);
            } else {
                server.log("Received a new token: " + newToken);
            }
        }
    );
}
```

## OAuth2.DeviceFlow.Client ##

This class implements an OAuth 2.0 authorization flow for browserless and/or input-constrained devices. Often referred to as the [device flow](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-05), this flow enables OAuth clients to request user authorization from devices that have an Internet connection but lack a suitable input method as required for a more traditional OAuth flow. This authorization flow therefore instructs the user to perform the authorization request on a secondary device, such as a smartphone.

The DeviceFlow Client was verified and tested using the Google [Firebase](https://firebase.google.com) authorization flow.

## OAuth2.DeviceFlow.Client Usage ##

<a id="device-flow-constructor"></a>

### constructor(*providerSettings, userSettings[, configSettings]*) ###

This constructor creates an instance of the *OAuth2.DeviceFlow.Client* class. The first parameter, *providerSettings*, must be passed a table containing provider-specific settings:

| *providerSettings*&nbsp;Key | Type | Required? | Description |
| --- | --- | --- | --- |
| *loginHost* | String | Yes | The authorization endpoint. This is used by the client to obtain authorization from the resource owner via user-agent redirection |
| *tokenHost* | String | Yes | The token endpoint. This is used by the client to exchange an authorization grant for an access token, typically with client authentication |
| *grantType* | String | No | The grant type identifier supported by the provider. Default: `"urn:ietf:params:oauth:grant-type:device_code"` |

The second parameter, *userSettings*, must be passed a table containing user- and application-specific settings:

| *userSettings*&nbsp;Key | Type | Required? | Description |
| --- | --- | --- | --- |
| *clientId* | String | Yes | The OAuth client ID |
| *clientSecret* | String | Yes | The project's client secret |
| *scope* | String | Yes | A scope. Scopes enable your application to only request access to the resources that it needs while also enabling users to control the amount of access that they grant to your application |

The third parameter, *configSettings*, is optional: it can take a table containing class configuration settings. If no table is passed in, the default settings will be applied:

| *configSettings*&nbsp;Key | Type | Required? | Description |
| --- | --- | --- | --- |
| *includeResp* | Boolean | No | Whether to include the HTTP response in the token ready callback. Default: `false` |
| *enLogging* | Boolean | No | Whether to enable debug logging. Default: `true` |
| *addReqCodeData* | Table | No | A table containing key-value pairs to be included in HTTP requests to obtain a device authorization code. In most cases this should not be needed. Default: `null` |

#### Example ####

```squirrel
// Import the OAuth 2.0 library
#require "OAuth2.agent.lib.nut:2.1.0"

local providerSettings = { "loginHost" : "https://accounts.google.com/o/oauth2/device/code",
                           "tokenHost" : "https://www.googleapis.com/oauth2/v4/token",
                           "grantType" : "http://oauth.net/grant_type/device/1.0" };

local userSettings = { "clientId"     : "<USER_FIREBASE_CLIENT_ID>",
                       "clientSecret" : "<USER_FIREBASE_CLIENT_SECRET>",
                       "scope"        : "email profile" };

client <- OAuth2.DeviceFlow.Client(providerSettings, userSettings);
```

## OAuth2.DeviceFlow.Client Methods ##

### acquireAccessToken(*tokenReadyCallback, notifyUserCallback[, force]*) ###

This method begins the access-token acquisition procedure. Depending on the client state, it may start a full client authorization procedure or just refresh a token that has already been acquired. The access token is delivered through the function passed into *tokenReadyCallback*.

#### Parameters ####

| Parameter | Type | Required? | Description |
| --- | --- | --- | --- |
| *tokenReadyCallback* | Function | Yes | The callback that will be executed when the access token has been acquired, or an error has occurred. The function’s parameters are described below |
| *notifyUserCallback* | Function | Yes | The callback that will be executed when user action is required. See [RFE, device flow, section 3.3](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-05#section-3.3) for information on what user action might be needed when this callback is triggered. The function’s parameters are described below |
| *force* | Boolean | No | This flag forces the token acquisition process to start from the beginning even if a previous request has not yet completed. Any previous session will be terminated. Default: `false` |

The function passed into the *tokenReadyCallback* parameter should include the first two of the following parameters. It should include the third only if you passed a table into the [constructor's configSettings parameter](#device-flow-constructor) and set the *includeResp* key's value to `true`.

| Parameter | Type | Description |
| --- | --- | --- |
| *token* | String | The access token |
| *error* | String | Error details, or `null` in the case of success |
| *resp*  | Table  | Only present if the *includeResp* flag is set to `true`. An HTTP response table with keys *statuscode*, *headers* and *body*, or `null` if no HTTP response is available |

The function passed into the *notifyUserCallback* parameter should have the following parameters of its own:

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

This method immediately provides either an existing access token if it is valid, or `null` if the token has expired or the client is yet not authorized.

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

This method indicates whether the current access token is valid.

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

This method asynchronously refreshes the access token and invokes the callback function passed into *tokenReadyCallback* when this has been completed or an error occurs.

#### Parameters ####

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| *tokenReadyCallback* | Function | Yes | Called when the token is ready for use |

The function passed into the *tokenReadyCallback* parameter should include the first two of the following parameters. It should include the third only if you passed a table into the [constructor's configSettings parameter](#device-flow-constructor) and set the *includeResp* key's value to `true`.

| Parameter | Type | Description |
| --- | --- | --- |
| *token* | String | The access token |
| *error* | String | Error details, or `null` in the case of success |
| *resp*  | Table  | Only present if the *includeResp* flag is set to `true`. An HTTP response table with keys *statuscode*, *headers* and *body*, or `null` if no HTTP response is available |

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

### Complete Device Flow Example ###

```squirrel
// Import the OAuth 2.0 library
#require "OAuth2.agent.lib.nut:2.1.0"

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

## License ##

This library is licensed under the [MIT License](LICENSE).