# OAuth 2.0

OAuth 2.0 authentication and authorization flows implementation. The library supports
the following flows:
- [OAuth2.JWTProfile.Client](#oauth2jwtprofileclient) &mdash; OAuth 2.0 with JSON Web Token (JWT) Profile for Client Authentication and Authorization Grants
 defined in the [IETF RFC 7523](https://tools.ietf.org/html/rfc7523).
- [OAuth2.DeviceFlow.Client](#oauth2deviceflowclient) &mdash; Device Flow for browserless and input constrained devices. The implementation conforms
to the [draft specification](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-05).

The library exposes access token for applications and hides provider specific
operations including refresh token management and expired access token renewal.

**To add this library to your project, add** `#require "OAuth2.agent.lib.nut:1.0.0"` **to the top of your agent code.**

## OAuth2.JWTProfile.Client

The class implements OAuth 2.0 flow with JSON Web Token (JWT) Bearer Token as a means for requesting
an access token as well as for client authentication.

**NOTE:** The flow requires RSA SHA256 signature, which is not currently supported by the Electric Imp
[Agent API](https://electricimp.com/docs/api/agent/). As a temporary solution it is proposed to use
[AWS Lambda](https://aws.amazon.com/lambda) function that will do
[RSA-SHA256 signatures](examples#setup-amazon-lambda-to-support-rs256-signature) for an agent. 
AWS Lambda is subject to a service charge (please refer to Amazon pricing 
[page](https://aws.amazon.com/lambda/pricing/) for more details).

### constructor(providerSettings, userSettings)

Construction that creates an instance of the `OAuth2.JWTProfile.Client`.

The first parameter `providerSettings` is a map that contains provider specific settings:

| Parameter | Type | Use | Description |
| --- | --- | --- | --- |
| `TOKEN_HOST` | *string* | Required | Token endpoint - used by the client to exchange an authorization grant for an access token, typically with client authentication. |

The second parameter `userSettings` defines a map with user and application specific settings:

| Parameter | Type | Use | Description |
| --- | --- | --- | --- |
| `iss` | *string* | Required | JWT issuer |
| `scope` | *string* | Required | Scopes enable your application to only request access to the resources that it needs while also enabling users to control the amount of access that they grant to your application |
| `jwtSignKey` | *string* | Required | JWT sign secret key |
| `rs256signer` | *[AWSLambda](https://github.com/electricimp/awslambda)* | Required | Instance of [AWSLambda](https://github.com/electricimp/awslambda) for RSA-SHA256 encryption. You can use [example](examples#jwt-profile-for-oauth-20) code to create the AWS Lambda function. |
| `sub` | *string* | Optional. *Default:* the value of `iss` | The *subject* of the JWT. Google seems to ignor this field. |

*Note* Optional `sub` property is substituted by mandatory `iss` property when omitted.


#### JWT Profile Client Creation Example

```squirrel
// AWS Lambda libraries
#require "AWSRequestV4.class.nut:1.0.2"
#require "AWSLambda.agent.lib.nut:1.0.0"

// OAuth 2.0 library
#require "OAuth2.agent.lib.nut:1.0.0"

// Substitute with real values
const LAMBDA_REGION        = "us-west-1";
const LAMBDA_ACCESS_KEY_ID = "<AWS access key id>";
const LAMBDA_ACCESS_KEY    = "<AWS access key>";
const GOOGLE_ISS           = "rsalambda@quick-cacao-168121.iam.gserviceaccount.com";
const GOOGLE_SECRET_KEY    = "-----BEGIN PRIVATE KEY-----\nprivate key goes here\n-----END PRIVATE KEY-----\n";

// Create AWS Lambda Instance
local signer = AWSLambda(LAMBDA_REGION, LAMBDA_ACCESS_KEY_ID, LAMBDA_ACCESS_KEY);

local providerSettings =  {
    "TOKEN_HOST"  : "https://www.googleapis.com/oauth2/v4/token"
};
local userSettings = {
    "iss"         : GOOGLE_ISS,
    "jwtSignKey"  : GOOGLE_SECRET_KEY,
    "scope"       : "https://www.googleapis.com/auth/pubsub",
    "rs256signer" : signer
};

local client = OAuth2.JWTProfile.Client(providerSettings, userSettings);
```
**IMPORTANT:** The name of the AWS Lambda function must be `RSALambda`!

### acquireAccessToken(tokenReadyCallback)

Starts access token acquisition procedure. Invokes the provided callback function immediately
if access token is available and valid.

Parameter details:

| Parameter | Type | Use | Description |
| --- | --- | --- | --- |
| `tokenReadyCallback` | Function | Required | The handler to be called when access token is acquired or an error occurs |

`tokenReadyCallback` callback should have two parameters:

| Parameter | Type | Description |
| --- | --- | --- |
| `token` | *string* | String representation of access token |
| `error` | *table* | Table with error details, `null` in case of success |

#### Example

Using `client` from previous [sample](#jwt-profile-client-creation-example)

```squirrel
client.acquireAccessToken(
    function(resp, err) {
        server.log(resp);
        if (err) {
            server.error(err);
        }
    }
);
```
### getValidAccessTokeOrNull()

Returns access token string non blocking way. Returns access token as a string object if token is valid,
null if the client is not authorized or token is expired.

#### Example

Using `client` from the first [sample](#jwt-profile-client-creation-example)

```squirrel
local token = client.getValidAccessTokeOrNull();
if (token) server.log("token is valid and has value: " + token);
else server.log("token is either expired  or client is not authorized!");
```

### isTokenValid()

Checks if access token is valid by comparing its expire time with current one.

#### Example

Using `client` from the first [sample](#jwt-profile-client-creation-example)

```squirrel
server.log("token is valid=" + client.isTokenValid());
```

## Complete usage sample

To connect all the parts together and show a sample of common case of library usage let's take a look a following sample

```squirrel
#require "AWSRequestV4.class.nut:1.0.2"
#require "AWSLambda.agent.lib.nut:1.0.0"
#require "OAuth2.agent.lib.nut:1.0.0

// Substitute with real values
const LAMBDA_REGION        = "us-west-1";
const LAMBDA_ACCESS_KEY_ID = "<AWS access key id>";
const LAMBDA_ACCESS_KEY    = "<AWS access key>";
const GOOGLE_ISS           = "rsalambda@quick-cacao-168121.iam.gserviceaccount.com";
const GOOGLE_SECRET_KEY    = "-----BEGIN PRIVATE KEY-----\nprivate key goes here\n-----END PRIVATE KEY-----\n";

local signer = AWSLambda(LAMBDA_REGION, LAMBDA_ACCESS_KEY_ID, LAMBDA_ACCESS_KEY);

local providerSettings =  {
    "TOKEN_HOST" : "https://www.googleapis.com/oauth2/v4/token"
};
local userSettings = {
    "iss"         : GOOGLE_ISS,
    "jwtSignKey"  : GOOGLE_SECRET_KEY,
    "scope"       : "https://www.googleapis.com/auth/pubsub",
    "rs256signer" : signer
};

local client = OAuth2.JWTProfile.Client(providerSettings, userSettings);

local token = client.getValidAccessTokeOrNull();
if (token != null) {
    server.log("Valid access token is: " + token);
} else {
    // Starting procedure of access token acquisition
    local error = client.acquireAccessToken(
        function(resp, err) {
            if (err) {
                server.error("Token acquisition error: " + err);
            } else {
                server.log("Received token: " + resp);
            }
        }
    );

    if (null != error) server.error("Failed to obtain token: " + error);
}
```

**NOTE:** JWT Profile for OAuth 2.0 was verified and tested with
Google [PubSub](https://cloud.google.com/pubsub/docs/) authorization flow.


## OAuth2.DeviceFlow.Client

The class implements OAuth 2.0 authorization flow for browserless and input
constrained devices, often referred to as the
[device flow](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-05), enables
OAuth clients to request user authorization from devices that have an
Internet connection, but don't have an easy input method, or lack a
suitable browser for a more traditional OAuth flow. This
authorization flow instructs the user to perform the authorization
request on a secondary device, such as a smartphone.


### constructor(providerSettings, userSettings)

Construction that creates an instance of the `OAuth2.DeviceFlow.Client`.

The first parameter `providerSettings` is a map that contains provider specific settings:

| Parameter | Type | Use | Description |
| --- | --- | --- | --- |
| `LOGIN_HOST` | *string* | Required | Authorization endpoint - used by the client to obtain authorization from the resource owner via user-agent redirection. authorization server  |
| `TOKEN_HOST` | *string* | Required | Token endpoint - used by the client to exchange an authorization grant for an access token, typically with client authentication. |
| `GRANT_TYPE` | *string* | Optional. *Default:* `urn:ietf:params:oauth:grant-type:device_code` | Grant type identifier supported by the provider |

The second parameter `userSettings` defines a map with user and application specific settings:

| Parameter | Type | Use |Description |
| --- | --- | --- | --- |
| `clientId` | *string* | Required | OAuth client ID |
| `clientSecret` | *string* | Required | The project's client secret |
| `scope` | *string* | Required | Scopes enable your application to only request access to the resources that it needs while also enabling users to control the amount of access that they grant to your application. |

The library provides predefined configuration settings for
Google Device Auth flow. These settings are defined in the provider
specific settings map:`OAuth2.DeviceFlow.GOOGLE`. The table
provides `LOGIN_HOST`, `TOKEN_HOST` and `GRANT_TYPE` values.

#### Device Flow Client Creation Example

```squirrel
    local providerSettings =  {
        "LOGIN_HOST" : "https://accounts.google.com/o/oauth2/device/code",
        "TOKEN_HOST" : "https://www.googleapis.com/oauth2/v4/token",
        "GRANT_TYPE" : "http://oauth.net/grant_type/device/1.0",
    };
    local userSettings = {
        "clientId"     : "USER_FIREBASE_CLIENT_ID",
        "clientSecret" : "USER_FIREBASE_CLIENT_SECRET",
        "scope"        : "email profile",
    };

    client <- OAuth2.DeviceFlow.Client(providerSettings, userSettings);
```

### acquireAccessToken(tokenReadyCallback, notifyUserCallback, force)

Starts access token acquisition procedure. Depending on Client state may starts full client authorization procedure or
just token refreshing. Returns null in case of success and error otherwise. Access token is delivered through provided *tokenReadyCallback* function.

Parameter details:

| Parameter | Type | Use | Description |
| --- | --- | --- | --- |
| `tokenReadyCallback` | *function* | Required | The handler to be called when access token is acquired or an error occurred |
| `notifyUserCallback` | *function* | Required | The handler to be called when user action is required. See [RFE, device flow, section3.3](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-05#section-3.3) |
| `force` | *boolean* | Optional. *Default:* `false` | The flag forces the token acquisition process to start from the beginning even if the previous request did not complete yet. The previous session will be terminated. |

where `tokenReadyCallback` should have the following parameters:

| Parameter | Type | Description |
| --- | --- | --- |
| `token` | *string* | String representation of access token |
| `error` | *table* | Table with  error details, `null` in case of success |

and `notifyUserCallback` should have two parameters:

| Parameter | Type | Description |
| --- | --- | --- |
| `uri`  | *string* | The URI the user need to use for client authorization |
| `code` | *string* | The code for the authorization server |

#### Example

Using `client` from previous [sample](#device-flow-client-creation-example)

```squirrel
client.acquireAccessToken(
    function(resp, err) {
        server.log(resp);
        if (err) {
            server.error(err);
        }
    },
    function(url, code) {
        server.log("Authorization is pending. Please grant access.");
        server.log("URL: " + url);
        server.log("CODE: " + code);
    }
);
```
### getValidAccessTokeOrNull()

Immediately returns either existing access token if it's valid, or null if it expired or 
the client is not authorized yet.

#### Example

Using `client` from the first [sample](#device-flow-client-creation-example)

```squirrel
local token = client.getValidAccessTokeOrNull();
if (token) {
    server.log("Token is valid: " + token);
} else {
    server.log("Either token expired or client is not authorized!");
}
```

### isTokenValid()

Checks if access token is valid.

#### Example

Using `client` from the first [sample](#device-flow-client-creation-example)

```squirrel
server.log("Token is valid: " + client.isTokenValid());
```

### isAuthorized()

Checks if the client is authorized and able to refresh expired access token.

Using `client` from the first [sample](#device-flow-client-creation-example)

```squirrel
server.log("Client is authorized: " + client.isAuthorized());
```

### refreshAccessToken(tokenReadyCallback)

Asynchronously refreshes access token and invokes `tokenReadyCallback` when done or an error occurs.

Function `tokenReadyCallback` should have two parameters:

| Parameter | Type | Description |
| --- | --- | --- |
| token | String | String representation of access token |
| error | Table | Table with  error details, `null` in case of success |

#### Example

Using `client` from the first [sample](#device-flow-client-creation-example)

```squirrel
client.refreshAccessToken(
    function(resp, err) {
        server.log(resp);
        if (err) {
            server.error(err);
        }
    }
);
```

## Complete usage sample

To connect all the parts together and show a sample of common case of library usage let's take a look a following sample

```squirrel
#require "OAuth2.agent.lib.nut:1.0.0

// Fill CLIENT_ID and CLIENT_SECRET with correct values
local userConfig = {
    "clientId"     : "CLIENT_ID",
    "clientSecret" : "CLIENT_SECRET",
    "scope"        : "email profile",
};

// Initializing client with provided Google Firebase config
client <- OAuth2.DeviceFlow.Client(OAuth2.DeviceFlow.GOOGLE, userConfig);

local token = client.getValidAccessTokeOrNull();
if (token != null) {
    server.log("Valid access token is: " + token);
} else {
    // Starting procedure of access token acquisition
    local error = client.acquireAccessToken(
        function(resp, err) {
            if (err) {
                server.error("Token acquisition error: " + err);
            } else {
                server.log("Received token: " + resp);
            }
        },
        function(url, code) {
            server.log("Authorization is pending. Please grant access.");
            server.log("URL: " + url);
            server.log("CODE: " + code);
        }
    );

    if (null != error) server.error("Failed to obtain token: " + error);
}
```

**NOTE:** The DeviceFlow Client was verified and tested on the Google [Firebase](https://firebase.google.com)
 authorization flow.


# License

The OAuth library is licensed under the [MIT License](LICENSE).