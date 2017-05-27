# Demo Instructions

* [JWT Profile for OAuth 2.0](#jwt-profile-for-oauth-20)
* [OAuth 2.0 Device Flow](#oauth-20-device-flow)

## JWT Profile for OAuth 2.0

This demo examples acquiring of OAuth access token from Google [OAuth service](https://developers.google.com/identity/protocols/OAuth2) with Google [OAuth 2.0 for Service Accounts](https://developers.google.com/identity/protocols/OAuth2ServiceAccount) that is implementation of `JWT Profile for OAuth 2.0` specification.

### Setup Amazon Lambda to support RS256 signature

The Electric Impl OAuth library temporary [required](..#oauth2jwtprofileclient) external service to sign JSON Web Token by `SHA256withRSA` (also known as `RS256`) signature algorithm. This sections shows how to create a [AWS Lambda](https://aws.amazon.com/lambda) that will do RSA-SHA256 signatures for an agent.

**NOTE**: An Amazon Web Services (AWS) account is required to run AWS Lambda. The account must be verified, ie. billing information entered and accepted. Account verification may take up to 12 hours, and no service is available prior to verification.

#### Setting up a Lambda

1. In a new browser tab, log into your [AWS account](https://aws.amazon.com/console/).
1. Select `Services` link (on the top left of the page) and them type `Lambda` in the search line
1. Select the `Lambda Run Code without Thinking about Services` item
1. Select `Create a Lambda function`
1. Under the `Select blueprint` choose `Blank function`
1. Select `Configure function` item from the manu on the left and do the following
    1. Give function a name `RSALambda`
    1. Select runtime `Node.js 6.10`
    1. Paste the full lambda [source code](./RSALambda.js) from this folder into the `Lambda function code` section.
    1. Leave `Handler` as default (`index.handler`)
    1. Set `Role` to `Create new role from template(s)`
    1. Set `Role name` to `role_with_no_permissions`
    1. Leave `Policy templates` empty
    1. `Next`
1. Press `Create function`
1. On the Lambda page copy and copy down Lambda's **ARN**. It can be found at the top right corner
of the page and should look like: `arn:aws:lambda:us-west-1:123456789101:function:RSALambda`
1. Copy down the Lambda region. It can be found on the top right corner of the page,
and is a next item to the right of the link with the user name (e.g. "us-east-1")

**IMPORTANT:** The name of the AWS Lambda function must be `RSALambda`!

#### Setting up AIM Policy

1. Select `Services` link (on the top left of the page) and them type `IAM` in the search line
1. Select `IAM Manage User Access and Encryption Keys` item
1. Select `Policies` item from the menu on the left
1. Press `Create Policy` button
1. Press `Select` for `Policy Generator`
1. On the `Edit Permissions` page do the following
    1. Set `Effect` to `Allow`
    1. Set `AWS Service` to `AWS Lambda`
    1. Set `Actions` to `InvokeFunction`
    1. Set `Amazon Resource Name (ARN)` to the Lambda **ARN** retrieved on the previous step
    1. Press `Add Statement`
    1. Press `Next Step`
1. Give your policy a name, for example, `allow-calling-RSALambda` and type in into the `Policy Name` field
1. Press `Create Policy`

#### Setting up the AIM User

1. Select `Services` link (on the top left of the page) and them type `IAM` in the search line
1. Select the `IAM Manage User Access and Encryption Keys` item
1. Select `Users` item from the menu on the left
1. Press `Add user`
1. Choose a user name, for example `user-calling-lambda`
1. Check `Programmatic access` but not anything else
1. Press `Next: Permissions` button
1. Press `Attach existing policies directly` icon
1. Check `allow-calling-RSALambda` from the list of policies
1. Press `Next: Review`
1. Press `Create user`
1. Copy down your `Access key ID` and `Secret access key`

### Setup Google OAuth2 for Service Accounts

Google names own implementation of [rfc7523](https://tools.ietf.org/html/rfc7523) as [`OAuth2 for Service Accounts`](https://developers.google.com/identity/protocols/OAuth2ServiceAccount). To obtain account's credentials do the following steps:
1. Open [`Google cloud console`](https://console.cloud.google.com).
1. Being at `Manage Resource` page create new project. Go to next step if the project was created already.
1. Select `IAM & Admin`, then `Service Accounts` from left side menu.
1. Press `Create service account` button.
1. Provide new service account name at corresponding field.
1. From drop down menu `Role` select new account role. For current example select all available `Pub/Sub` group roles.
1. Check `Furnish a new private key` button. Leave other untouched.
1. Press `Create` button.
1. If no key is generated (`Key ID` field contains `No key`), create new public/private key pair by pressing `Create key` from right drop down menu. Select `JSON` at popup window and press `CREATE`.
1. The file `<project name>-<random number>.json` will be downloaded to your machine.

An example of downloaded file:
``` JSON
{
  "type": "service_account",
  "project_id": "test-project",
  "private_key_id": "27ed751da7f0cb605c02dafda6a5cf535e662aea",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMII ..... QbDgw==\n-----END PRIVATEKEY-----\n",
  "client_email": "test-account@test-project.iam.gserviceaccount.com",
  "client_id": "117467107027610486288",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://accounts.google.com/o/oauth2/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test-account%40@test-project.iam.gserviceaccount.com"
}
```

### Setting up Agent Code

Here is some agent [code](JWTProfile.agent.nut). Copy and paste it into the Web IDE to the left window (agent code).

Set the example code configuration parameters with values retrieved on the previous steps:

Parameter             | Description
----------------------| -----------
AWS_LAMBDA_REGION     | AWS region where Lambda located
AWS_ACCESS_KEY_ID     | AWS IAM `Access key ID`
AWS_SECRET_ACCESS_KEY | AWS IAM `Secret Access Key`
GOOGLE_ISS            | `client_email` field from downloaded JSON
GOOGLE_SECRET_KEY     | `private_key` field from downloaded JSON

Run the example code and it should print acquired access token.

## OAuth 2.0 Device Flow

This example is about acquiring OAuth access token from  Google OAuth service using "TV and Limited Devices" authorization.

### Adding Credentials

1. Go to `https://console.developers.google.com` and log in
1. Select `Credentials` in the left bar
1. Click on the `Create credentials` button
1. Select `OAuth client ID`
1. Select `Other`
1. Enter a name and press `Create`
1. Copy client ID and client secret from popup window shown in the browser

**NOTE**: If you have lost your Client ID and Secret click on the ID name in the `OAuth 2.0 client IDs` list and copy them from the Client ID details page.

### Customizing Consent Screen

To customize the page that users see while authorizing your application go to
`OAuth consent screen` tab.


### Setting up Agent Code

Copy the example agent [code](DeviceFlow.agent.nut) and paste it into the Web IDE to the left window (agent code).

Set the example code configuration parameters with values retrieved on the previous steps:

Parameter             | Description
----------------------| -----------
CLIENT_ID  			  | Google client ID
CLIENT_SECRET         | Google client secret

**NOTE**: As the sample code includes the private key verbatim in the source,
it should be treated carefully, and not checked into version control!

# License

The OAuth library is licensed under the [MIT License](../LICENSE).
