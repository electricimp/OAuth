# Demo Instructions #

* [JWT Profile for OAuth 2.0](#jwt-profile-for-oauth-20)
* [OAuth 2.0 Device Flow](#oauth-20-device-flow)

## JWT Profile For OAuth 2.0 ##

This example shows how you can acquire an access token from Google's [OAuth service](https://developers.google.com/identity/protocols/OAuth2) usin the Google [OAuth 2.0 for Service Accounts](https://developers.google.com/identity/protocols/OAuth2ServiceAccount) Protocol, which implements the [JWT Profile for the OAuth 2.0 specification](https://tools.ietf.org/html/rfc7523).

### Setting Up Google OAuth2 For Service Accounts ###

To obtain Google account credentials follow the steps below.

**Note** The instructions assume that you are registered and logged in at [console.cloud.google.com](https://console.cloud.google.com).

1. If you have an existing project that you want to work with, select the it in the project selector (the link to the right of the **Google Cloud Platform** icon at the top right corner of the screen). Otherwise click on the project selector and press **+** in the opened window.
1. Click **IAM & Admin** and then **Service Accounts** from left side menu.
1. Click the **Create service account** button.
1. Enter a new service account name in the corresponding field.
1. Select **New Account Role** from the **Role** dropdown menu. For the example, select all available **Pub/Sub** group roles.
1. Check the **Furnish a new private key** checkbox. Leave all other checkboxes untouched.
1. Click the **Create** button.
1. If no key is generated (the **Key ID** field contains the text `No key`), create a new public/private key pair
by selecting **Create key** from the dropdown menu of the selected service account. Select **JSON** in the popup window and press **CREATE**.
1. The file `<project name>-<random number>.json` will be downloaded to your computer. It will look something like this:

```json
{ "type": "service_account",
  "project_id": "test-project",
  "private_key_id": "27ed751da7f0cb605c02dafda6a5cf535e662aea",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMII ..... QbDgw==\n-----END PRIVATEKEY-----\n",
  "client_email": "test-account@test-project.iam.gserviceaccount.com",
  "client_id": "117467107027610486288",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://accounts.google.com/o/oauth2/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test-account%40@test-project.iam.gserviceaccount.com" }
```

### Set Up The Agent Code ###

Copy and paste [this agent code](JWTGooglePubSub.agent.nut) into the impCentral™ code editor’s left-hand pane.

Now set the example code configuration parameters with values retrieved during the previous steps:

Parameter             | Description
--------------------- | -----------
*GOOGLE_ISS*          | Use the `client_email` field from the downloaded JSON file (see [Setting Up Google OAuth2 For Service Accounts](#setting-up-google-oauth2-for-service-accounts), above)
*GOOGLE_SECRET_KEY*   | Use the `private_key` field from the downloaded JSON file (see [Setting Up Google OAuth2 For Service Accounts](#setting-up-google-oauth2-for-service-accounts), above)

Run the example code and it should print acquired access token.

## OAuth 2.0 Device Flow ##

This example demonstrates how you can acquire an access token from Google's [OAuth service](https://developers.google.com/identity/protocols/OAuth2) using [OAuth 2.0 for TV and Limited-Input Device Applications](https://developers.google.com/identity/protocols/OAuth2ForDevices).

### Creating Google Client Credentials ###

To obtain Google client credentials follow the steps below.

**Note** The instructions below assume that you are registered and logged in at [console.cloud.google.com](https://console.cloud.google.com).

1. Open the [project dashboard](https://console.cloud.google.com/projectselector/home/dashboard).
1. Select the required project in the project selector (the link to the right of the **Google Cloud Platform** icon at the top right corner of the screen).
1. Select **APIs and Services** from the left side menu.
1. Select **Credentials** in the left bar.
1. Go to the **OAuth consent screen** tab and enter your public product name into the **Product name shown to users** field. Now click **Save**.
1. Select the **Credentials** tab.
1. Click on the **Create credentials** button.
1. Select **OAuth client ID**.
1. Select **Other**.
1. Enter a name and click **Create**.
1. Copy the client ID and the client secret from the popup window shown in your browser.

**Note** If you have lost your Client ID and Secret, click on the ID name in the **OAuth 2.0 client IDs** list and copy them from the Client ID details page.

### Customize The Consent Screen ###

To customize the page that users see while authorizing your application, go to the **OAuth consent screen** tab.

### Set Up The Agent Code ###

Copy this [example agent code](DeviceFlowGoogle.agent.nut) and paste it into the impCentral code editor’s left-hand pane.

Now set the example code configuration parameters with values retrieved during the previous steps:

Parameter             | Description
--------------------- | -----------
*CLIENT_ID*  	      | Enter the Google Client ID acquired in [the steps above](#creating-google-client-credentials)
*CLIENT_SECRET*       | Enter the Google Client Secret acquired in [the steps above](#creating-google-client-credentials)

**Note** As the sample source code includes the private key verbatim, it should be treated carefully and not checked into version control.