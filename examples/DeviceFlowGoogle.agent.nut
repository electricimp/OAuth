// MIT License
//
// Copyright 2017 Electric Imp
//
// SPDX-License-Identifier: MIT
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
// EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

#require "OAuth2.agent.lib.nut:2.1.0"

const CLIENT_ID = "";
const CLIENT_SECRET = "";

local providerSettings = {
    "loginHost" : "https://accounts.google.com/o/oauth2/device/code",
    "tokenHost" : "https://www.googleapis.com/oauth2/v4/token",
    "grantType" : "http://oauth.net/grant_type/device/1.0"
}

// Fill CLIENT_ID and CLIENT_SECRET with correct values
local userConfig = {
    "clientId"     : CLIENT_ID,
    "clientSecret" : CLIENT_SECRET,
    "scope"        : "email profile",
};

// Initializing client with provided Google Firebase config
client <- OAuth2.DeviceFlow.Client(providerSettings, userConfig);

local token = client.getValidAccessTokenOrNull();
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
