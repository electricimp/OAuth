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

//@include "../OAuth2.agent.lib.nut"
#require "OAuth2.agent.lib.nut:2.1.0"

const GOOGLE_ISS = "";
const GOOGLE_SECRET_KEY = "";

local config = {
    "iss"         : GOOGLE_ISS,
    "jwtSignKey"  : GOOGLE_SECRET_KEY,
    "scope"       : "https://www.googleapis.com/auth/pubsub"
};

// Initializing client with provided Google Firebase config
client <- OAuth2.JWTProfile.Client(OAuth2.DeviceFlow.GOOGLE, config);

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
        }
    );

    if (null != error) server.error("Failed to obtain token: " + error);
}
