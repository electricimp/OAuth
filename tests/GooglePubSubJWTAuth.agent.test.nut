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

const TOKEN_VERIFICATION_URL = "https://www.googleapis.com/oauth2/v3/tokeninfo";

class GooglePubSubJWTAuth extends ImpTestCase {

    _auth = null;

    static ISS = "@{GOOGLE_ISS}";
    static SECRET_KEY = "@{GOOGLE_SECRET_KEY}";

    function setUp() {
        local config = {
            "iss"         : ISS,
            "jwtSignKey"  : SECRET_KEY,
            "scope"       : "https://www.googleapis.com/auth/pubsub"
        };

        _auth = OAuth2.JWTProfile.Client(OAuth2.DeviceFlow.GOOGLE, config);
    }

    function verifyToken(token, success, failure, doRefresh = false) {
        try {
            info("VerifyTokenTest: checking token");
            local query = http.urlencode({"access_token" : token });
            // Don't include token in testing logs
            server.log("VerifyTokenTest: token query is: " + query);
            http.post(TOKEN_VERIFICATION_URL + "?" + query, {}, "")
                .sendasync(function (resp) {
                    local status = resp.statuscode;
                    info("VerifyTokenTest: status is: " + status);
                    local body = resp.body;
                    // For debugging only - Don't include token in testing logs
                    server.log("VerifyTokenTest: body is: " + body);
                    if (200 != status) {
                        failure("Verification server returns NOT OK");
                    } else {
                        if (doRefresh) {
                            local res = _auth.acquireAccessToken(function(token, err) {
                                info("VerifyTokenTest_refresh: callback involved");
                                if (null != err) {
                                    info("VerifyTokenTest_refresh: err != null: " + err);
                                    failure(err);
                                } else {
                                    info("VerifyTokenTest_refresh: going to check token");
                                    verifyToken(token, success, failure);
                                }
                            }.bindenv(this));
                            if (null != res) failure(res);
                        } else {
                            success();
                        }
                    }
                }.bindenv(this));
        } catch (error) {
            failure(error);
        }
    }

    function testAcquireAndVerifyToken() {
        return Promise(function (success, failure) {

            local token = _auth.getValidAccessTokenOrNull();
            if (null != token) {
                info("VerifyTokenTest: it was not null!. something went wrong!");
                failure("Initial token is not null");
            } else {
                local err = _auth.acquireAccessToken(function(token, err) {
                    info("VerifyTokenTest: callback involved");
                    if (null != err) {
                        info("VerifyTokenTest: err != null: " + err);
                        failure(err);
                    } else {
                        info("VerifyTokenTest: going to check token");
                        verifyToken(token, success, failure, true);
                    }
                }.bindenv(this));
            }
        }.bindenv(this));
    }
}
