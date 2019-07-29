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

class DeviceFlowGoogleTestCase extends ImpTestCase {

    auth = null;

    static ID = "@{CLIENT_ID}";
    static SECRET = "@{CLIENT_SECRET}";

    function setUp() {
        local config = {
            "clientId"     : ID,
            "clientSecret" : SECRET,
            "scope"        : "email",
        };

        auth = OAuth2.DeviceFlow.Client(OAuth2.DeviceFlow.GOOGLE, config);
    }


    function checkToken(token, success, failure, doRefresh = false) {
        try {
            info("VerifyTokenTest: checking token");
            local query = http.urlencode({"access_token" : token });
            info("VerifyTokenTest: token query is: " + query);
            http.post(TOKEN_VERIFICATION_URL + "?"+query, {}, "")
                .sendasync(function (resp) {
                    local status = resp.statuscode;
                    info("VerifyTokenTest: status is: " + status);
                    local body = resp.body;
                    info("VerifyTokenTest: body is: " + body);
                    if (200 != status) {
                        failure("Verification server returns NOT OK");
                    } else {
                        if (doRefresh) {
                            local res = auth.refreshAccessToken(function(token, err) {
                                info("VerifyTokenTest_refresh: callback involved");
                                if (null != err) {
                                    info("VerifyTokenTest_refresh: err != null: " + err);
                                    failure(err);
                                } else {
                                    info("VerifyTokenTest_refresh: going to check token");
                                    checkToken(token, success, failure);
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

    function grantAccess(url, code, success, failure) {
        //TODO: goto url, parse html and  post the code
        //works as partially manual test now, fully automated scenario looks too fragile
        info("Need user action at " + url + " with code " + code);
        if ("@{OS}" == "Windows_NT") {
            // windows
            this.runCommand("start " + url);
        } else {
            // osx, linux is not supported
            this.runCommand("open " + url);
        }
    }

    function testRunCommandAsynchronously() {
        return Promise(function (success, failure) {

            local token = auth.getValidAccessTokenOrNull();
            if (null != token) {
                info("VerifyTokenTest: it was not null!. something went wrong!");
                checkToken(token, success, failure);
            } else {
                local err = auth.acquireAccessToken(function(token, err){
                    info("VerifyTokenTest: callback involved");
                    if (null != err) {
                        info("VerifyTokenTest: err != null: " + err);
                        failure(err);
                    } else {
                        info("VerifyTokenTest: going to check token");
                        checkToken(token, success, failure, true);
                    }
                }.bindenv(this), function(url, code) {
                    grantAccess(url, code, success, failure);
                }.bindenv(this));
                if (null != err) failure(err);
            }
        }.bindenv(this));
    }
}
