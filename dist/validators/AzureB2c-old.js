"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AzureB2c = void 0;
const axios_1 = __importDefault(require("axios"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const jwks_rsa_1 = __importDefault(require("jwks-rsa"));
class AzureB2c {
    //constructor (name: string, tenant:string,userflow:string, schedule:string) {
    constructor(val) {
        this.cachedSigningKeys = new Map();
        this.verify = true;
        this.getKey = async (header, callback) => {
            if (this.cachedSigningKeys && this.cachedSigningKeys.has(header.kid)) {
                callback(null, this.cachedSigningKeys.get(header.kid));
            }
            else {
                //console.log('no kid found on cache');
                callback('no kid found on cache');
            }
        };
        this.decodeAndValidateToken = async (context) => {
            var _a, _b;
            try {
                const options = {
                //audience: [applicationId],
                //issuer: [issuerUri]
                };
                if (!context.token) {
                    console.log("***b2c notoken***");
                    return;
                }
                if (!context.validationStatus) {
                    if (this.verify) {
                        const decoded = await new Promise((resolve, reject) => {
                            jsonwebtoken_1.default.verify(context.token, this.getKey, options, (err, decoded) => {
                                if (err) {
                                    console.log("vererr");
                                    console.log(err);
                                    reject(err);
                                }
                                else {
                                    console.log("verok");
                                    console.log(decoded);
                                    resolve(decoded);
                                }
                            });
                        });
                        context.decoded = decoded;
                        context.validationStatus = true;
                    }
                    else {
                        try {
                            context.decoded = jsonwebtoken_1.default.decode(context.token, options);
                            context.validationStatus = true;
                            console.log("decok");
                        }
                        catch (err) {
                            context.validationStatus = false;
                            console.log("decerr");
                        }
                    }
                    console.log('Test special conditions');
                    if (context.validationStatus) {
                        // primero validamos aud si se ha indicado en la definicion del validator
                        if (this.aud) {
                            console.log('Validate aud');
                            if (!((_a = context.decoded) === null || _a === void 0 ? void 0 : _a.aud)) {
                                console.log("auderrunk");
                                context.validationStatus = false;
                            }
                            else {
                                if (context.decoded.aud === this.aud) {
                                    console.log("audok");
                                }
                                else {
                                    console.log("auderrdiff");
                                    context.validationStatus = false;
                                }
                            }
                        }
                        else {
                            console.log("no aud special condition present");
                        }
                        // luego iss. preguntamos por validationstatus, porque si viene a false (puede ser valido pero no cumplir aud) ya no miramos iss
                        if (context.validationStatus) {
                            if (this.iss) {
                                console.log('Validate iss');
                                if (!((_b = context.decoded) === null || _b === void 0 ? void 0 : _b.iss)) {
                                    console.log("isserrunk");
                                    context.validationStatus = false;
                                }
                                else {
                                    if (context.decoded.iss === this.iss) {
                                        console.log("issok");
                                    }
                                    else {
                                        console.log("isserrdiff");
                                        context.validationStatus = false;
                                    }
                                }
                            }
                            else {
                                console.log("no iss special condition present");
                            }
                        }
                    }
                }
                else {
                    console.log("***b2c token already decoded***");
                }
            }
            catch (err) {
                console.log("b2c decoding err");
                console.log(err);
                context.validationError = err;
                context.validationStatus = false;
            }
        };
        this.name = val.name;
        if (val.aud)
            this.aud = val.aud;
        if (val.iss)
            this.iss = val.iss;
        this.verify = val.verify;
        var openIdUrl = `https://${val.tenant}.b2clogin.com/${val.tenant}.onmicrosoft.com/${val.userflow}/v2.0/.well-known/openid-configuration`;
        axios_1.default.get(openIdUrl).then((response) => {
            this.jwksUri = response.data.jwks_uri;
            console.log(`Creating AzureB2c validator ${this.name} with jwks: ${this.jwksUri}`);
            this.cacheKeys();
            //+++if (val.schedule) cron.schedule(val.schedule, this.cacheKeys);
        })
            .catch((err) => {
            console.log("ERR");
            console.log(err);
        });
    }
    async cacheKeys() {
        console.log(`Downloading & caching keys for validator ${this.name}`);
        this.client = (0, jwks_rsa_1.default)({ jwksUri: this.jwksUri });
        var response = await axios_1.default.get(this.jwksUri);
        for (var k of response.data.keys) {
            this.client.getSigningKey(k.kid, async (err, key) => {
                if (key)
                    this.cachedSigningKeys.set(key.kid, key.getPublicKey());
            });
        }
    }
}
exports.AzureB2c = AzureB2c;
