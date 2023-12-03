"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Cognito = void 0;
const axios_1 = __importDefault(require("axios"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const jwks_rsa_1 = __importDefault(require("jwks-rsa"));
const node_cron_1 = __importDefault(require("node-cron"));
class Cognito {
    constructor(name, region, userPoolId, schedule) {
        this.cachedSigningKeys = new Map();
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
            try {
                const options = {
                //audience: [applicationId],
                //issuer: [issuerUri]
                };
                if (!context.token) {
                    console.log("***cgn notoken***");
                    return;
                }
                if (!context.validationStatus) {
                    const decoded = await new Promise((resolve, reject) => {
                        jsonwebtoken_1.default.verify(context.token, this.getKey, options, (err, decoded) => {
                            if (err) {
                                console.log("decerr");
                                reject(err);
                            }
                            else {
                                console.log("dec");
                                console.log(decoded);
                                resolve(decoded);
                            }
                        });
                    });
                    context.decoded = decoded;
                    context.validationStatus = true;
                }
                else {
                    console.log("***cgn token already decoded***");
                }
            }
            catch (err) {
                console.log("cgn decoding err");
                console.log(err);
                context.validationError = err;
                context.validationStatus = false;
            }
        };
        this.name = name;
        this.jwksUri = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;
        console.log('Creating Cognito validator with jwks: ' + this.jwksUri);
        this.cacheKeys();
        if (schedule)
            node_cron_1.default.schedule(schedule, this.cacheKeys);
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
exports.Cognito = Cognito;
