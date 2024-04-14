"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyCloak = void 0;
const axios_1 = __importDefault(require("axios"));
const BasicValidator_1 = require("./BasicValidator");
class KeyCloak extends BasicValidator_1.BasicValidator {
    constructor(val) {
        super(val);
        //+++if (val.schedule) cron.schedule(val.schedule, this.cacheKeys);
        //var openIdUrl = `https://${val.tenant}.b2clogin.com/${val.tenant}.onmicrosoft.com/${val.userflow}/v2.0/.well-known/openid-configuration`;
        //http://localhost:8080/realms/testrealm/.well-known/openid-configuration
        var openIdUrl = `${val.url}/realms/${val.realm}/.well-known/openid-configuration`;
        axios_1.default.get(openIdUrl).then(async (response) => {
            this.jwksUri = response.data.jwks_uri;
            console.log(`Creating KeyCloak validator ${this.name} with jwks: ${this.jwksUri}`);
            //+++ retries
            await this.cacheKeys();
        })
            .catch((err) => {
            console.log("ERR");
            console.log(err);
        });
    }
}
exports.KeyCloak = KeyCloak;
