"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AzureB2c = void 0;
const axios_1 = __importDefault(require("axios"));
const Basic_1 = require("./Basic");
class AzureB2c extends Basic_1.Basic {
    constructor(val) {
        super(val);
        //+++if (val.schedule) cron.schedule(val.schedule, this.cacheKeys);
        var openIdUrl = `https://${val.tenant}.b2clogin.com/${val.tenant}.onmicrosoft.com/${val.userflow}/v2.0/.well-known/openid-configuration`;
        axios_1.default.get(openIdUrl).then(async (response) => {
            this.jwksUri = response.data.jwks_uri;
            console.log(`Creating AzureB2c validator ${this.name} with jwks: ${this.jwksUri}`);
            //+++ retries
            await this.cacheKeys();
        })
            .catch((err) => {
            console.log("ERR");
            console.log(err);
        });
    }
}
exports.AzureB2c = AzureB2c;
