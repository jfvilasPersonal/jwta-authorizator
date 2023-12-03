"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AzureAd = void 0;
const BasicValidator_1 = require("./BasicValidator");
class AzureAd extends BasicValidator_1.BasicValidator {
    constructor(val) {
        super(val);
        this.cachedSigningKeys = new Map();
        this.jwksUri = `https://login.microsoftonline.com/${val.tenant}/discovery/v2.0/keys`;
        console.log('Creating AzureAD validator with jwks: ' + this.jwksUri);
        this.cacheKeys();
        //if (schedule) cron.schedule(schedule, this.cacheKeys);
    }
}
exports.AzureAd = AzureAd;
