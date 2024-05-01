"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AzureAd = void 0;
const Basic_1 = require("./Basic");
class AzureAd extends Basic_1.Basic {
    constructor(val) {
        super(val);
        this.cachedSigningKeys = new Map();
        this.jwksUri = `https://login.microsoftonline.com/${val.tenant}/discovery/v2.0/keys`;
        console.log('Creating AzureAD validator with jwks: ' + this.jwksUri);
        this.cacheKeys();
        //+++if (schedule) cron.schedule(schedule, this.cacheKeys);
    }
}
exports.AzureAd = AzureAd;
