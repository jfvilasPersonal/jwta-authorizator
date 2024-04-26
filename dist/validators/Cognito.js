"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Cognito = void 0;
const Basic_1 = require("./Basic");
class Cognito extends Basic_1.Basic {
    constructor(val) {
        super(val);
        this.jwksUri = `https://cognito-idp.${val.region}.amazonaws.com/${val.userpool}/.well-known/jwks.json`;
        console.log('Creating Cognito validator with jwks: ' + this.jwksUri);
        this.cacheKeys();
        //+++if (schedule) cron.schedule(schedule, this.cacheKeys);
    }
}
exports.Cognito = Cognito;
