"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Cognito = void 0;
const BasicValidator_1 = require("./BasicValidator");
class Cognito extends BasicValidator_1.BasicValidator {
    constructor(val) {
        super(val);
        this.jwksUri = `https://cognito-idp.${val.region}.amazonaws.com/${val.userpool}/.well-known/jwks.json`;
        console.log('Creating Cognito validator with jwks: ' + this.jwksUri);
        this.cacheKeys();
        //+++if (schedule) cron.schedule(schedule, this.cacheKeys);
    }
}
exports.Cognito = Cognito;
