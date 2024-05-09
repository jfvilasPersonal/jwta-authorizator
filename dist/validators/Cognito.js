"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Cognito = void 0;
const BasicDecoder_1 = require("./BasicDecoder");
class Cognito extends BasicDecoder_1.BasicDecoder {
    constructor(val) {
        super(val);
        this.jwksUri = `https://cognito-idp.${val.region}.amazonaws.com/${val.userpool}/.well-known/jwks.json`;
        console.log('Creating Cognito validator with jwks: ' + this.jwksUri);
        this.cacheKeys();
        //+++if (schedule) cron.schedule(schedule, this.cacheKeys);
    }
}
exports.Cognito = Cognito;
