import { ITokenDecoder } from './ITokenDecoder';
import { BasicDecoder } from './BasicDecoder';
import { Validator } from '../model/Validator';

export class Cognito extends BasicDecoder implements ITokenDecoder {

  constructor (val:Validator) {
    super(val);
    this.jwksUri = `https://cognito-idp.${val.region}.amazonaws.com/${val.userpool}/.well-known/jwks.json`
    console.log('Creating Cognito validator with jwks: '+this.jwksUri);
    this.cacheKeys();
    //+++if (schedule) cron.schedule(schedule, this.cacheKeys);
  }

}