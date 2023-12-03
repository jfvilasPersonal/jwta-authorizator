import { IValidator } from './IValidator';
import { BasicValidator } from './BasicValidator';
import { Validator } from '../model/Validator';

export class Cognito extends BasicValidator implements IValidator {

  constructor (val:Validator) {
    super(val);
    this.jwksUri = `https://cognito-idp.${val.region}.amazonaws.com/${val.userpool}/.well-known/jwks.json`
    console.log('Creating Cognito validator with jwks: '+this.jwksUri);
    this.cacheKeys();
    //+++if (schedule) cron.schedule(schedule, this.cacheKeys);
  }

}