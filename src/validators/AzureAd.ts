import { IValidator } from './IValidator';
import { BasicValidator } from './BasicValidator';
import { Validator } from '../model/Validator';

export class AzureAd extends BasicValidator implements IValidator {
  name!:string;
  client:any;
  jwksUri!:string;
  cachedSigningKeys:Map<string,string> = new Map();


  constructor (val:Validator) {
    super(val);
    this.jwksUri = `https://login.microsoftonline.com/${val.tenant}/discovery/v2.0/keys`;
    console.log('Creating AzureAD validator with jwks: '+this.jwksUri);
      this.cacheKeys();
      //if (schedule) cron.schedule(schedule, this.cacheKeys);
  }

  /*
  ***Note***:
  In order to validate signature correctly in th jwt.verify, the "scope" asked when obtaining
  the token must be the one (or ones) assigned in the "app registration" (normally, AAD adds
  "User.Read", "openid", "email",..., and this may not be correct). You shouold usually ask
  for an scopt like "api://xxxxxxxxxxxxx/read" and occasionally "openid" (to get an id token)
  and "offline_access" (to get a refresh token)
*/
 
  
}