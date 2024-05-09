import axios from 'axios';
import { Validator } from '../model/Validator';
import { ITokenDecoder } from './ITokenDecoder';
import { BasicDecoder } from './BasicDecoder';

export class AzureB2c extends BasicDecoder implements ITokenDecoder {

  constructor (val:Validator) {
    super(val);
    //+++if (val.schedule) cron.schedule(val.schedule, this.cacheKeys);

    var openIdUrl = `https://${val.tenant}.b2clogin.com/${val.tenant}.onmicrosoft.com/${val.userflow}/v2.0/.well-known/openid-configuration`;
    axios.get(openIdUrl).then ( async (response) => {
      this.jwksUri = response.data.jwks_uri;
      console.log(`Creating AzureB2c validator ${this.name} with jwks: ${this.jwksUri}`);
      //+++ retries
      await this.cacheKeys();
    })
    .catch( (err) => {
      console.log("ERR");
      console.log(err);
    });
  }
 
  
}