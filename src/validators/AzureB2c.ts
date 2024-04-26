import axios from 'axios';
// import jwt from 'jsonwebtoken';
// import jkwsClient from 'jwks-rsa';
// import { RequestContext } from '../model/RequestContext';
import { Validator } from '../model/Validator';
import { ITokenDecoder } from './ITokenDecoder';
import { Basic } from './Basic';

export class AzureB2c extends Basic implements ITokenDecoder {

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