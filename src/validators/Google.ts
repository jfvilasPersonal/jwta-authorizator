import axios from 'axios';
import { Validator } from '../model/Validator';
import { IValidator } from './IValidator';
import { BasicValidator } from './BasicValidator';

export class Google extends BasicValidator implements IValidator {

  constructor (val:Validator) {
    super(val);

    var openIdUrl = `https://accounts.google.com/.well-known/openid-configuration`;
    axios.get(openIdUrl).then ( async (response) => {
      this.jwksUri = response.data.jwks_uri;
      console.log(`Creating Google validator ${this.name} with jwks: ${this.jwksUri}`);
      //+++ retries
      await this.cacheKeys();
    })
    .catch( (err) => {
      console.log("ERR");
      console.log(err);
    });
  }
  
}
