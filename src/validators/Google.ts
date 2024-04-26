import axios from 'axios';
import { Validator } from '../model/Validator';
import { ITokenDecoder } from './ITokenDecoder';
import { Basic } from './Basic';

export class Google extends Basic implements ITokenDecoder {

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
