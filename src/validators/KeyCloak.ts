import axios from 'axios';
import { Validator } from '../model/Validator';
import { ITokenDecoder } from './ITokenDecoder';
import { BasicDecoder as BasicDecoder } from './BasicDecoder';

export class KeyCloak extends BasicDecoder implements ITokenDecoder {

  constructor (val:Validator) {
    super(val);
    //+++if (val.schedule) cron.schedule(val.schedule, this.cacheKeys);

    var openIdUrl = `${val.url}/realms/${val.realm}/.well-known/openid-configuration`;
    axios.get(openIdUrl).then ( async (response) => {
      this.jwksUri = response.data.jwks_uri;
      console.log(`Creating KeyCloak validator ${this.name} with jwks: ${this.jwksUri}`);
      //+++ retries
      await this.cacheKeys();
    })
    .catch( (err) => {
      console.log("ERR");
      console.log(err);
    });
  }
 
}