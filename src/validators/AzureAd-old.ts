import axios from 'axios';
import jwt from 'jsonwebtoken';
import jkwsClient from 'jwks-rsa';
import { RequestContext } from '../model/RequestContext';
import { IValidator } from './IValidator'
import cron from 'node-cron';

export class AzureAd implements IValidator {
  name!:string;
  client:any;
  jwksUri!:string;
  cachedSigningKeys:Map<string,string> = new Map();


  constructor (name: string, tenant:string, schedule:string) {
    this.name=name;
    this.jwksUri = `https://login.microsoftonline.com/${tenant}/discovery/v2.0/keys`;
    console.log('Creating AzureAD validator with jwks: '+this.jwksUri);
      this.cacheKeys();
      if (schedule) cron.schedule(schedule, this.cacheKeys);
  }


  async cacheKeys() {
    console.log(`Downloading & caching keys for validator ${this.name}`);
    this.client = jkwsClient({ jwksUri: this.jwksUri })
    var response = await axios.get(this.jwksUri);

    for (var k of response.data.keys) {
      this.client.getSigningKey(k.kid, async (err:any, key:any) => {
        if (key) this.cachedSigningKeys.set(key.kid,key.getPublicKey());
      });
    }
  }


  private getKey = async  (header:any, callback:any) => {
    if (this.cachedSigningKeys && this.cachedSigningKeys.has(header.kid)) {
      callback(null, this.cachedSigningKeys.get(header.kid));
    }
    else {
      callback('no kid found on cache');
    }
  } 


  decodeAndValidateToken = async (context:RequestContext) => {
    try {
      const options = {
        //audience: [applicationId],
        //issuer: [issuerUri]
      };
  
      if (!context.token) {
        console.log("***AD notoken***");
        return;
      } 
      if (!context.validationStatus) {
        const decoded = await new Promise((resolve, reject) => {
          /*
            ***Note***:
            In order to validate signature correctly in th jwt.verify, the "scope" asked when obtaining
            the token must be the one (or ones) assigned in the "app registration" (normally, AAD adds
            "User.Read", "openid", "email",..., and this may not be correct). You shouold usually ask
            for an scopt like "api://xxxxxxxxxxxxx/read" and occasionally "openid" (to get an id token)
            and "offline_access" (to get a refresh token)
          */
          jwt.verify(context.token as string, this.getKey, options, (err, decoded) => {
            if (err) {
              console.log("decerr");
              console.log(err);
              reject(err);
            }
            else {
              console.log("dec");
              console.log(decoded);
              resolve(decoded);
            }
          });
        });  
        context.decoded=(decoded as {});
        context.validationStatus=true;
      }
      else {
        console.log("***AD token already decoded***");
      }
    }
    catch (err) {
      console.log("AD decoding err");
      console.log(err);
      context.validationError=(err as string);
      context.validationStatus=false;
    }
  }
 
  
}