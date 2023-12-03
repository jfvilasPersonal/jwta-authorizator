import axios from 'axios';
import jwt from 'jsonwebtoken';
import jkwsClient from 'jwks-rsa';
import { RequestContext } from '../model/RequestContext';
import { IValidator } from './IValidator'
import cron from 'node-cron';

export class Cognito implements IValidator {
  name!:string;
  client:any;
  jwksUri!:string;
  cachedSigningKeys:Map<string,string> = new Map();


  constructor (name: string, region:string,userPoolId:string, schedule:string) {
    this.name=name;
    this.jwksUri = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`
    console.log('Creating Cognito validator with jwks: '+this.jwksUri);
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
      //console.log('no kid found on cache');
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
        console.log("***cgn notoken***");
        return;
      } 
      if (!context.validationStatus) {
        const decoded = await new Promise((resolve, reject) => {
          jwt.verify(context.token as string, this.getKey, options, (err, decoded) => {
            if (err) {
              console.log("decerr");
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
        console.log("***cgn token already decoded***");
      }
    }
    catch (err) {
      console.log("cgn decoding err");
      console.log(err);
      context.validationError=(err as string);
      context.validationStatus=false;
    }
  }
      
}