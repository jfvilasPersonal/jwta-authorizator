import axios from 'axios';
import jwt from 'jsonwebtoken';
import jkwsClient from 'jwks-rsa';
import { RequestContext } from '../model/RequestContext';
import { Validator } from '../model/Validator'
import { IValidator } from './IValidator'
import cron from 'node-cron';

export class AzureB2c implements IValidator {
  name!:string;
  client:any;
  jwksUri!:string;
  cachedSigningKeys:Map<string,string> = new Map();
  iss!:string;
  aud!:string;
  verify:boolean=true;


  //constructor (name: string, tenant:string,userflow:string, schedule:string) {
  constructor (val:Validator) {
    this.name=val.name;
    if (val.aud) this.aud=val.aud;
    if (val.iss) this.iss=val.iss;
    this.verify=val.verify;
    var openIdUrl = `https://${val.tenant}.b2clogin.com/${val.tenant}.onmicrosoft.com/${val.userflow}/v2.0/.well-known/openid-configuration`;
    axios.get(openIdUrl).then ( (response) => {
      this.jwksUri = response.data.jwks_uri;
      console.log(`Creating AzureB2c validator ${this.name} with jwks: ${this.jwksUri}`);
      this.cacheKeys();
      //+++if (val.schedule) cron.schedule(val.schedule, this.cacheKeys);
    })
    .catch( (err) => {
      console.log("ERR");
      console.log(err);
    });
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
        console.log("***b2c notoken***");
        return;
      } 
      if (!context.validationStatus) {
        if (this.verify) {
          const decoded = await new Promise((resolve, reject) => {
            jwt.verify(context.token as string, this.getKey, options, (err, decoded) => {
              if (err) {
                console.log("vererr");
                console.log(err);
                reject(err);
              }
              else {
                console.log("verok");
                console.log(decoded);
                resolve(decoded);
              }
            });
          });  
          context.decoded=(decoded as {});
          context.validationStatus=true; 
        }
        else {
          try {
            context.decoded = jwt.decode(context.token,options) as {};
            context.validationStatus=true; 
            console.log("decok");
          }
          catch (err) {
            context.validationStatus=false; 
            console.log("decerr");
          }
        }
        console.log('Test special conditions');

        if (context.validationStatus) {
          // primero validamos aud si se ha indicado en la definicion del validator
          if (this.aud) {
            console.log('Validate aud');
            if (!context.decoded?.aud) {
              console.log("auderrunk");
              context.validationStatus=false;
            }
            else {
              if (context.decoded.aud===this.aud) {
                console.log("audok");
              }
              else {
                console.log("auderrdiff");
                context.validationStatus=false;
              }
            }
          }
          else {
            console.log("no aud special condition present");
          }
          // luego iss. preguntamos por validationstatus, porque si viene a false (puede ser valido pero no cumplir aud) ya no miramos iss
          if (context.validationStatus) {
            if (this.iss) {
              console.log('Validate iss');
              if (!context.decoded?.iss) {
                console.log("isserrunk");
                context.validationStatus=false;
              }
              else {
                if (context.decoded.iss===this.iss) {
                  console.log("issok");
                }
                else {
                  console.log("isserrdiff");
                  context.validationStatus=false;
                }
              }
            }
            else {
              console.log("no iss special condition present");
            }
          }
        }
      }
      else {
        console.log("***b2c token already decoded***");
      }
    }
    catch (err) {
      console.log("b2c decoding err");
      console.log(err);
      context.validationError=(err as string);
      context.validationStatus=false;
    }
  }
 
  
}