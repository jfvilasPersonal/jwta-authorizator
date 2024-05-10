import axios from 'axios';
import jwt from 'jsonwebtoken';
import jkwsClient from 'jwks-rsa';
import { RequestContext } from '../model/RequestContext';
import { Validator } from '../model/Validator'
import { Filter } from '../model/Filter';
import { ITokenDecoder } from './ITokenDecoder';
import { Invalidation } from '../model/Invalidation';

export class BasicDecoder implements ITokenDecoder{
  name!:string;
  type!:string;
  //client:any; //+++ ¿?
  jwksUri!:string;
  cachedSigningKeys:Map<string,string> = new Map();
  iss!:string;
  aud!:string;
  verify:boolean=true;
  totalRequests:number=0;
  totalOkRequests:number=0;
  filter:Filter;
  invalidation:Invalidation;
  
  constructor (val:Validator) {
    console.log('ctor.name:'+val.name);
    console.log('ctor.type:'+val.type);
    this.name=val.name;
    this.type=val.type;
    if (val.aud) this.aud=val.aud;
    if (val.iss) this.iss=val.iss;
    this.verify=val.verify;
    this.filter=new Filter();
    this.invalidation=new Invalidation();
  }

  public applyFilter(rc:RequestContext, sub?:string, action?:string) {
    if (this.filter) {
      if (sub!==undefined && this.filter.subject===sub) {
        rc.action=action;
        this.filter.events.push(rc);
      }
    }
  }

  public async cacheKeys() {
    console.log(`Downloading & caching keys for validator ${this.type}/${this.name}`);
    //this.client = jkwsClient({ jwksUri: this.jwksUri })
    var client = jkwsClient({ jwksUri: this.jwksUri })
    var response = await axios.get(this.jwksUri);

    for (var k of response.data.keys) {
      client.getSigningKey(k.kid, async (err:any, key:any) => {
        if (key) this.cachedSigningKeys.set(key.kid,key.getPublicKey());
      });
    }
  }


  public testSpecialConditions = (context:RequestContext) => {
    console.log('Test special conditions');

    if (context.validationStatus) {
      // First, we check AUD conditions (if something has been detailed in validator definition
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
      // then check ISS. First we check validationStatus, since it can be set to false after checkin AUD conditions, in such a case we don't check for ISS
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


  public getKey = async  (header:any, callback:any) => {
    if (this.cachedSigningKeys && this.cachedSigningKeys.has(header.kid)) {
      callback(null, this.cachedSigningKeys.get(header.kid));
    }
    else {
      callback('no kid found on cache');
    }
  } 


  public decodeAndValidateToken = async (context:RequestContext) => {
    try {
      this.totalRequests++;
  
      if (!context.token) {
        console.log("***b2c notoken***");
        return;
      } 
      if (!context.validationStatus) {
        if (this.verify) {
          const decoded = await new Promise((resolve, reject) => {
            jwt.verify(context.token as string, this.getKey, {}, (err, decoded) => {
              if (err) {
                console.log("vererr");
                console.log(err);
                this.applyFilter(context,undefined,'VerifyError');
                reject(err);
              }
              else {
                console.log("verok");
                console.log(decoded);
                this.totalOkRequests++;
                resolve(decoded);
              }
            });
          });
          context.decoded=(decoded as {});
          context.validationStatus=true; 
          this.totalOkRequests++;
          this.applyFilter(context,context.decoded.subject,'SigninOK');
        }
        else {
          try {
            context.decoded = jwt.decode(context.token,{}) as {};
            context.validationStatus=true; 
            this.totalOkRequests++;
            this.applyFilter(context,context.decoded.subject,'SigninOK');
            console.log("decok");
          }
          catch (err) {
            context.validationStatus=false; 
            this.applyFilter(context,undefined,'DecodeError');
            console.log("decerr");
          }
        }

        this.testSpecialConditions(context);
      }
      else {
        console.log(`***${this.type}/${this.name} token already decoded***`);
      }
    }
    catch (err) {
      console.log(`***${this.type}/${this.name} decoding err***`);
      console.log(err);
      context.validationError=(err as string);
      context.validationStatus=false;
    }
  }

}