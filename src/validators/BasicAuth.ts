import { RequestContext } from '../model/RequestContext';
import { Validator } from '../model/Validator';
import { ITokenDecoder } from './ITokenDecoder';
import { Basic } from './Basic';

export class BasicAuth extends Basic implements ITokenDecoder {
  usersdb: any = {};
  realm: string | undefined;

  constructor (val:Validator, usersdb:{}) {
    super(val);
    this.type="basic-auth";
    this.usersdb=usersdb;
    this.realm=val.realm;
    console.log("Starting usersdb:");
    console.log(this.usersdb);
  }

  decodeAndValidateToken = async (context:RequestContext) => {
    try {
      this.totalRequests++;
      console.log("decode token BAL");
      if (!context.token) {
        //if (context.responseHeaders===undefined) context.responseHeaders=new Map();
        context.responseHeaders?.set("WWW-Authenticate",`Basic realm="${this.realm}"`);
        console.log(context.responseHeaders);
        context.validationStatus=false; 
        return;
      } 
      if (!context.validationStatus) {
        // decode the token (it is in fact the authorization header of a basic auth)
        console.log(`Received: ${context.token}`);
        var token=context.token.trim();
        // no needed if (token.startsWith('Basic ')) token=token.substring(6);
        var decoded=Buffer.from(token, 'base64').toString('utf-8');
        console.log(`Decoded: ${decoded}`);
        var i =decoded.indexOf(':');
        var username=decoded.substring(0,i);
        var password=decoded.substring(i+1);

        console.log(`Find user '${username}' with password *****`);
        if (this.usersdb && this.usersdb[username]===password) {
          console.log("Found: "+username);
          context.decoded=username;
          context.validationStatus=true; 
        }
        else {
          console.log("NotFound");
          if (context.responseHeaders===null) context.responseHeaders=new Map();
          context.responseHeaders?.set("WWW-Authenticate",`Basic realm="${this.realm}"`);
        }
        return;
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