import { RequestContext } from '../model/RequestContext';
import { Validator } from '../model/Validator';
import { IValidator } from './IValidator';
import { BasicValidator } from './BasicValidator';

interface User {
  name: string,
  password:string
}

export class BasicAuthList extends BasicValidator implements IValidator {
  users: User[] | undefined;
  realm: string | undefined;

  constructor (val:Validator) {
    super(val);
    this.type="basic-auth-list";
    this.users=val.users;
    this.realm=val.realm;
    console.log("Users:");
    console.log(this.users);
  }

  //+++ disponer de basicauth list con array, conconfigmap y con secret (estos ultimos permitirian cambiiar lass passwords)
  
  decodeAndValidateToken = async (context:RequestContext) => {
    try {
      console.log("decode token BAL");
      if (!context.token) {
        //if (context.responseHeaders===undefined) context.responseHeaders=new Map();
        context.responseHeaders?.set("WWW-Authenticate",`Basic realm="${this.realm}"`);
        console.log(context.responseHeaders);
        context.validationStatus=false; 
        return;
      } 
      if (!context.validationStatus) {
        // decodificar el token (que es el header authorization de basic auth)
        var decoded=Buffer.from(context.token, 'base64').toString()
        var i =decoded.indexOf(':');
        var username=decoded.substring(0,i);
        var password=decoded.substring(i);
        console.log(`Find user '${username}' with password '${password}'`);
        var user = this.users?.find( u => u.name===username && u.password === password);
        if (user!==null) {
          console.log("Found: "+user);
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