import { RequestContext } from '../model/RequestContext';
import { Validator } from '../model/Validator';
import { IValidator } from './IValidator';
import { BasicValidator } from './BasicValidator';

interface User {
  name: string,
  password:string
}

export class BasicAuthList extends BasicValidator implements IValidator {
  users:User[] | undefined;

  constructor (val:Validator) {
    super(val);
    this.users=val.users;
    console.log("Users:");
    console.log(this.users);
  }

  decodeAndValidateToken = async (context:RequestContext) => {
    try {
      // the token contains the value of the header authorization
      if (!context.token) {
        console.log(`***${this.type}/${this.name} Authorization***`);
        return;
      } 
      if (!context.validationStatus) {
        if (this.verify) {
          // decodificar el token (que es el header authorization de basic auth)
          var decoded=Buffer.from(context.token, 'base64').toString()
          var i =decoded.indexOf(':');
          var username=decoded.substring(0,i);
          var password=decoded.substring(i);
          console.log(`Find user '${username}' with password '${password}'`);
          var user = this.users?.find( u => u.name===username && u.password === password);
          if (user!==null) {
            console.log("Found");
            console.log(user);
            context.decoded=username;
          }
          else {
            console.log("NotFound");
          }
          context.validationStatus=true; 
          return;
        }
        else {
            context.validationStatus=true; 
            console.log("decok");
            return;
          }
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