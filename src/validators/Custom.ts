import { RequestContext } from '../model/RequestContext';
import { Validator } from '../model/Validator';
import { ITokenDecoder } from './ITokenDecoder';
import { Basic } from './Basic';

export class Custom extends Basic implements ITokenDecoder {
  validFunction:boolean = false;
  authorize = function(a?:object) { return "$$INVALID$$" };

  constructor (val:Validator) {
    super(val);
    this.type="custom";

    if (val.code) {
      // we use a simple prototype function to check if code contains a valid authorize function.
      try {
        eval ("this.authorize = "+val.code.trim());
        if (this.authorize.length!==1) {
            console.log("Error, Invalid signature of authorize funciton ");
        }
        else {
            console.log("Authorize function is valid");
            this.validFunction=true;
        }
    }
    catch (ex) {
        console.log("Error, Invalid syntax on Authorize function");
        console.log(ex);
    }
}
    else {
      console.log("Error, no JavaScript code has been provided");
    }
    
  }

  decodeAndValidateToken = async (context:RequestContext) => {
    try {
      console.log("Decode token Custom");
      if (!context.validationStatus) {
        if (this.validFunction) {
          //validate token
          try {
              console.log("Invoking custom authorize function");
              var requestData= {
                uri: context.uri,
                token: context.token
              };
              context.decoded = this.authorize(requestData);
              if (context.decoded) context.validationStatus=true;
            }
            catch (ex) {
              context.validationError="Error invoking authorize function"+(ex as string);
              context.validationStatus=false;     
            }
            return;
        }
        else {
          context.validationError="No valid authorize function has been provided";
          context.validationStatus=false;     
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