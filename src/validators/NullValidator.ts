import { RequestContext } from '../model/RequestContext';
import { Validator } from '../model/Validator';
import { Basic } from './Basic';
import { ITokenDecoder } from './ITokenDecoder'

export class NullValidator extends Basic implements ITokenDecoder {
  returnValue=false;

  constructor (val:Validator, returnValue:boolean) {
    super(val);
    console.log(`Instancing NullValidator with '${returnValue}' return value`);
    this.returnValue=returnValue;
  }

  decodeAndValidateToken = async (context:RequestContext) => {
    this.totalRequests++;
    context.validationStatus=this.returnValue;
  }
     
}