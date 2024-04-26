import { RequestContext } from '../model/RequestContext';
import { ITokenDecoder } from './ITokenDecoder'

export class NullValidator implements ITokenDecoder {
  returnValue=false;

  constructor (returnValue:boolean) {
    console.log('Instancing NullValidator');
    this.returnValue=returnValue;
  }

  decodeAndValidateToken = async (context:RequestContext) => {
    context.validationStatus=this.returnValue;
  }
     
}