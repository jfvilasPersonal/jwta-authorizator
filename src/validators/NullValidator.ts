import { RequestContext } from '../model/RequestContext';
import { IValidator } from './IValidator'

export class NullValidator implements IValidator {
  returnValue=false;

  constructor (returnValue:boolean) {
    console.log('Instanciado NullValidator');
    this.returnValue=returnValue;
  }

  decodeAndValidateToken = async (context:RequestContext) => {
    context.validationStatus=this.returnValue;
  }
     
}