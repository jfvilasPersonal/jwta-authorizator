import { RequestContext } from '../model/RequestContext';
import { Validator } from '../model/Validator';
import { BasicDecoder } from './BasicDecoder';
import { ITokenDecoder } from './ITokenDecoder'

export class NullValidator extends BasicDecoder implements ITokenDecoder {
  returnValue=false;

  constructor (val:Validator, returnValue:boolean) {
    super(val);
    console.log(`Instancing NullValidator with '${returnValue}' return value`);
    this.returnValue=returnValue;
  }

  decodeAndValidateToken = async (context:RequestContext) => {
    this.totalRequests++;
    var start=process.hrtime()
    if (this.returnValue) {
      this.totalOkRequests++;
      this.applyFilter(context,context.decoded.subject,'SigninOK');
    }
    else {
      this.applyFilter(context,context.decoded.subject,'SigninError');
    }

    context.validationStatus=this.returnValue;
    
    var end=process.hrtime()
    var microSeconds = ( (end[0] * 1000000 + end[1] / 1000) - (start[0] * 1000000 + start[1] / 1000));
    this.totalMicros+=microSeconds;

  }
     
}