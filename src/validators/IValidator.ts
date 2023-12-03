import { RequestContext } from '../model/RequestContext';

export interface IValidator {
    decodeAndValidateToken(context:RequestContext) : Promise<void>;
}
  
  