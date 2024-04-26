import { RequestContext } from '../model/RequestContext';

export interface ITokenDecoder {
    decodeAndValidateToken(context:RequestContext) : Promise<void>;
}
  
  