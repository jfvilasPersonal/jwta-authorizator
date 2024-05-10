import { Filter } from '../model/Filter';
import { Invalidation } from '../model/Invalidation';
import { RequestContext } from '../model/RequestContext';

export interface ITokenDecoder {
    decodeAndValidateToken(context:RequestContext) : Promise<void>;
    filter:Filter;
    invalidation:Invalidation;
}
  
  