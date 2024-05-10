import { ITokenDecoder } from "../validators/ITokenDecoder"
import { Invalidation } from "./Invalidation"
// import { Filter } from "./Filter"
// import { RequestContext } from "./RequestContext"

export type Validator = {
    // general properties
    name:string,
    type:string,
    aud?:string,
    iss?:string,
    verify:boolean,
    url?:string,
    decoderInstance:ITokenDecoder,

    // Azure
    tenant?: string,
    userflow?: string,

    // Cognito
    region?: string,
    userpool?: string,

    // Keycloak
    realm?: string,
    
    // BasicAuthList
    storeType: string,
    storeSecret: string,
    storeKey: string,
    users?: {}[],
    
    // Custom
    code: string,
    configMap: string,
    configMapkey: string,
}
