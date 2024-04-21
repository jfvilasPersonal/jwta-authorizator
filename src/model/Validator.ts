import { IValidator } from "../validators/IValidator"

export type Validator = {
    // general properties
    name:string,
    type:string,
    aud?:string,
    iss?:string,
    verify:boolean,
    url?:string,
    ivalidator:IValidator|undefined,

    // Azure
    tenant?: string,
    userflow?: string,

    // Cognito
    region?: string,
    userpool?: string,

    // Keycloak
    realm?: string,
    
    // BasicAuthList
    users?: [],
    
    // Custom
    code: string,
    configMap: string,
    key: string
    
}
