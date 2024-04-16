import { IValidator } from "../validators/IValidator"

export type Validator = {
    name:string,
    type:string,

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
    
    // generales
    aud?:string,
    iss?:string,
    verify:boolean,



    url?:string,
    ivalidator:IValidator|undefined
}
