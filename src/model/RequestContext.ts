import { Rule } from "./Rule"

export type RequestContext = {
  requestUri:string,
  token?:string,
  decoded?:any,
  validationStatus?:boolean,
  validationError?:string,
  rules:Array<Rule>,
  responseHeaders:Map<string,string>
}
