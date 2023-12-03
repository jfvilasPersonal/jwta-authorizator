import { Rule } from "./Rule"

export type RequestContext = {
  uri:string,
  token?:string,
  decoded?:any,
  validationStatus?:boolean,
  validationError?:string,
  ruleset:Array<Rule>
}
