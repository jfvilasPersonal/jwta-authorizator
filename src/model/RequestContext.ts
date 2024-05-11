import { Filter } from "./Filter"

export type RequestContext = {
  epoch:number,
  requestUri:string,
  token?:string,
  decoded?:any,
  validationStatus?:boolean,
  validationError?:string,
  responseHeaders:Map<string,string>,
  action?:string,
  subject?:string,
  uuid?:string
}
