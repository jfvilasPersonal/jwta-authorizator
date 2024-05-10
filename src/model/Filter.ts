import { RequestContext } from "./RequestContext"

export class Filter {
  status:boolean=false;
  subject?:string;
  aud?:string;
  iss?:string;
  maxEvents:number=0;
  events:RequestContext[]=[];
}
