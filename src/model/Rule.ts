import { Filter } from "./Filter"

export type Rule = {
  uri: string|undefined,
  uris: string[],
  uritype: string,
  type:string,
  name:string,
  policy:string,
  options:Array<string>,
  ontrue:string,
  onfalse:string,
  values:Array<any>,
  subset:Array<Rule>,
  validators:Array<string>,

  // stats
  totalExecuted:number,
  totalValid:number
}
