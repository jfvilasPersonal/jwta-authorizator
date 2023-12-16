export type Rule = {
    uri: string,
    uritype: string,
    type:string,
    name:string,
    policy:string,
    options:Array<string>,
    ontrue:string,
    onfalse:string,
    values:Array<any>,
    subset:Array<Rule>,
    validators:Array<string>
  }
