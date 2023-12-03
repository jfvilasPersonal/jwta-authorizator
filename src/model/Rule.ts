export type Rule = {
    uri: string,
    uritype: string,
    type:string,
    policy:string,
    options:Array<string>,
    name:string,
    values:Array<any>,
    subset:Array<Rule>,
    validators:Array<string>
  }
