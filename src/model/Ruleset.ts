import { Rule } from "./Rule"

export type Ruleset = {
  name:string,
  uriPrefix: Array<string>,
  rules: Array<Rule>
}
