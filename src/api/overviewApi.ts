import express from 'express';
import { Environment } from '../model/Environment';
import { Status } from '../model/Status';

export class OverviewApi {

  public route = express.Router();
  public env:Environment | undefined;
  public status:Status | undefined;

  constructor (mainEnv:Environment, mainStatus:Status) {
    this.env=mainEnv;
    this.status=mainStatus;

    this.route.route('/config')
      .get( (req, res) => {
        res.json(this.env);
      })

    this.route.route('/status')
      .get( (req, res) => {
        res.json(this.status);
      });

    this.route.route('/validators')
      .get( (req, res) => {
        var resp= [];
        if (this.env?.obkaValidators){
          for (var val of this.env?.obkaValidators.values()) {
            resp.push (val);
          }
        }
        res.json(resp);
      });

    this.route.route('/rulesets')
      .get( (req, res) => {
        var resp= [];
        if (this.env?.obkaRulesets){
          for (var rs of this.env?.obkaRulesets.values()) {
            resp.push ({ name:rs.name, ruleset:rs});
          }
        }
        res.json(resp);
      });
  }

}
