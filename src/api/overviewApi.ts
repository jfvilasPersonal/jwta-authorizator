import express from 'express';
import { Environment } from '../model/Environment';
import { Status } from '../model/Status';

export class OverviewApi {

  public routeApi = express.Router();
  public env:Environment | undefined;
  public status:Status | undefined;

  constructor (mainEnv:Environment, mainStatus:Status) {
    this.env=mainEnv;
    this.status=mainStatus;

    this.routeApi.route('/config')
      .all(function (req, res, next) {
        res.setHeader('Content-Type', 'application/json');
        next();
      })
      .get( (req, res, next) => {
        res.end(JSON.stringify(this.env));
      })

      this.routeApi.route('/status')
      .all(function (req, res, next) {
        res.setHeader('Content-Type', 'application/json');
        next();
      })
      .get( (req, res, next) => {
        res.end(JSON.stringify(this.status));
      });

      this.routeApi.route('/validators')
      .all(function (req, res, next) {
        res.setHeader('Content-Type', 'application/json');
        next();
      })
      .get( (req, res, next) => {
        var resp= [];
        if (this.env?.obkaValidators){
          for (var val of this.env?.obkaValidators.values()) {
            resp.push ({ name:val.name, validator:val});
          }
        }
        res.end(JSON.stringify(resp));
      });

      this.routeApi.route('/rulesets')
      .all(function (req, res, next) {
        res.setHeader('Content-Type', 'application/json');
        next();
      })
      .get( (req, res, next) => {
        var resp= [];
        if (this.env?.obkaRulesets){
          for (var rs of this.env?.obkaRulesets.values()) {
            resp.push ({ name:rs.name, ruleset:rs});
          }
        }
        res.end(JSON.stringify(resp));
      });
  }

}
