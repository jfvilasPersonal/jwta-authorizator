import express, { Request, Response } from 'express';
import { Environment } from '../model/Environment';

export class ConfigApi {

  public routeApi = express.Router();
  public env:Environment | undefined;

  constructor (mainEnv:Environment) {
    this.env=mainEnv;

    this.routeApi.route('/config')
      .all(function (req, res, next) {
        res.setHeader('Content-Type', 'application/json');
        next();
      })
      .get( (req, res, next) => {
        var resp:any={};
        resp.name=this.env?.obkaName;
        resp.namespace=this.env?.obkaNamespace;
        resp.console=this.env?.obkaConsole;
        resp.api=this.env?.obkaApi;
        resp.prometheus=this.env?.obkaPrometheus;
        res.end(JSON.stringify(resp));
      })
      .put( (req, res, next) => {
        console.log(req.body);
        var payload=req.body;
        //var payload=JSON.parse(req.body);
        if (payload.prometheus && this.env) this.env.obkaPrometheus=payload.prometheus;

        // just an example of maybe updating the user
        // req.user.name = req.params.name
        // // save user ... etc
        // res.json(req.user)
        res.status(200).send('Ok');
      })
    .post( (req, res, next) => {
        var resp:any={};
        resp.name=this.env?.obkaName;
        resp.namespace=this.env?.obkaNamespace;
        resp.console=this.env?.obkaConsole;
        resp.api=this.env?.obkaApi;
        resp.prometheus=this.env?.obkaPrometheus;
        res.end(JSON.stringify(resp));
      });
        
  }

}
