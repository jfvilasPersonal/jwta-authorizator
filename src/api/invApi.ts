import express from 'express';
import { Validator } from '../model/Validator';
import { Filter } from '../model/Filter';
import { RequestContext } from '../model/RequestContext';

export class InvApi {
  public route = express.Router();
  private vals:Map<string,Validator>;

  /*
    /invalidate/subject
    /invalidate/aud
    /invalidate/iss
    /invalidate/claim
    /invalidate
  */

  constructor (validators:Map<string,Validator>) {
    this.vals=validators;

    this.route.route('/subject')
      .post( (req, res) => {
        var vname=req.body.validator;
        var subject=req.body.subject;
        var val=this.vals.get(vname);
        if (val) {
          if (!val.invalidation) val.invalidation= { subject:[], claim:[], iss:[], aud:[] }
          val.invalidation.subject.push(subject);
          res.status(200).json({ ok:true });
        }
        else {
          res.status(200).json({ ok:false, err:'valundefined'});
        }
      });

    this.route.route('/iss')
      .post( (req, res) => {
        var vname=req.body.validator;
        var iss=req.body.iss;
        var val=this.vals.get(vname);
        if (val) {
          if (!val.invalidation) val.invalidation= { subject:[], claim:[], iss:[], aud:[] }
          val.invalidation.iss.push(iss);
          res.status(200).json({ ok:true });
        }
        else {
          res.status(200).json({ ok:false, err:'valundefined'});
        }
      });

    this.route.route('/aud')
      .post( (req, res) => {
        var vname=req.body.validator;
        var aud=req.body.aud;
        var val=this.vals.get(vname);
        if (val) {
          if (!val.invalidation) val.invalidation= { subject:[], claim:[], iss:[], aud:[] }
          val.invalidation.aud.push(aud);
          res.status(200).json({ ok:true });
        }
        else {
          res.status(200).json({ ok:false, err:'valundefined'});
        }
      });

    this.route.route('/iss')
      .post( (req, res) => {
        var vname=req.body.validator;
        var claim=req.body.claim;
        var val=this.vals.get(vname);
        if (val) {
          if (!val.invalidation) val.invalidation= { subject:[], claim:[], iss:[], aud:[] }
          val.invalidation.iss.push(claim);
          res.status(200).json({ ok:true });
        }
        else {
          res.status(200).json({ ok:false, err:'valundefined'});
        }
      });

    this.route.route('/invalidate')
      .get( (req, res) => {
        var vname=req.body.validator;
        var val=this.vals.get(vname);
        if (val) {
          if (val.invalidation) 
            res.status(200).json({ ok:true, ...val.invalidation });
          else
            res.status(200).json({ ok:false, err:'noinvalidation' });
        }
        else {
          res.status(200).json({ ok:false, err:'valundefined'});
        }
      });

  }
}
