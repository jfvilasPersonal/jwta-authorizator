export class Invalidation {
    // +++ invalidations should have a time frame (ideally >= access token timeout)
    enabled:boolean=false;
    claim:string[]=[];
    sub: string[]=[];
    aud:string[]=[];
    iss:string[]=[];
}