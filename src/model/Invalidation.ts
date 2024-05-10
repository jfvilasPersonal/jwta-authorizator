export class Invalidation {
    // +++ invalidations should hav a time frame (ideally >= access tiken timeout)
    enabled:boolean=false;
    claim:string[]=[];
    sub: string[]=[];
    aud:string[]=[];
    iss:string[]=[];
}