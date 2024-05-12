import { RequestContext } from '../model/RequestContext';
import { Validator } from '../model/Validator';
import { ITokenDecoder } from './ITokenDecoder';
import { BasicDecoder } from './BasicDecoder';
import * as k8s from '@kubernetes/client-node';

export class BasicAuth extends BasicDecoder implements ITokenDecoder {
  usersdb: any = {};
  realm?: string;
  namespace:string='';
  storeSecret:string='';
  storeKey:string='';
  storeType:string='';
  coreApi?: k8s.CoreV1Api = undefined;
  users:any;

  constructor (val:Validator, coreApi:k8s.CoreV1Api, namespace:string) {
    super(val);
    this.namespace=namespace;
    this.type="basic-auth";
    this.storeType=val.storeType;
    this.realm=val.realm;
    this.users=val.users;  // these are the users read from the yaml

    if (val.storeType==='secret') {
      this.coreApi = coreApi;
      this.storeSecret=val.storeSecret;
      this.storeKey=val.storeKey;
    }
  }

  init = async () => {   
    if (this.storeType==='secret') {
      if (this.storeSecret!==undefined) {
        var ct:any = await this.coreApi?.readNamespacedSecret(this.storeSecret,this.namespace);
        var secretData = ct.body.data;
        var secret = {
          metadata: {
            name: this.storeSecret,
            namespace: this.namespace
          },
          data: {}
        };

        if (secretData===undefined) {
          console.log(`No secret '${this.storeSecret}' exists, we create an empty 'userdb' secret`);
          (secret as any).data[this.storeKey] = 'e30=';   // {} in base64
          await this.coreApi?.createNamespacedSecret(this.namespace, secret);
        }
        else {
          console.log(`Secret found, looking for key '${this.storeKey}' in secret`);
          var value = Buffer.from(secretData[this.storeKey], 'base64').toString('utf-8');
          this.usersdb=JSON.parse(value);
          console.log(`Read usersdb ${JSON.stringify(this.usersdb)}`);
        }

        if (this.users!==undefined) {
          console.log('Copying new users to usersdb');
          for (var user of this.users) {
            console.log(user);
            var u:any=user;
            if (this.usersdb[u.name]===undefined) {
              console.log(`Added ${u.name}`);
              this.usersdb[u.name]=u.password;
            }
            else {
              console.log(`Skipped ${u.name}`);
            }
          }
          console.log(`Updating usersdb in secret`);
          (secret as any).data[this.storeKey] = Buffer.from(JSON.stringify(this.usersdb), 'utf-8').toString('base64');
          await this.coreApi?.replaceNamespacedSecret(this.storeSecret,this.namespace, secret);
        }
      }
      else {
        console.log('No storeSecret provided');
        return false;
      }
    }
    else {
      // we are working with an 'inline' validator
      // we read all users from validator and store them in a simpler format:  { 'user1': 'password1' , 'user2': 'password2'... }
      if (this.users) {
        for (var usr of this.users) {
          console.log(`Adding user ${JSON.stringify(usr)}`);
          this.usersdb[(usr as any).name] = (usr as any).password;
        }
      }
    }

    console.log("Basic Atuh initialized with this usersdb:");
    console.log(this.usersdb);
    return true;
  }

  saveUsersDb = async () => {
    var secret = {
      metadata: {
        name: this.storeSecret,
        namespace: this.namespace
      },
      data: {}
    };    
    (secret as any).data[this.storeKey] = Buffer.from(JSON.stringify(this.usersdb), 'utf-8').toString('base64');
    await this.coreApi?.replaceNamespacedSecret(this.storeSecret,this.namespace, secret);
  }

  decodeAndValidateToken = async (context:RequestContext) => {
    this.totalRequests++;
    var start=process.hrtime()
    try {
      console.log("Decode token in Basic Auth");
      if (!context.token) {
        context.responseHeaders?.set("WWW-Authenticate",`Basic realm="${this.realm}"`);
        console.log(context.responseHeaders);
        context.validationStatus=false; 
      } 
      else {
        if (!context.validationStatus && this.usersdb) {
          // decode the token (it is in fact the authorization header of a basic auth)
          console.log(`Received: ${context.token}`);
          var token=context.token.trim();
          var decoded=Buffer.from(token, 'base64').toString('utf-8');
          console.log(`Decoded: ${decoded}`);
          var i =decoded.indexOf(':');
          var username=decoded.substring(0,i);
          var password=decoded.substring(i+1);

          console.log('stored: '+this.usersdb[username]);
          var blankPos=password.indexOf(' ');
          if (blankPos>=0) {
            // it's a change password request (password field contains oldPassword, blankSpace, newPassword)
            console.log("ChangePassword Request");
            var oldPassword=password.substring(0,i);
            if (this.usersdb[username]===oldPassword) {
              // this is the first step for changing password: we receive the old+blank+new password form the user but in the db is stored just the old password
              // so we update the password in the db (with old and new) and request a second step
              console.log("ChangePassword Step 1");
              console.log('store: '+password);
              this.usersdb[username]=password;
              context.responseHeaders?.set("WWW-Authenticate",`Basic realm="${this.realm}"`);
              this.totalOkRequests++;
              this.applyFilter(context,username,'ChangePasswordStep1');
            }
            else {
              // if recieve old+blank+new and stored is old+bank+new (and they match) we make no changes and keep going
              if (this.usersdb[username]===password) {
                console.log('keep going');
                context.responseHeaders?.set("WWW-Authenticate",`Basic realm="${this.realm}"`);
              }
              else {
                console.log("ChangeRequest with invalid oldpassword");
                context.responseHeaders?.set("WWW-Authenticate",`Basic realm="${this.realm}"`);
                this.applyFilter(context,username,'ChangePasswordInvalidPassword');
              }
            }
          }
          else {
            // it's a sign in request
            console.log(`Find user '${username}' with password *****`);
            if (this.usersdb[username]===password) {
              console.log("Found: "+username);
              context.decoded=username;
              this.totalOkRequests++;
              context.validationStatus=true;
              this.applyFilter(context,username,'SigninOK');
            }
            else {
              console.log('password do not match');
              var storedPassword = this.usersdb[username] as string;
              if (storedPassword===undefined) {
                console.log("User NotFound");
                context.responseHeaders?.set("WWW-Authenticate",`Basic realm="${this.realm}"`);
                this.applyFilter(context,username,'UnknownUser');
              }
              else {
                var i = storedPassword.indexOf(' ');
                if (i<0) {
                  // it is a signin where the user entered an invalid password
                  console.log("Invalid Password");
                  context.responseHeaders?.set("WWW-Authenticate",`Basic realm="${this.realm}"`);
                  this.applyFilter(context,username,'InvalidPassword');
                }
                else {
                  console.log('second step');
                  // it is a second step of a change password, that is, th user entered the new password second time and in th db is stored old+blank+new
                  var oldPassword=storedPassword.substring(0,i);
                  var newPassword=storedPassword.substring(i+1);
                  if (password===newPassword) {
                    // second step change-password is correct, we update the password, validate the access and store the usersdb
                    console.log('update password to: '+newPassword);
                    this.usersdb[username]=newPassword;
                    context.decoded=username;
                    this.totalOkRequests++;
                    context.validationStatus=true; 
                    //we only update kubernetes secret if password change is ok
                    this.saveUsersDb();
                    this.applyFilter(context,username,'PasswordUpdatedOK');
                  }
                  else {
                    // second step change-password is not correct, we restore the old password
                    console.log('restore old password to: '+oldPassword);
                    this.usersdb[username]=oldPassword;
                    this.applyFilter(context,username,'InvalidNewPassword');
                  }
                }
              }
            }
          }
        }
        else {
          console.log(`***${this.type}/${this.name} token already decoded***`);
        }
      }
    }
    catch (err) {
      console.log(`***${this.type}/${this.name} decoding err***`);
      console.log(err);
      context.validationError=(err as string);
      context.validationStatus=false;
    }

    var end=process.hrtime()
    var microSeconds = ( (end[0] * 1000000 + end[1] / 1000) - (start[0] * 1000000 + start[1] / 1000));
    console.log('ms:'+microSeconds);
    this.totalMicros+=microSeconds;

  }
  
}