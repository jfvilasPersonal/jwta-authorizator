# Welcome
This repo contains all source artifacts needed to create the JWTA-Authorizator component of the [JWT Authorizator project](https://jfvilaspersonal.github.io/jwtauthorizator).

## JWT Authorizator project
JWT Authorizator is a module created for having the flexibility to deploy JWT validation in front of any application project deployed on a Kubernetes cluster where the access is managed via Nginx Ingress Controller.

The JWT Authorizator project is made up of several components:
  - *Custom Resource Definitions*. The way a JWT Authorizator can be deployed is based on kubernetes CRD's. You can see examples in the JWT Authorizator repositories explaning how to build and deploy an authorizator using such CRD's.
  - *Controller*. Creating CRD's is a good starting point, but for the CRD's to do something useful, you need to have a controller who can listen for CRD events (resource creation, resource modification and resource deletion). The JWT Authorizator controller is deployed to kubernetes as a Deployment.
  - *Authorizator*. The Authorizator is the component in charge of managing users requests and deciding, according to specs included in the CRD's, where to approve or deny access requests to web resources.

This repo contains everything you need to deploy a JWTA Authorizator.

## JWTA authorizator operation
>Explain how JWTA authorizator works.

## JWTA authorizator architecture
>Small explanation of JWTA authorizator architecture.

## JWTA authorizator creation
Follow these simple steps to have your JWTA authorizator created and deployed to your kubernetes cluster (please remember you must first install the JWTA Controller and the CRD as explained [here](https://github.com/jfvilasPersonal/jwta-controller)).

  1. Create the YAML describig yout authorizator needs. Following you can find a very simple (and not too much useful) authorizator defintion YAML. This authorizatror runs as follows:
     1. All resources under the URI path "/public" can be accessed anonymously, the path is not protected in any way.
     2. All resources under "/private" URI path require that the requestor presents a valid JWT token emitted by an AWS Cognito service (the one specified under 'validators' section).

```yaml
  apiVersion: jfvilas.at.outlook.com/v1
  kind: JwtAuthorizator
  metadata:
    name: simple-authorizator
    namespace: test
  spec:
    ingress:
      name: sample-nginx-ingress
      class: nginx
    validators:
      - cognito:
          name: cognito-validator
          region: eu-west-1
          userpool: eu-west-1_abcdefg
    ruleset:
      # all resurces under /public can be accessed (access is unrestricted)
      - uri: "/public/"
        uritype: "prefix"
        type: "unrestricted"
      # all resurces under /private require a valid JWT token emitted by the cognito validator
      - uri: "/private/"
        uritype: "prefix"
        type: "valid"
```

  2. Apply the YAML
        `kubectl apply -f your-application-authorizator.yaml`
       
**That's it!**
