# Welcome
This repo contains all source artifacts needed to create the Oberkotn authorizator component of the [Oberkorn Authorizator project](https://jfvilaspersonal.github.io/oberkorn).

## Oberkorn Authorizator project
Oberkorn authorizator is a module created for having the flexibility to deploy token validation (JWT or whatever) in front of any application project deployed on a Kubernetes cluster where the access is managed via Nginx Ingress Controller.

The Oberkorn authorizator project is made up of several components:
  - *Custom Resource Definitions*. The way an Oberkorn Authorizator can be deployed is based on kubernetes CRD's. You can see examples in the Oberkorn authorizator repositories explaning how to build and deploy an authorizator using such CRD's.
  - *Controller*. Creating CRD's is a good starting point, but for the CRD's to do something useful, you need to have a controller who can listen for CRD events (resource creation, resource modification and resource deletion). The Oberkorn controller is deployed to kubernetes as a Deployment.
  - *Authorizator*. The Authorizator is the component in charge of managing users requests and deciding, according to specs included in the CRD's, where to approve or deny access requests to web resources.

This repo contains everything you need to deploy an Oberkorn authorizator.

## Oberkorn authorizator operation
This is how an Oberkorn authorizator works:

![Data Plane](https://jfvilaspersonal.github.io/oberkorn/_media/architecture/dataplane.png)

The flow is as follows:
  1. A user request a resource (typically an API call or a static web resource like 'index.html', an image, a CSS,...).
  2. When the ingress receives the requests it routes the request to the Oberkorn authorizator.
  3. The Authorizator examines the requested URI in order to find a rule that matches that URI.
  4. If a matching rule is found, then the rule is evaluated.
  5. If the evaluation is 'true' the access is granted. If the evaluation is false, normally, the authorizator continues searching for more rules that match the requested URI (this behaviour can be customized).
  6. If the access is granted (at least a rule evaluates to 'true'), the ingress sends the request to the backend (typically a service inside the kubernetes cluster). If the response form the authorizator is 'false', a 4xx HTTP status code is sent back to the customer.

## Oberkorn authorizator creation
Follow these simple steps to have your Oberkorn authorizator created and deployed to your kubernetes cluster (please remember you must first install the Oberkorn controller and the CRD as explained [here](https://github.com/jfvilasPersonal/obk-controller)).

  1. Create the YAML describig yout authorizator needs. Following you can find a very simple (and not too much useful) authorizator defintion YAML. This authorizatror runs as follows:
     1. All resources under the URI path "/public" can be accessed anonymously, the path is not protected in any way.
     2. All resources under "/private" URI path require that the requestor presents a valid JWT token emitted by an AWS Cognito service (the one specified under 'validators' section).

```yaml
  apiVersion: jfvilas.at.outlook.com/v1
  kind: ObkAuthorizator
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
    rulesets:
      - name: general
        uriPrefix: [ '' ]
        rules:
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

## Oberkorn architecture
Oberkorn is build around two separate resources: **the controller** (in charge of the control plane) and **the authorizator** (repsonsible of the data plane). The architecture of the whole project is depicted below.

![Oberkorn architecture](https://jfvilaspersonal.github.io/oberkorn/_media/architecture/oberkorn-architecture.png)
