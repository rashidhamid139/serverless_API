---
apiOwner: "TI/Hosting/SDE/CaaS"
language: python3
testRunner: pyunit
oasVersion: 3
isContainerized: false
webPlatform: aws-lambda
dbPlatform: null
authors:
    - Carlos Cepeda
date: 2020-12-01
---

# F5 APIs CLOUD - Local 

=====================

## What does this Product API do?

Most commonly, the term load balancing refers to distributing incoming HTTP requests across Web servers in a server farm, to avoid overloading any one server. Because load balancing distributes the requests based on the actual load at each server, it is excellent for ensuring availability and defending against denial of service attacks.

The term load balancing can also refer to file servers, when file protocol requests are distributed across file servers to overcome the capacity, bandwidth, or CPU limitations of any single system.

The developed APIs will be used for automation on IP Flow in order to configure F5 Big IP Servers on Cloud (AWS, AZURE, GCP) upon request of routing traffic to a new endpoint

## API Key features

1. Manage SSL certificated creation
2. Manage Pool and Members creation
3. Updating IRULES on default VIP for Redirect traffic
4. Updating VIPs configuration on F5 servers in HA

## Use Cases

1. Configure BigIP to route traffic:
   *  Automation on IP Flow in order to configure F5 Big IP Load Balancer Servers on Cloud (AWS, AZURE, GCP) upon request of routing traffic to a new endpoint
   *  The API is able to register a new endpoint as a member pool, create SSL Profiles and configure a default shared virtual server to route the https trafic based on the host name on the request header.
   *  The API is able to identify which F5 Server to configure based on inputs shuch as Cloud provider, Region, and Environment.

## How many endpoints

1. POST: /ingress (To route inbound traffic for a new target IP)
   * It will include create Pool, add members, create cert, create/update Irule and update VIP SSL profiles
   * It will include rollback in case failure in any of the steps to delete previously created resources

2. POST: /pool (to create a new pool with members)
   * It will be a new API
   * It will create a new pool
   * It will add members to the new created pool (if members are provided)
   * It will not add the pool to the default pool of the Shared VIP
   * It will include rollback in case failure on adding members to delete previously created pool

3. POST: /cert
   * It will Create a System Certificate (profile). PKCS or Cert & Key files have to be provided
   * It will create Client SSL and Server SSL profiles on Local depending on SSL Terminated on F5 flag
   * It will add the Client SSL and Server SSL profiles to the VIPs depending on SSL Terminated on the F5 flag. Also if Cloud provider is Azure, it will replicate this step on the second F5 Server on the HA configuration.

4. POST: /irule (to update existing IRULE)
   * This IRULE will be update by appending a section to redirect the inbound traffic based on the FQDN to a specific pool
   * It will be updating the shared IRULE for the selected F5 Server.

5. GET: /validateip (to validate if given IP belonsg to a given CIDR Block)
   * This endpoint wil be used by the IP FLOW teraform recipe in order to verify that a given IP belonsg to a given CIDR Block

## How it works

Please refer to API specifications for details about API Endpoints and API request details.
