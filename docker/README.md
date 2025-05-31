<!--
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->
# Docker Registry 

## Artifactory

To simplify our SC prototype development, we use artifactory as our IBM internal docker registry.
The repo is available at https://eu.artifactory.swg-devops.com/artifactory/res-decentralized-trust-team-sc-docker-local/ and requires permission to use it.

### Setting up your account

First, we need to add you to the permission group.
Please contact @marcus via IBM Slack or [bur@zurich.ibm.com](bur@zurich.ibm.com).

Next, use your w3id to login at https://eu.artifactory.swg-devops.com/artifactory/res-decentralized-trust-team-sc-docker-local/.
On the top-right, click on your w3id and open ["Edit profile"](https://eu.artifactory.swg-devops.com/ui/admin/artifactory/user_profile).
Click on "Generate an Identity Token", give it a name and keep the token string somewhere at a save place. :P
You will need the token string later, to login with docker.


### Docker Login

```bash
docker login docker-eu.artifactory.swg-devops.com
// please use your w3id as user and the token as pasword
```

### Work with the Docker Registry

In this example, we illustrate how to pull and push the `sc_runner` docker image from our artifactory.

#### Pull
```bash
docker pull docker-eu.artifactory.swg-devops.com/res-decentralized-trust-team-sc-docker-local/sc_runner:latest
docker tag docker-eu.artifactory.swg-devops.com/res-decentralized-trust-team-sc-docker-local/sc_runner:latest sc_runner:latest
```

#### Push
```bash
docker tag sc_runner:latest docker-eu.artifactory.swg-devops.com/res-decentralized-trust-team-sc-docker-local/sc_runner:latest
docker push docker-eu.artifactory.swg-devops.com/res-decentralized-trust-team-sc-docker-local/sc_runner:latest
```

## Run Image
The image contains the binaries, default config files, and a script that runs all services (including the DB). To run it, we need to:
* map the sidecar port
* mount the endorser key on `/root/pubkey/sc_pubkey.pem`
* mount the crypto material (preferably on `/root/config/crypto/`, as this is used in the default configs)
* optionally override config properties using environment variables.

For example:
```shell
docker run \
    -p 5050:5050 \
    -v config/sidecar-machine/fabric.mytopos/crypto/peerOrganizations/defaultpeerorg.example.com/peers/endorser-1.defaultpeerorg.example.com/tss/endorser/msp/signcerts/endorser-cert.pem:/root/pubkey/sc_pubkey.pem \
    -v config/sidecar-machine/fabric.mytopos/crypto/:/root/config/crypto/ \
    -e SC_SIDECAR_ORDERER_ORDERER_CONNECTION_PROFILE_MSP_DIR="/root/config/crypto/peerOrganizations/defaultpeerorg.example.com/peers/peerservice-machine1.defaultpeerorg.example.com/msp" \
    -e SC_SIDECAR_ORDERER_ORDERER_CONNECTION_PROFILE_ROOT_CA_PATHS="/root/config/crypto/ca-certs.pem" \
    -e SC_SIDECAR_ORDERER_CHANNEL_ID="mychannel" \
    -e SC_SIDECAR_ORDERER_ENDPOINT=":7050" \
    -e METANS_SIG_SCHEME="ECDSA" \
    sc_runner:latest
```
