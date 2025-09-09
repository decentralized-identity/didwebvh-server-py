# DID WebVH Server Demo

## Pre-requisite

### Docker compose

Ensure you have docker compose installed. This can be verified with the following command.
`docker compose --version`

Instructions on how to install docker compose can be found here
https://docs.docker.com/compose/install/

### NGROK

We strongly recommend setting up a free ngrok account prior to going through this demo.

You can signup here:
https://dashboard.ngrok.com/

Once your account is created, you need to setup a free static endpoint and grab your API key.

You can setup a free static domain in the domain section once logged in:
https://dashboard.ngrok.com/domains

To get an API key, go to the API key section:
https://dashboard.ngrok.com/api-keys

Once you have your static domain and your API, proceed with the demo.

## Setting up you local deployments

Start by cloning the repository
```bash
git clone https://github.com/identity-foundation/didwebvh-server-py.git
cd didwebvh-server-py/demo/
```

Create your `.env` file and fill in the value using your ngrok account
`cp .env-demo .env`

Build and start the service
`docker compose up --build`

This will run the server along with an acapy agent and run a script to provision some dids/resources.

You can visit the webvh explorer at your ngrok domain `/explorer`.