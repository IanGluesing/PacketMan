# Demos and Example Scenarios

Each scenario in this folder is used to demonstrate functionality of `packetman`. 

Every scenario consists of a `docker-compose.yml` file which dictates the container orchestration and networing for that intended scenario. 

Instructions for running each scanerio are located in the corresponding README of that example.

Helper scripts to setup networking are located in the `setup_scripts` folder.

The dockerfile that all containers are based on is located in this directory. 

The dockerfile copies and installs the current release of `packetman` into the container to allow for minimal setup to demonstrate functionality.