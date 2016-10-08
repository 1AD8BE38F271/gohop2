#!/usr/bin/env bash

protoc --proto_path=./proto/ ./proto/*.proto --go_out=./proto/
