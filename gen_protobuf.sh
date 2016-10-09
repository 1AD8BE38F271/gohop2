#!/usr/bin/env bash

protoc --proto_path=./protodef/ ./protodef/*.proto --go_out=./protodef/
