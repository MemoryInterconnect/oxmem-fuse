#!/bin/bash

sudo kill -9 `ps aux | grep oxmem-mount | head -n 3 | awk '{print $2}'`
