#! /bin/bash

sudo rmmod lisakmod
sudo insmod /tmp/lisakmod.ko
sudo /tmp/kmodtest


