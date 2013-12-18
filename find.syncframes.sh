#!/bin/sh
perl -ln0777e 'print unpack("H*",$1), "\n", pos() while /(.....\0\0\0\0\0\x80.....)/g' $1
