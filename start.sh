#!/bin/sh

exec erl -pa $PWD/ebin $PWD/deps/*/ebin -s spood start
