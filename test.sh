#!/bin/bash -eu

declare -r DEBUG=''
declare -r KEY='mypassword'
declare -r ORIGIN='./origin.txt'
declare -r MIDDLE='./middle.txt'
declare -r TARGET='./target.txt'
declare -r ENGINES="sequential threads process"

cat > $ORIGIN  <<EOF
This is a test
   and it should result
in the same
EOF


function assert_equals {
    local origin="$1"
    local target="$2"

    diff -q $origin $target
}


function encrypt {
    ./crypted.py $DEBUG --key $KEY --engine $CURRENT_ENGINE --encrypt $@
}

function decrypt {
    ./crypted.py $DEBUG --key $KEY --engine $CURRENT_ENGINE --decrypt $@
}


function test_file_origin_or_target() {
    echo ${FUNCNAME[0]} using $CURRENT_ENGINE

    encrypt --origin $ORIGIN --target $MIDDLE
    decrypt --origin $MIDDLE --target $TARGET

    assert_equals $ORIGIN $TARGET
}

function test_streamed_origin_or_target() {
    echo ${FUNCNAME[0]} using $CURRENT_ENGINE

    cat $ORIGIN | encrypt --target $MIDDLE
    decrypt --origin $MIDDLE > $TARGET

    assert_equals $ORIGIN $TARGET
}

function test_streamed_origin_and_target() {
    echo ${FUNCNAME[0]} using $CURRENT_ENGINE

    cat $ORIGIN | encrypt | decrypt > $TARGET

    assert_equals $ORIGIN $TARGET
}


for CURRENT_ENGINE in $ENGINES; do
    test_file_origin_or_target
    test_streamed_origin_or_target
    test_streamed_origin_and_target
done
echo "OK!"
