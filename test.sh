#!/bin/bash -eu

declare -r DEBUG='-v'
declare -r KEY='mypassword'
declare -r ORIGIN='./origin.txt'
declare -r MIDDLE='./middle.txt'
declare -r TARGET='./target.txt'

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
    ./crypted.py $DEBUG --key $KEY --encrypt $@
}

function decrypt {
    ./crypted.py $DEBUG --key $KEY --decrypt $@
}


function test_file_origin_or_target() {
    echo ${FUNCNAME[0]}

    encrypt --origin $ORIGIN --target $MIDDLE
    decrypt --origin $MIDDLE --target $TARGET

    assert_equals $ORIGIN $TARGET
}

function test_streamed_origin_or_target() {
    echo ${FUNCNAME[0]}

    cat $ORIGIN | encrypt --target $MIDDLE
    decrypt --origin $MIDDLE > $TARGET

    assert_equals $ORIGIN $TARGET
}

function test_streamed_origin_and_target() {
    echo ${FUNCNAME[0]}

    cat $ORIGIN | encrypt | decrypt > $TARGET

    assert_equals $ORIGIN $TARGET
}


test_file_origin_or_target
test_streamed_origin_or_target
test_streamed_origin_and_target
echo "OK!"
