#!/bin/bash -eu

declare -r DEBUG=''
declare -r TEST_NAME="${1:-}"
declare -r KEY='mypassword'
declare -r ORIGIN='./origin.txt'
declare -r MIDDLE='./middle.txt'
declare -r TARGET='./target.txt'
declare -r MIN_BLOCK_SIZE=41
declare -r BLOCK_SIZES="$MIN_BLOCK_SIZE 256"
declare -r DEFAULT_ENGINE=sequential
declare -r ENGINES="sequential threads process"
declare CURRENT_ENGINE=$DEFAULT_ENGINE
declare CURRENT_PASSWORD=

function encrypt {
    ./crypted.py $DEBUG --key $KEY --engine $CURRENT_ENGINE --encrypt $@
}

function decrypt {
    ./crypted.py $DEBUG --key $KEY --engine $CURRENT_ENGINE --decrypt $@
}

function random_password {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-32} | head -n 1
}

function setup {
    CURRENT_PASSWORD=$(random_password)
    cat > $ORIGIN  <<EOF
This is a test
   and it should result
in the same
EOF
}

function cleanup {
    rm -f $ORIGIN $MIDDLE $TARGET
}

function assert_equals {
    local origin="$1"
    local target="$2"

    diff -q $origin $target
}

function run() {
    local test="$1"

    printf "Running $test\n"
    printf "Using engine: $CURRENT_ENGINE pass: $CURRENT_PASSWORD"
    setup
    $test
    cleanup
    printf "\tOK\n"
}


function test_file_origin_or_target() {
    encrypt --origin $ORIGIN --target $MIDDLE
    decrypt --origin $MIDDLE --target $TARGET

    assert_equals $ORIGIN $TARGET
}

function test_streamed_origin_or_target() {
    cat $ORIGIN | encrypt --target $MIDDLE
    decrypt --origin $MIDDLE > $TARGET

    assert_equals $ORIGIN $TARGET
}

function test_streamed_origin_and_target() {
    cat $ORIGIN | encrypt | decrypt > $TARGET

    assert_equals $ORIGIN $TARGET
}

function test_different_block_sizes() {
    echo
    for BLOCK_SIZE in $BLOCK_SIZES; do
        echo "block size $BLOCK_SIZE"
        encrypt --block-size $BLOCK_SIZE --origin $ORIGIN --target $MIDDLE
        decrypt --block-size $BLOCK_SIZE --origin $MIDDLE --target $TARGET

        assert_equals $ORIGIN $TARGET
    done
}

function run_one() {
    local name="$1"

    run $name
}

function run_tests() {
    for CURRENT_ENGINE in $ENGINES; do
        run test_file_origin_or_target
        run test_streamed_origin_or_target
        run test_streamed_origin_and_target
        run test_different_block_sizes
    done
}


if test -z $TEST_NAME; then
    run_tests
else
    run_one $TEST_NAME
fi
echo "OK!"
