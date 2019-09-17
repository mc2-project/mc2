#!/bin/bash

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -m|--worker-memory)
    WORKER_MEMORY="$2"
    shift # past argument
    shift # past value
    ;;
    -p|--num-parties)
    PARTIES="$2"
    shift # past argument
    shift # past value
    ;;
    -d|--dir)
    SYNC_DST_DIR="$2"
    shift # past argument
    shift # past value
    ;;
    -j|--job)
    JOB="$2"
    shift # past argument
    shift # past value
    ;;
    --default)
    DEFAULT=YES
    shift # past argument
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

../../dmlc-core/tracker/dmlc-submit --cluster ssh --num-workers ${PARTIES} --host-file hosts.config --worker-memory ${WORKER_MEMORY} --sync-dst-dir ${SYNC_DST_DIR} python3 ${JOB}
