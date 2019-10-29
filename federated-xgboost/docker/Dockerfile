FROM fnndsc/ubuntu-python3

USER root
RUN apt-get update && apt-get install -y g++ dnsutils
RUN pip3 install awscli
RUN aws s3 --no-sign-request --region=us-east-2 sync s3://risecamp2019-mc2/hb /data/hb
RUN echo "alias python=python3" > $HOME/.bash_aliases; /bin/bash -c "source $HOME/.bash_aliases"
EXPOSE 9000-9100
RUN apt-get install -y vim
ENTRYPOINT bash

