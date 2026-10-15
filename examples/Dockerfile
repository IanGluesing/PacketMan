FROM rockylinux:9-minimal

RUN microdnf install -y \
    iproute \
    iptables \
    iputils \
    tcpdump \
    conntrack-tools \
    net-tools \
    procps-ng \
    python3 \
    vim \
    nodejs \
    npm \
    && microdnf clean all

COPY packetman-0.1.1-1.aarch64.rpm /tmp/packetman-0.1.1-1.aarch64.rpm

RUN rpm -Uvh /tmp/packetman-0.1.1-1.aarch64.rpm

CMD ["sleep", "infinity"]