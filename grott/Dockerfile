ARG BUILD_FROM
FROM ${BUILD_FROM}

ENV LANG=C.UTF-8 \
    GROTT_DIR=/opt/grott \
    GROTT_REF=master

RUN apk add --no-cache \
        python3 \
        py3-pip \
        py3-paho-mqtt \
        py3-requests \
        py3-yaml \
        git \
        tzdata \
    && git clone --depth 1 --branch "${GROTT_REF}" \
        https://github.com/johanmeijer/grott.git "${GROTT_DIR}" \
    && rm -rf "${GROTT_DIR}/.git"

COPY run.sh /run.sh
RUN chmod a+x /run.sh

LABEL \
    org.opencontainers.image.title="Home Assistant Add-on: Grott" \
    org.opencontainers.image.description="Local proxy + MQTT bridge for Growatt solar inverters" \
    org.opencontainers.image.source="https://github.com/nalditopr/ha-grott-addon" \
    org.opencontainers.image.licenses="MIT"

CMD [ "/run.sh" ]
