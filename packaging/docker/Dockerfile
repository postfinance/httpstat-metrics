FROM gcr.io/distroless/static-debian11:latest as runtime
LABEL maintainer="OpenSource PF <opensource@postfinance.ch>"

COPY httpstat-metrics /httpstat-metrics
USER 65534

CMD ["/httpstat-metrics"]