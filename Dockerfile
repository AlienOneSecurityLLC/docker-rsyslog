FROM registry.access.redhat.com/rhel7.5

LABEL version="0.1"

LABEL description="Rsyslog 8.36.0 - RHEL 7.5 Container"

ENV RSYSLOG_VERSION 8.36.0-3.el7.x86_64

ENV container=docker

RUN yum -y install lsof wget net-tools

RUN rpm --import http://rpms.adiscon.com/RPM-GPG-KEY-Adiscon

RUN cd /etc/yum.repos.d/;wget http://rpms.adiscon.com/v8-stable/rsyslog.repo

RUN yum install rsyslog

# Install confd
ARG CONFD_VER='0.16.0'
#ADD https://github.com/kelseyhightower/confd/releases/download/v${CONFD_VER}/confd-${CONFD_VER}-linux-amd64 /usr/local/bin/confd
COPY usr/local/bin/confd-${CONFD_VER}-linux-amd64 /usr/local/bin/confd
  # Use bundled file to avoid downloading all the time
RUN chmod +x /usr/local/bin/confd && \
  mkdir -p /etc/confd/conf.d && \
  mkdir -p /etc/confd/templates

# Copy rsyslog config templates (for confd)
COPY etc/confd /etc/confd

# Copy rsyslog config files and create folders for template config
COPY etc/rsyslog.conf /etc/rsyslog.conf
COPY etc/rsyslog.d/input/ /etc/rsyslog.d/input/
COPY etc/rsyslog.d/output/ /etc/rsyslog.d/output/
# Directories intended as optional volume mounted config
RUN mkdir -p \
  /etc/rsyslog.d/input/filters \
  /etc/rsyslog.d/output/filters \
  /etc/rsyslog.d/extra
# Note:
# - rsyslog.d/input/filters is a volume used for addtional input filters that fit into pre-defined templated inputs
# - rsyslog.d/output/filters is a volume used for addtional output filters that fit into pre-defined templated outputs
# - rsyslog.d/extra is a volume used for unforseen custom config

# Copy a default self-signed cert and key - this is INSECURE and for testing/build purposes only
# - To help handle cases when the rsyslog tls volume doesn't have expected files present
# - rsyslog.sh entrypoint script will symlink and use these defaults if not provided in a volume
# - For production, avoid insecure default by providing an /etc/pki/rsyslog volume provisioned with your own keys and certficates
RUN mkdir -p usr/local/etc/pki/test
COPY usr/local/etc/pki/test/test_ca.cert.pem /usr/local/etc/pki/test
COPY usr/local/etc/pki/test/test_syslog_server.key.pem /usr/local/etc/pki/test
COPY usr/local/etc/pki/test/test_syslog_server.cert.pem /usr/local/etc/pki/test

# Default ENV vars for rsyslog config

# TLS related globals
ENV rsyslog_global_ca_file='/etc/pki/tls/certs/ca-bundle.crt' \
  rsyslog_server_cert_file='/etc/pki/rsyslog/cert.pem' \
  rsyslog_server_key_file='/etc/pki/rsyslog/key.pem'

# Inputs and parsing inputs
ENV rsyslog_global_maxmessagesize=65536 \
  rsyslog_parser='["rsyslog.rfc5424", "custom.rfc3164"]' \
  rsyslog_pmrfc3164_force_tagEndingByColon='off' \
  rsyslog_pmrfc3164_remove_msgFirstSpace='on' \
  rsyslog_global_parser_permitslashinprogramname='on' \
  rsyslog_global_parser_escapecontrolcharactertab='off' \
  rsyslog_global_preservefqdn='on' \
  rsyslog_mmpstrucdata='on' \
  rsyslog_mmjsonparse='on' \
  rsyslog_mmjsonparse_without_cee='off' \
  rsyslog_support_metadata_formats='off' \
  rsyslog_input_filtering_enabled='on' \
  rsyslog_module_impstats_interval='60' \
  rsyslog_module_impstats_resetcounters='on' \
  rsyslog_module_impstats_format='cee' \
  rsyslog_impstats_ruleset='output' \
  rsyslog_global_action_reportSuspension='on' \
  rsyslog_global_senders_keeptrack='on' \
  rsyslog_global_senders_timeoutafter='86400' \
  rsyslog_global_senders_reportgoneaway='on' \
  rsyslog_module_imtcp_stream_driver_auth_mode='anon' \
  rsyslog_tls_permitted_peer='["*"]'
# Note 'anon' or 'x509/certvalid' or 'x509/name' for ...auth_mode

# Outputs
# See 60-output_format.conf.tmpl
ENV rsyslog_output_filtering_enabled='on' \
  rsyslog_omfile_enabled='on' \
  rsyslog_omfile_split_files_per_host='off' \
  rsyslog_omfile_template='RSYSLOG_TraditionalFileFormat' \
  rsyslog_omkafka_enabled='off' \
  rsyslog_omkafka_broker='' \
  rsyslog_omkafka_confParam='' \
  rsyslog_omkafka_topic='syslog' \
  rsyslog_omkafka_dynatopic='off' \
  rsyslog_omkafka_topicConfParam='' \
  rsyslog_omkafka_template='TmplJSON' \
  rsyslog_omfwd_syslog_enabled='off' \
  rsyslog_omfwd_syslog_host='' \
  rsyslog_omfwd_syslog_port=514 \
  rsyslog_omfwd_syslog_protocol='tcp' \
  rsyslog_omfwd_syslog_template='TmplRFC5424' \
  rsyslog_omfwd_json_enabled=off \
  rsyslog_omfwd_json_host='' \
  rsyslog_omfwd_json_port=5000 \
  rsyslog_omfwd_json_template='TmplJSON' \
  rsyslog_om_action_queue_maxdiskspace=1073741824 \
  rsyslog_om_action_queue_size=2097152 \
  rsyslog_om_action_queue_discardmark=1048576 \
  rsyslog_om_action_queue_discardseverity=6 \
  rsyslog_call_fwd_extra_rule='off'
# Several globals are defined via rsyslog_global_* inlcuding reporting stats
#
# rsyslog_support_metadata_formats and the appropriate template choice must both be used to allow including validation checks on syslog headers, hostnames and tags for RFC3164. The metadata template choices are:
# - TmplRFC5424Meta
# - TmplJSONRawMsg
#
# Notes for the pre-canned outputs (kafka, JSON, syslog)
# - each pre-canned output can have it's own template applied, e.g.
# - rsyslog_om_action_queue_* is set for all outputs (sort of a global)
# - rsyslog_om_action_queue_maxdiskspace=1073741824 ~ 1G
# - E.g. if three outputs have ~ 1G file limit for the queue, 3G overall is needed
# - Most rsyslog limits work on number of messages in the queue, so rsyslog_om_action_queue_size and rsyslog_om_action_queue_discardmark need to be adjusted in line with rsyslog_om_action_queue_maxdiskspace
# - E.g. Assuming 512 byte messages, a 1G file can fit ~ 2 million messages, and start discarding at ~ 1 million messages
# - While arithmentic could be used to work backwards from max file sizes to message numbers, unfortunatly confd's arithmetic golang text template functions don't handle dynamic type conversion. See: https://github.com/kelseyhightower/confd/issues/611
# - rsyslog_om_action_queue_discardseverity=6 implies info and debug messages get discarded
#
# Additonal output config will probably be highly varied, so instead of trying to template/pre-can it, we allow for that config to be red in
# As above, extra optional volumes with config that can be supplied at runtime
# - /etc/rsyslog.d/input/filters
# - /etc/rsyslog.d/output/filters
# - /etc/rsyslog.d/extra
#
# rsyslog_call_fwd_extra_rule makes the config expect input the user to add a ruleset named fwd_extra somewhere in /etc/rsyslog.d/extra/*.conf

# Volumes required
VOLUME /var/log/remote \
  /var/lib/rsyslog \
  /etc/pki/rsyslog

# Ports to expose
# Note: UDP=514, TCP=514, TCP Secure=6514, RELP=2514, RELP Secure=7514, RELP Secure with strong client auth=8514
EXPOSE 514/udp 514/tcp 6514/tcp 2514/tcp 7514/tcp 8514/tcp

#TODO: also, decide if we will accept the signal to reload config without restarting the container

COPY usr/local/bin/entrypoint.sh usr/local/bin/rsyslog_healthcheck.sh usr/local/bin/rsyslog_healthcheck.sh usr/local/bin/rsyslog_config_expand.py /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

HEALTHCHECK CMD /usr/local/bin/rsyslog_healthcheck.sh

# Add build-date at the end to avoid invalidating the docker build cache
ARG BUILD_DATE
LABEL org.label-schema.build-date="${BUILD_DATE}"
