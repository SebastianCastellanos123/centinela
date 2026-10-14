#!/bin/sh
set -e
rsyslogd
exec /usr/sbin/sshd -D
