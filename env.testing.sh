# Environment variables for local integration testing
# Usage: source .env.test && go test -tags=integration -v ./...

# Network Services
export SSH_TEST_HOST=localhost:2222
export SSH_TEST_USER=testuser
export SSH_TEST_PASS=testpass
export FTP_TEST_HOST=localhost:21
export FTP_TEST_USER=ftpuser
export FTP_TEST_PASS=ftppass
export TELNET_TEST_HOST=localhost:23
export TELNET_TEST_USER=user
export TELNET_TEST_PASS=password
export VNC_TEST_HOST=localhost:5901
export VNC_TEST_PASS=vncpass

# Enterprise Infrastructure
export SMB_TEST_HOST=localhost:445
export SMB_TEST_USER=smbuser
export SMB_TEST_PASS=smbpass
export LDAP_TEST_HOST=localhost:389
export LDAP_TEST_USER="cn=admin,dc=test,dc=local"
export LDAP_TEST_PASS=adminpass
export RDP_TEST_HOST=localhost:3389
export RDP_TEST_USER=guest
export RDP_TEST_PASS=rdppass

# Databases
export MYSQL_TEST_HOST=localhost:3306
export MYSQL_TEST_USER=root
export MYSQL_TEST_PASS=rootpass
export POSTGRES_TEST_HOST=localhost:5432
export POSTGRES_TEST_USER=postgres
export POSTGRES_TEST_PASS=postgrespass
export MSSQL_TEST_HOST=localhost:1433
export MSSQL_TEST_USER=sa
export MSSQL_TEST_PASS='MssqlPass123!'
export MONGODB_TEST_HOST=localhost:27017
export MONGODB_TEST_USER=mongouser
export MONGODB_TEST_PASS=mongopass
export REDIS_TEST_HOST=localhost:6379
export REDIS_TEST_PASS=redispass
export NEO4J_TEST_HOST=localhost:7687
export NEO4J_TEST_USER=neo4j
export NEO4J_TEST_PASS=neo4jpass
export CASSANDRA_TEST_HOST=localhost:9042
export CASSANDRA_TEST_USER=cassandra
export CASSANDRA_TEST_PASS=cassandra
export COUCHDB_TEST_HOST=localhost:5984
export COUCHDB_TEST_USER=couchuser
export COUCHDB_TEST_PASS=couchpass
export ELASTICSEARCH_TEST_HOST=localhost:9200
export ELASTICSEARCH_TEST_USER=elastic
export ELASTICSEARCH_TEST_PASS=elasticpass
export INFLUXDB_TEST_HOST=localhost:8086
export INFLUXDB_TEST_USER=influxuser
export INFLUXDB_TEST_PASS=influxpass

# Communications
export SMTP_TEST_HOST=localhost:3025
export SMTP_TEST_USER=testuser
export SMTP_TEST_PASS=testpass
export IMAP_TEST_HOST=localhost:3143
export IMAP_TEST_USER=testuser
export IMAP_TEST_PASS=testpass
export POP3_TEST_HOST=localhost:3110
export POP3_TEST_USER=testuser
export POP3_TEST_PASS=testpass

# SNMP
export SNMP_TEST_HOST=localhost:161
export SNMP_TEST_COMMUNITY=public
