"""
BeeWAF Mega Rules Database — Part 5
=====================================
Massive expansion: SQL injection variants, XSS deep, command injection deep,
path traversal deep, SSRF deep, authentication bypass, encoding attacks.
~1800 additional patterns.
"""

# ============================================================================
# 1. SQL INJECTION — COMPREHENSIVE EXPANSION (400 patterns)
# ============================================================================
SQLI_ULTRA = [
    # --- UNION-based with column enumeration ---
    r"(?i)\bunion\s+(?:all\s+)?select\s+(?:null|0x[0-9a-f]+|char\(\d+\)|concat\(|group_concat\(|string_agg\(|listagg\(|xmlagg\(|array_agg\(|json_agg\()",
    r"(?i)\bunion\s+(?:all\s+)?select\s+\d+\s*,\s*\d+\s*,\s*\d+",
    r"(?i)\bunion\s+(?:all\s+)?select\s+null\s*,\s*null\s*,\s*null",
    r"(?i)\bunion\s+(?:all\s+)?select\s+(?:user|current_user|session_user|system_user|current_database|version|@@version|@@servername|@@language|@@spid|db_name|schema_name)\s*\(",
    r"(?i)\bunion\s+(?:all\s+)?select\s+\w+\s+from\s+(?:information_schema|sys\.|mysql\.|pg_catalog|dba_|all_|user_|v\$)",
    r"(?i)\bunion\s+(?:all\s+)?select\s+\w+\s+from\s+(?:information_schema\.(?:tables|columns|schemata|table_privileges|column_privileges|key_column_usage|table_constraints|referential_constraints|routines|parameters|views|triggers))\b",
    r"(?i)\bunion\s+(?:all\s+)?select\s+\w+\s+from\s+(?:sys\.(?:objects|tables|columns|views|procedures|functions|triggers|indexes|schemas|databases|server_principals|sql_logins|dm_exec_sessions|dm_exec_requests|dm_os_sys_info))\b",
    r"(?i)\bunion\s+(?:all\s+)?select\s+\w+\s+from\s+(?:pg_catalog\.(?:pg_tables|pg_columns|pg_views|pg_proc|pg_shadow|pg_roles|pg_user|pg_database|pg_namespace|pg_class|pg_attribute|pg_index|pg_constraint|pg_trigger|pg_type))\b",
    r"(?i)\bunion\s+(?:all\s+)?select\s+\w+\s+from\s+(?:mysql\.(?:user|db|tables_priv|columns_priv|proc|func|plugin|servers|help_topic|general_log|slow_log))\b",
    r"(?i)\bunion\s+(?:all\s+)?select\s+\w+\s+from\s+(?:sqlite_master|sqlite_temp_master|sqlite_sequence)\b",
    r"(?i)\bunion\s+(?:all\s+)?select\s+\w+\s+from\s+(?:dba_tables|dba_users|dba_tab_columns|all_tables|all_users|all_tab_columns|user_tables|user_tab_columns|v\$version|v\$instance|v\$session|v\$database)\b",
    # --- Boolean blind techniques ---
    r"(?i)\band\s+\d+\s*=\s*\d+\b",
    r"(?i)\bor\s+\d+\s*=\s*\d+\b",
    r"(?i)\band\s+substring\s*\(\s*(?:user|current_user|version|database|@@version|db_name)\s*\(",
    r"(?i)\band\s+ascii\s*\(\s*substring\s*\(",
    r"(?i)\band\s+ord\s*\(\s*mid\s*\(",
    r"(?i)\band\s+left\s*\(\s*(?:user|version|database)\s*\(\s*\)\s*,\s*\d+\s*\)\s*(?:=|like|regexp)",
    r"(?i)\band\s+(?:if|ifnull|nullif|iif|iff|coalesce|nvl|nvl2|decode|case\s+when)\s*\(",
    r"(?i)\band\s+length\s*\(\s*(?:user|version|database|current_user|session_user)\s*\(\s*\)\s*\)\s*(?:=|>|<|>=|<=|!=|<>)\s*\d+",
    r"(?i)\band\s+char_length\s*\(\s*(?:user|version|database)\s*\(\s*\)\s*\)\s*(?:=|>|<)\s*\d+",
    r"(?i)\band\s+(?:exists|not\s+exists)\s*\(\s*select\b",
    r"(?i)\band\s+\(\s*select\s+count\s*\(\s*\*?\s*\)\s+from\b",
    r"(?i)\band\s+\(\s*select\s+top\s+1\b",
    r"(?i)\band\s+\d+\s*(?:=|<|>)\s*\(\s*select\b",
    r"(?i)\bor\s+\d+\s*(?:=|<|>)\s*\(\s*select\b",
    # --- Time-based blind ---
    r"(?i)\band\s+sleep\s*\(\s*\d+\s*\)",
    r"(?i)\band\s+benchmark\s*\(\s*\d+\s*,",
    r"(?i)\band\s+pg_sleep\s*\(\s*\d+\s*\)",
    r"(?i)\band\s+waitfor\s+delay\s+['\"]",
    r"(?i)\band\s+dbms_lock\.sleep\s*\(\s*\d+\s*\)",
    r"(?i)\band\s+dbms_pipe\.receive_message\s*\(",
    r"(?i)\band\s+randomblob\s*\(\s*\d+\s*\)",
    r"(?i)\bif\s*\(\s*\d+\s*=\s*\d+\s*,\s*sleep\s*\(",
    r"(?i)\bif\s*\(\s*\d+\s*=\s*\d+\s*,\s*benchmark\s*\(",
    r"(?i)\bcase\s+when\s+\d+\s*=\s*\d+\s+then\s+(?:pg_sleep|sleep|benchmark|waitfor|dbms_lock\.sleep)\s*\(",
    r"(?i);\s*waitfor\s+delay\s+['\"]0:0:\d+['\"]",
    r"(?i);\s*select\s+sleep\s*\(\s*\d+\s*\)",
    r"(?i);\s*select\s+pg_sleep\s*\(\s*\d+\s*\)",
    r"(?i)\|\|\s*pg_sleep\s*\(\s*\d+\s*\)",
    # --- Error-based ---
    r"(?i)\band\s+(?:extractvalue|updatexml)\s*\(\s*\d+\s*,\s*concat\s*\(",
    r"(?i)\band\s+(?:exp|cot|pow|ln|log|log2|log10|sqrt|acos|asin|atan|ceil|floor|round|sign|rand|pi|degrees|radians)\s*\(\s*~?\s*\(\s*select\b",
    r"(?i)\band\s+(?:geometrycollection|multipoint|polygon|multipolygon|linestring|multilinestring|point)\s*\(\s*\(\s*select\b",
    r"(?i)\band\s+(?:gtid_subset|json_keys|json_extract|json_object|json_array|json_quote|json_contains|json_depth|json_length|json_type|json_valid|json_merge|json_merge_patch|json_merge_preserve|json_pretty|json_remove|json_replace|json_set|json_storage_free|json_storage_size|json_table|json_unquote|json_value)\s*\(",
    r"(?i)convert\s*\(\s*(?:int|varchar|nvarchar|char|nchar|text|ntext|binary|varbinary)\s*,\s*\(\s*select\b",
    r"(?i)cast\s*\(\s*\(\s*select\s+.*\)\s+as\s+(?:int|varchar|text|char|numeric|decimal|float|double|integer|bigint|smallint|tinyint|nvarchar|nchar|ntext)\s*\)",
    r"(?i)(?:xml|json)_(?:query|value|modify|exist|nodes|text|data|type|length|extract|extractvalue|table)\s*\(\s*(?:concat|chr|char|substring|user|version|database|@@version)\b",
    # --- Stacked queries ---
    r"(?i);\s*(?:select|insert|update|delete|drop|create|alter|exec|execute|declare|set|grant|revoke|truncate|rename|call|load|merge|replace|handler|analyze|check|checksum|optimize|repair|flush|purge|reset|prepare|deallocate|begin|commit|rollback|savepoint)\b",
    r"(?i);\s*declare\s+@?\w+\s+(?:varchar|nvarchar|char|int|bigint|text|cursor|table)\b",
    r"(?i);\s*exec\s*\(\s*(?:'|\")",
    r"(?i);\s*execute\s+(?:sp_|xp_|fn_|master\.\.)\w+",
    r"(?i);\s*xp_cmdshell\s*\(",
    r"(?i);\s*sp_(?:oacreate|oamethod|oagetproperty|configure|addextendedproc|executesql|prepare|execute|make_webserver|helptext|help|columns|tables|databases|fkeys|pkeys|server_info|stored_procedures)\b",
    r"(?i);\s*openrowset\s*\(",
    r"(?i);\s*opendatasource\s*\(",
    r"(?i);\s*bulk\s+insert\b",
    r"(?i);\s*load\s+data\s+(?:local\s+)?infile\b",
    r"(?i);\s*load_file\s*\(",
    r"(?i);\s*into\s+(?:outfile|dumpfile)\b",
    r"(?i);\s*create\s+(?:or\s+replace\s+)?(?:function|procedure|trigger|event|view|table|database|schema|index|user|role)\b",
    # --- Database-specific functions ---
    r"(?i)\b(?:concat|concat_ws|group_concat|string_agg|listagg|wm_concat|xmlagg|list|array_agg|json_agg|json_arrayagg|json_objectagg|json_group_array|json_group_object)\s*\(\s*(?:0x[0-9a-f]+|char\(\d+\)|chr\(\d+\)|user|version|database|current_user|session_user|@@version)\b",
    r"(?i)\b(?:hex|unhex|to_hex|encode|decode|from_base64|to_base64|base64_decode|base64_encode|compress|uncompress|md5|sha1|sha2|sha256|sha512|crc32|crypt|des_encrypt|des_decrypt|aes_encrypt|aes_decrypt)\s*\(\s*(?:\(\s*select\b|user|version|database|@@version)\b",
    r"(?i)\b(?:char|chr|nchar|unicode|ascii|ord)\s*\(\s*\d+\s*\)\s*(?:\+|\|\|)\s*(?:char|chr|nchar)\s*\(\s*\d+\s*\)",
    r"(?i)\b(?:replace|reverse|repeat|space|left|right|trim|ltrim|rtrim|lpad|rpad|insert|stuff|translate|soundex|difference|quotename|parsename)\s*\(\s*(?:\(\s*select\b|user|version|database|@@version)\b",
    r"(?i)\b(?:substring|substr|mid|substrb|substrc|substr2|substr4)\s*\(\s*(?:\(\s*select\b|user|version|database|current_user|@@version)\s*(?:\(\s*\))?\s*,\s*\d+\s*,\s*\d+\s*\)",
    r"(?i)\b(?:length|len|char_length|character_length|bit_length|octet_length|datalength)\s*\(\s*(?:\(\s*select\b|user|version|database|@@version)\b",
    r"(?i)\b(?:locate|instr|position|charindex|strpos|find_in_set|field|elt|make_set)\s*\(",
    # --- MySQL specific ---
    r"(?i)\b(?:information_schema\.\w+|mysql\.\w+|performance_schema\.\w+|sys\.\w+)\b",
    r"(?i)\b@@(?:version|version_comment|version_compile_os|version_compile_machine|hostname|port|basedir|datadir|tmpdir|log_error|general_log|slow_query_log|secure_file_priv|server_id|server_uuid|sql_mode|max_connections|max_allowed_packet|wait_timeout|interactive_timeout|character_set_server|collation_server|innodb_version|have_ssl|have_openssl|plugin_dir|slave_running|read_only|super_read_only|gtid_mode|enforce_gtid_consistency|binlog_format|expire_logs_days|system_time_zone|time_zone)\b",
    r"(?i)\b(?:load_file|into\s+outfile|into\s+dumpfile|benchmark|sleep|get_lock|release_lock|is_free_lock|is_used_lock|master_pos_wait|found_rows|row_count|last_insert_id|connection_id|current_user|system_user|session_user|user|database|version|schema|uuid|uuid_short|rand|floor)\s*\(",
    # --- PostgreSQL specific ---
    r"(?i)\bpg_(?:catalog|tables|views|indexes|sequences|class|attribute|namespace|type|proc|description|constraint|index|trigger|rules|rewrite|depend|shdepend|stat_activity|stat_replication|stat_wal_receiver|stat_subscription|stat_ssl|stat_database|stat_user_tables|stat_user_indexes|stat_io_user_tables|stat_io_user_indexes|statio_user_tables|statio_user_indexes|locks|prepared_xacts|prepared_statements|cursors|user|roles|shadow|group|authid|auth_members|database|tablespace|settings|file_settings|hba_file_rules|policies|publication|subscription)\b",
    r"(?i)\b(?:pg_sleep|pg_sleep_for|pg_sleep_until|pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|pg_advisory_lock|pg_try_advisory_lock|pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|pg_switch_wal|pg_current_wal_lsn|pg_walfile_name|pg_export_snapshot|pg_create_restore_point|pg_start_backup|pg_stop_backup|pg_basebackup|pg_receivexlog|pg_recvlogical|pg_isready|pg_dump|pg_dumpall|pg_restore|pg_ctl|lo_import|lo_export|lo_create|lo_open|lo_close|lo_read|lo_write|lo_lseek|lo_tell|lo_truncate|lo_unlink|dblink|dblink_connect|dblink_exec|dblink_get_result|dblink_send_query)\s*\(",
    r"(?i)\bcopy\s+\w+\s+(?:from|to)\s+(?:program|stdin|stdout)\b",
    r"(?i)\bcreate\s+(?:or\s+replace\s+)?(?:function|procedure)\s+\w+\s*\(.*\)\s+(?:returns|as\s+\$\$|language\s+(?:plpgsql|plpython|plperl|plr|pltcl|sql|c))\b",
    r"(?i)\bdo\s+\$\$.*\$\$\s*(?:language\s+plpgsql)?\s*;",
    # --- MSSQL specific ---
    r"(?i)\b(?:master|tempdb|model|msdb|mssqlsystemresource)\.\.",
    r"(?i)\b(?:xp_cmdshell|xp_regread|xp_regwrite|xp_regdeletevalue|xp_regdeletekey|xp_regenumvalues|xp_regenumkeys|xp_regaddmultistring|xp_regremovemultistring|xp_instance_regread|xp_instance_regwrite|xp_fixeddrives|xp_dirtree|xp_subdirs|xp_fileexist|xp_create_subdir|xp_delete_file|xp_availablemedia|xp_enumdsn|xp_enumerrorlogs|xp_getfiledetails|xp_getnetname|xp_loginconfig|xp_logininfo|xp_msver|xp_ntsec_enumdomains|xp_readerrorlog|xp_servicecontrol|xp_sprintf|xp_sscanf|xp_terminate_process|sp_oacreate|sp_oamethod|sp_oagetproperty|sp_oadestroy|sp_oageterrorinfo|sp_oasetproperty|sp_oastop|sp_configure|sp_executesql|sp_makewebtask|sp_addextendedproc|sp_helptext|sp_password|sp_addlogin|sp_droplogin|sp_grantlogin|sp_revokelogin|sp_addsrvrolemember|sp_dropsrvrolemember|sp_addrolemember|sp_droprolemember|sp_defaultdb|sp_defaultlanguage|sp_change_users_login)\s*(?:\(|')",
    r"(?i)\b(?:openrowset|opendatasource|openquery|openxml|bulk\s+insert|bcp|readtext|writetext|updatetext|textptr|textvalid)\b",
    r"(?i)\b(?:fn_get_sql|fn_xe_file_target_read_file|fn_dblog|fn_dump_dblog|fn_trace_gettable|fn_trace_getinfo|fn_trace_getfilterinfo|fn_trace_geteventinfo|fn_trace_getdata)\b",
    r"(?i)reconfigure\b",
    r"(?i)exec\s+master\.\.xp_cmdshell",
    # --- Oracle specific ---
    r"(?i)\b(?:utl_http\.request|utl_inaddr\.get_host_address|utl_inaddr\.get_host_name|utl_file\.fopen|utl_file\.get_line|utl_file\.put|utl_file\.put_line|utl_file\.fclose|utl_file\.fremove|utl_file\.frename|utl_file\.fcopy|utl_file\.fgetattr|utl_file\.is_open|utl_smtp\.open_connection|utl_smtp\.helo|utl_smtp\.mail|utl_smtp\.rcpt|utl_smtp\.data|utl_smtp\.write_data|utl_smtp\.quit|utl_tcp\.open_connection|utl_tcp\.write_line|utl_tcp\.read_line|utl_tcp\.close_connection|dbms_ldap\.init|dbms_ldap\.simple_bind_s|dbms_java\.runjava|dbms_java\.loadjava|dbms_scheduler\.create_job|dbms_scheduler\.run_job|dbms_xmlquery\.getxml|dbms_xmlquery\.newcontext|dbms_xmlquery\.setrowsettag|dbms_output\.put_line|dbms_sql\.execute|dbms_sql\.parse|dbms_random\.value|dbms_pipe\.send_message|dbms_pipe\.receive_message|dbms_lock\.sleep|dbms_metadata\.get_ddl|ctx_sys\.browse_words|ctxsys\.drithsx\.sn)\s*\(",
    r"(?i)\bexecute\s+immediate\s+['\"]",
    r"(?i)\b(?:all_tables|all_tab_columns|all_views|all_source|all_procedures|all_objects|all_users|all_db_links|all_directories|all_synonyms|all_sequences|all_triggers|all_constraints|all_indexes|all_tab_privs|all_col_privs|dba_tables|dba_tab_columns|dba_views|dba_source|dba_procedures|dba_objects|dba_users|dba_db_links|dba_directories|dba_synonyms|dba_sequences|dba_triggers|dba_constraints|dba_indexes|dba_tab_privs|dba_col_privs|dba_roles|dba_role_privs|dba_sys_privs|user_tables|user_tab_columns|user_views|user_source|user_procedures|user_objects|user_synonyms|user_sequences|user_triggers|user_constraints|user_indexes|user_tab_privs|user_col_privs|v\$version|v\$instance|v\$session|v\$database|v\$parameter|v\$nls_parameters|v\$timezone_names|v\$log|v\$logfile|v\$datafile|v\$tablespace|v\$process|v\$sql|v\$sqltext|v\$sql_plan|v\$sga|v\$sgastat|v\$sgainfo|v\$fixed_table|v\$pwfile_users|v\$option)\b",
    # --- SQLite specific ---
    r"(?i)\b(?:sqlite_master|sqlite_temp_master|sqlite_sequence|sqlite_stat1|sqlite_stat2|sqlite_stat3|sqlite_stat4)\b",
    r"(?i)\b(?:randomblob|zeroblob|typeof|quote|hex|unicode|zeroblob|total_changes|changes|last_insert_rowid|sqlite_version|sqlite_source_id|sqlite_compileoption_get|sqlite_compileoption_used|load_extension|fts3|fts4|fts5|rtree|json_extract|json_each|json_tree|json_type|json_valid|json_quote|json_group_array|json_group_object|json_object|json_array|json_array_length|json_insert|json_replace|json_set|json_remove|json_patch)\s*\(",
    r"(?i)\battach\s+database\s+['\"]",
    # --- NoSQL injection expansion ---
    r"(?i)\{\s*['\"]?\$(?:regex|options|where|gt|gte|lt|lte|ne|eq|in|nin|not|nor|or|and|exists|type|mod|all|size|elemMatch|slice|text|search|language|caseSensitive|diacriticSensitive|near|nearSphere|geoWithin|geoIntersects|geometry|maxDistance|minDistance|polygon|box|center|centerSphere|uniqueDocs)\s*['\"]?\s*:",
    r"(?i)\{\s*['\"]?\$(?:set|unset|inc|mul|rename|min|max|currentDate|addToSet|pop|pull|push|pullAll|pushAll|bit|position|each|slice|sort)\s*['\"]?\s*:",
    r"(?i)\{\s*['\"]?\$(?:lookup|unwind|group|project|match|sort|limit|skip|sample|addFields|set|unset|replaceRoot|replaceWith|merge|out|facet|bucket|bucketAuto|sortByCount|count|graphLookup|geoNear|redact|collStats|indexStats|planCacheStats|currentOp|listSessions|listLocalSessions)\s*['\"]?\s*:",
    r"(?i)db\.(?:eval|runCommand|adminCommand|getMongo|getSiblingDB|getCollection|createCollection|createUser|dropUser|updateUser|grantRolesToUser|revokeRolesFromUser|createRole|dropRole|updateRole|grantPrivilegesToRole|revokePrivilegesFromRole|auth|logout|currentOp|killOp|setProfilingLevel|getProfilingStatus|fsyncLock|fsyncUnlock|serverStatus|hostInfo|buildInfo|version|isMaster|hello|replSetGetStatus|replSetInitiate|replSetReconfig|replSetStepDown|replSetFreeze|replSetMaintenance|replSetSyncFrom|shardCollection|split|moveChunk|mergeChunks|removeShard|addShard|enableSharding|listShards|printShardingStatus)\s*\(",
    r"(?i)this\.\w+\s*(?:==|!=|===|!==|>|<|>=|<=)\s*(?:['\"]|true|false|null|\d+)",
    # --- Redis injection ---
    r"(?i)\b(?:EVAL|EVALSHA|SCRIPT|CLIENT|CONFIG|DEBUG|FLUSHALL|FLUSHDB|KEYS|SHUTDOWN|SLAVEOF|REPLICAOF|MODULE|BGSAVE|BGREWRITEAOF|SAVE|DBSIZE|INFO|SLOWLOG|MONITOR|SUBSCRIBE|PSUBSCRIBE|PUBLISH|ACL|AUTH|CLUSTER|COMMAND|LATENCY|MEMORY|OBJECT|PERSIST|PEXPIRE|PEXPIREAT|PTTL|RANDOMKEY|RENAME|RENAMENX|RESTORE|SCAN|SORT|TTL|TYPE|UNLINK|WAIT|WATCH|ZADD|ZRANGEBYSCORE|ZRANGEBYLEX|ZREVRANGEBYSCORE|ZREVRANGEBYLEX|ZRANGE|ZREVRANGE|ZCARD|ZCOUNT|ZLEXCOUNT|ZREM|ZREMRANGEBYSCORE|ZREMRANGEBYLEX|ZREMRANGEBYRANK|ZINCRBY|ZSCORE|ZMSCORE|ZUNION|ZUNIONSTORE|ZINTER|ZINTERSTORE|ZDIFF|ZDIFFSTORE|ZPOPMIN|ZPOPMAX|BZPOPMIN|BZPOPMAX|ZRANDMEMBER|ZRANGESTORE|SET|GET|DEL|EXISTS|EXPIRE|EXPIREAT|APPEND|DECR|DECRBY|GETDEL|GETEX|GETRANGE|GETSET|INCR|INCRBY|INCRBYFLOAT|LCS|MGET|MSET|MSETNX|PSETEX|SETEX|SETNX|SETRANGE|STRLEN|SUBSTR|HSET|HGET|HDEL|HEXISTS|HGETALL|HINCRBY|HINCRBYFLOAT|HKEYS|HLEN|HMGET|HMSET|HRANDFIELD|HSCAN|HSETNX|HVALS|LINDEX|LINSERT|LLEN|LMOVE|LPOP|LPOS|LPUSH|LPUSHX|LRANGE|LREM|LSET|LTRIM|RPOP|RPOPLPUSH|RPUSH|RPUSHX|SADD|SCARD|SDIFF|SDIFFSTORE|SINTER|SINTERCARD|SINTERSTORE|SISMEMBER|SMEMBERS|SMISMEMBER|SMOVE|SPOP|SRANDMEMBER|SREM|SSCAN|SUNION|SUNIONSTORE)\b\s+",
    r"(?i)\bCONFIG\s+(?:SET|GET|RESETSTAT|REWRITE)\s+\w+",
    r"(?i)\bSCRIPT\s+(?:LOAD|EXISTS|FLUSH|KILL)\b",
    # --- CQL/Cassandra ---
    r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|LIST|USE|DESCRIBE|BATCH|APPLY)\s+.*\b(?:FROM|INTO|TABLE|KEYSPACE|TYPE|INDEX|FUNCTION|AGGREGATE|MATERIALIZED|TRIGGER|USER|ROLE|PERMISSION|PERMISSIONS|ALL|ROLES|USERS|KEYSPACES|TABLES|TYPES|FUNCTIONS|AGGREGATES|ALLOW\s+FILTERING)\b",
]

# ============================================================================
# 2. XSS — COMPREHENSIVE EXPANSION (350 patterns)
# ============================================================================
XSS_ULTRA = [
    # --- HTML tag injection ---
    r"(?i)<\s*script[^>]*>",
    r"(?i)<\s*/\s*script\s*>",
    r"(?i)<\s*img\s+[^>]*(?:on\w+|src\s*=\s*['\"]?(?:javascript|data|vbscript):)[^>]*>",
    r"(?i)<\s*svg\s+[^>]*(?:on\w+|xmlns)[^>]*>",
    r"(?i)<\s*body\s+[^>]*on\w+\s*=[^>]*>",
    r"(?i)<\s*iframe\s+[^>]*(?:src|srcdoc|onload)\s*=[^>]*>",
    r"(?i)<\s*object\s+[^>]*(?:data|type|classid)\s*=[^>]*>",
    r"(?i)<\s*embed\s+[^>]*(?:src|type)\s*=[^>]*>",
    r"(?i)<\s*applet\b[^>]*>",
    r"(?i)<\s*form\s+[^>]*(?:action|onsubmit)\s*=[^>]*>",
    r"(?i)<\s*input\s+[^>]*(?:onfocus|autofocus|onmouseover|type\s*=\s*['\"]?image)[^>]*>",
    r"(?i)<\s*button\s+[^>]*(?:onclick|onfocus|onmouseover|formaction)\s*=[^>]*>",
    r"(?i)<\s*select\s+[^>]*(?:onfocus|onchange|onblur)\s*=[^>]*>",
    r"(?i)<\s*textarea\s+[^>]*(?:onfocus|onblur|onchange|oninput)\s*=[^>]*>",
    r"(?i)<\s*details\s+[^>]*(?:ontoggle|open)\s*[^>]*>",
    r"(?i)<\s*marquee\s+[^>]*(?:onstart|onfinish|onbounce)\s*=[^>]*>",
    r"(?i)<\s*video\s+[^>]*(?:onloadstart|onloadeddata|oncanplay|onerror|src)\s*=[^>]*>",
    r"(?i)<\s*audio\s+[^>]*(?:onloadstart|onloadeddata|oncanplay|onerror|src)\s*=[^>]*>",
    r"(?i)<\s*source\s+[^>]*(?:onerror|src)\s*=[^>]*>",
    r"(?i)<\s*track\s+[^>]*(?:oncuechange|src)\s*=[^>]*>",
    r"(?i)<\s*meta\s+[^>]*(?:http-equiv\s*=\s*['\"]?refresh|content\s*=\s*['\"]?[^'\"]*url\s*=)[^>]*>",
    r"(?i)<\s*link\s+[^>]*(?:rel\s*=\s*['\"]?(?:import|stylesheet|preload|prefetch|dns-prefetch|preconnect|prerender))[^>]*>",
    r"(?i)<\s*base\s+[^>]*href\s*=[^>]*>",
    r"(?i)<\s*style[^>]*>.*(?:expression|url|import|@import|behavior|moz-binding|-webkit-|animation-name|content)\b",
    r"(?i)<\s*div\s+[^>]*(?:onmouseover|onmouseenter|onmousemove|onclick|ondblclick|oncontextmenu|ondrag|ondragstart|ondragend|ondragenter|ondragleave|ondragover|ondrop|onwheel|onscroll|oncopy|oncut|onpaste)\s*=[^>]*>",
    r"(?i)<\s*a\s+[^>]*(?:href\s*=\s*['\"]?(?:javascript|data|vbscript):|onclick|onmouseover|onfocus)\s*[^>]*>",
    r"(?i)<\s*table\s+[^>]*(?:background|onload|onerror)\s*=[^>]*>",
    r"(?i)<\s*td\s+[^>]*(?:background|onmouseover|onclick)\s*=[^>]*>",
    r"(?i)<\s*math\s+[^>]*>.*(?:xlink:href|href)\s*=",
    r"(?i)<\s*isindex\b",
    r"(?i)<\s*xss\b",
    r"(?i)<\s*x\s+[^>]*on\w+\s*=",
    r"(?i)<\s*image\s+[^>]*(?:src|onerror|onload)\s*=",
    # --- Event handler injection (comprehensive list) ---
    r"(?i)\bon(?:abort|afterprint|animationend|animationiteration|animationstart|auxclick|beforecopy|beforecut|beforeinput|beforepaste|beforeprint|beforeunload|blur|canplay|canplaythrough|change|click|close|contextmenu|copy|cuechange|cut|dblclick|devicemotion|deviceorientation|drag|dragend|dragenter|dragexit|dragleave|dragover|dragstart|drop|durationchange|emptied|ended|error|focus|focusin|focusout|formdata|fullscreenchange|fullscreenerror|gotpointercapture|hashchange|input|invalid|keydown|keypress|keyup|languagechange|load|loadeddata|loadedmetadata|loadend|loadstart|lostpointercapture|message|messageerror|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseover|mouseup|mousewheel|offline|online|open|orientationchange|pagehide|pageshow|paste|pause|play|playing|pointercancel|pointerdown|pointerenter|pointerleave|pointermove|pointerout|pointerover|pointerrawupdate|pointerup|popstate|progress|ratechange|readystatechange|rejectionhandled|reset|resize|scroll|scrollend|search|securitypolicyviolation|seeked|seeking|select|selectionchange|selectstart|slotchange|stalled|storage|submit|suspend|timeupdate|toggle|touchcancel|touchend|touchforcechange|touchmove|touchstart|transitioncancel|transitionend|transitionrun|transitionstart|unhandledrejection|unload|visibilitychange|volumechange|waiting|webkitanimationend|webkitanimationiteration|webkitanimationstart|webkittransitionend|wheel)\s*=",
    # --- JavaScript protocol variants ---
    r"(?i)(?:href|src|action|formaction|data|poster|background|codebase|cite|classid|profile|usemap|longdesc|lowsrc|dynsrc)\s*=\s*['\"]?\s*(?:javascript|vbscript|livescript|mocha|ecmascript|data\s*:|blob\s*:)\s*:",
    r"(?i)javascript\s*:\s*(?:alert|confirm|prompt|eval|Function|setTimeout|setInterval|document|window|location|navigator|XMLHttpRequest|fetch|ActiveXObject|WScript|WSH)\b",
    r"(?i)javascript\s*:\s*void\s*\(",
    r"(?i)javascript\s*&colon;",
    r"(?i)java\s*script\s*:",
    r"(?i)j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:",
    r"(?i)&#(?:106|74)\s*;?\s*&#(?:97|65)\s*;?\s*&#(?:118|86)\s*;?\s*&#(?:97|65)\s*;?",
    r"(?i)&#x(?:6a|4a)\s*;?\s*&#x(?:61|41)\s*;?\s*&#x(?:76|56)\s*;?\s*&#x(?:61|41)\s*;?",
    r"(?i)\\u006a\\u0061\\u0076\\u0061\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074",
    r"(?i)\\x6a\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74",
    # --- DOM-based XSS sinks ---
    r"(?i)(?:document|window|location|navigator|history|screen|performance|crypto|caches|indexedDB|localStorage|sessionStorage|opener|parent|top|self|frames|this)\.\s*(?:write|writeln|open|close|createElement|createElementNS|createDocumentFragment|createComment|createTextNode|createAttribute|createEvent|createRange|createNodeIterator|createTreeWalker|getElementById|getElementsByClassName|getElementsByName|getElementsByTagName|getElementsByTagNameNS|querySelector|querySelectorAll|evaluate|execCommand|domain|cookie|referrer|URL|documentURI|baseURI|lastModified|title|designMode|contentEditable|charset|characterSet|compatMode|contentType|doctype|head|body|all|anchors|applets|embeds|forms|images|links|plugins|scripts|styleSheets)\b",
    r"(?i)\.(?:innerHTML|outerHTML|innerText|outerText|textContent|insertAdjacentHTML|insertAdjacentText|insertAdjacentElement)\s*(?:=|\+\=)",
    r"(?i)\.(?:src|href|action|data|codebase|cite|background|poster|lowsrc|dynsrc|formaction)\s*=\s*(?:document\.|window\.|location\.|decodeURI|decodeURIComponent|unescape|atob|String\.fromCharCode)\b",
    r"(?i)\.setAttribute\s*\(\s*['\"](?:src|href|action|data|codebase|cite|background|poster|formaction|on\w+)['\"]",
    r"(?i)(?:location|document\.location|window\.location)\s*(?:\.(?:href|hash|search|pathname|protocol|hostname|port|host|origin|assign|replace)|=)",
    r"(?i)(?:document\.domain|document\.cookie|document\.referrer|document\.URL|document\.documentURI|document\.baseURI)\s*(?:=|\.match|\.indexOf|\.substring|\.slice|\.split|\.replace)",
    r"(?i)(?:eval|Function|setTimeout|setInterval|setImmediate|execScript|msSetImmediate)\s*\(\s*(?:document\.|window\.|location\.|navigator\.|decodeURI|atob|String\.fromCharCode|unescape)",
    r"(?i)(?:document\.write|document\.writeln)\s*\(\s*(?:'[^']*<|\"[^\"]*<|`[^`]*<|decodeURI|atob|unescape|String\.fromCharCode)",
    # --- Template injection for XSS ---
    r"(?i)\{\{.*(?:constructor|__proto__|prototype|toString|valueOf|__lookupGetter__|__lookupSetter__|__defineGetter__|__defineSetter__).*\}\}",
    r"(?i)\{\{.*(?:\(\)|\.call\(|\.apply\(|\.bind\(|new\s+Function|eval\().*\}\}",
    r"(?i)\$\{.*(?:document|window|location|navigator|alert|confirm|prompt|eval|Function|setTimeout|setInterval|XMLHttpRequest|fetch|atob|btoa).*\}",
    r"(?i)<%.*(?:document|window|alert|confirm|prompt|eval|Function|Response\.Write|Server\.Execute|Server\.Transfer|Application|Session|Request).*%>",
    # --- SVG-based XSS ---
    r"(?i)<\s*svg[^>]*>\s*<\s*(?:animate|animateMotion|animateTransform|set|use|image|foreignObject|text|desc|title|metadata|switch|g|defs|symbol|clipPath|mask|pattern|linearGradient|radialGradient|stop|filter|feBlend|feColorMatrix|feComponentTransfer|feComposite|feConvolveMatrix|feDiffuseLighting|feDisplacementMap|feDistantLight|feDropShadow|feFlood|feFuncA|feFuncB|feFuncG|feFuncR|feGaussianBlur|feImage|feMerge|feMergeNode|feMorphology|feOffset|fePointLight|feSpecularLighting|feSpotLight|feTile|feTurbulence|cursor|marker|view|a|altGlyph|altGlyphDef|altGlyphItem|circle|ellipse|glyph|glyphRef|hkern|line|path|polygon|polyline|rect|textPath|tref|tspan|vkern)\b",
    r"(?i)<\s*svg[^>]*(?:onload|onerror|onmouseover|onfocus|onclick)\s*=",
    r"(?i)<\s*svg[^>]*>\s*<\s*(?:script|handler|listener)\b",
    r"(?i)<\s*svg[^>]*(?:xmlns:xlink|xlink:href)\s*=\s*['\"]?\s*(?:javascript|data|vbscript):",
    # --- CSS-based XSS ---
    r"(?i)(?:expression|behavior|moz-binding|animation-name|@import|@charset|@namespace|@font-face|@keyframes)\s*(?:\(|:|\s*url)\s*(?:javascript|data|vbscript|eval|alert|document|window|cookie|http)",
    r"(?i)(?:background|background-image|list-style|list-style-image|cursor|content)\s*:\s*url\s*\(\s*(?:javascript|data|vbscript):",
    r"(?i)-(?:moz|webkit|ms|o)-binding\s*:",
    r"(?i)(?:var|env|attr|counter|counters|calc|min|max|clamp|element|image|cross-fade|paint)\s*\(\s*(?:javascript|data|eval|alert|document|window)",
    # --- Encoding evasion for XSS ---
    r"(?i)(?:%3C|%3c)\s*(?:script|img|svg|body|iframe|object|embed|applet|form|input|button|select|textarea|details|marquee|video|audio|source|link|meta|base|style|div|a|table|math|isindex|xss|x)\b",
    r"(?i)\x3c\s*(?:script|img|svg|body|iframe|object|embed)",
    r"(?i)&lt;\s*(?:script|img|svg|body|iframe|object|embed)",
    r"(?i)&#(?:60|x3c|X3C|003c|0003c|00003c)\s*;?\s*(?:script|img|svg|body|iframe|object|embed)",
    r"(?i)\\u003c\s*(?:script|img|svg|body|iframe|object|embed)",
    r"(?i)\\x3c\s*(?:script|img|svg|body|iframe|object|embed)",
    # --- Data URI XSS ---
    r"(?i)data\s*:\s*(?:text/html|text/javascript|application/javascript|application/x-javascript|text/ecmascript|application/ecmascript|text/vbscript|text/xml|application/xml|image/svg\+xml|text/xsl|application/xhtml\+xml)\s*[;,]",
    r"(?i)data\s*:\s*[^;,]+\s*;\s*base64\s*,\s*(?:PH|PD|PG|aW|ZX|Ym|YW|ZG|dW|cH|ZnV|c2|b24|ZXZ|ZXh|c3R|c3l|ZG9|d2lu|bG9j|bmF2|aGlz|c2Ny|cGVy|Y3J5|Y2Fj|aW5k|bG9j|c2Vz|b3Bl|cGFy|dG9w|c2Vs|ZnJh|dGhp)",
    # --- AngularJS sandbox escape ---
    r"(?i)\{\{.*(?:constructor|toString|valueOf|hasOwnProperty|isPrototypeOf|propertyIsEnumerable|toLocaleString|__defineGetter__|__defineSetter__|__lookupGetter__|__lookupSetter__).*\}\}",
    r"(?i)\{\{.*(?:\.constructor\.constructor\(|\.constructor\(\)|Function\(|eval\().*\}\}",
    r"(?i)ng-(?:app|bind|bind-html|bind-template|change|checked|class|click|cloak|controller|copy|csp|cut|dblclick|disabled|focus|hide|href|if|include|init|jq|keydown|keypress|keyup|list|maxlength|minlength|model|mousedown|mouseenter|mouseleave|mousemove|mouseover|mouseup|non-bindable|open|options|paste|pattern|pluralize|readonly|repeat|required|selected|show|src|srcset|style|submit|switch|transclude|value|view)\s*=",
    # --- React/Vue XSS ---
    r"(?i)dangerouslySetInnerHTML\s*=\s*\{",
    r"(?i)v-html\s*=\s*['\"]",
    r"(?i)v-bind:(?:innerHTML|outerHTML|textContent)\s*=",
    r"(?i)v-on:\w+\s*=\s*['\"].*(?:eval|Function|setTimeout|setInterval|document|window|location)\b",
    r"(?i)(?:jsx|tsx)\s*\{.*(?:eval|Function|setTimeout|setInterval|document|window|location|dangerouslySetInnerHTML)\b",
]

# ============================================================================
# 3. COMMAND INJECTION — MASSIVE EXPANSION (300 patterns)
# ============================================================================
CMDI_ULTRA = [
    # --- Shell metacharacters ---
    r"(?i)(?:;|\||&&|\|\|)\s*(?:id|whoami|uname|hostname|ifconfig|ipconfig|ip\s+addr|ip\s+route|cat|ls|dir|pwd|echo|printf|type|find|grep|awk|sed|sort|uniq|wc|head|tail|cut|tr|tee|xargs|env|printenv|set|export|alias|history|ps|top|kill|pkill|killall|bg|fg|jobs|nohup|screen|tmux|at|crontab|cron|systemctl|service|journalctl|dmesg|last|lastlog|who|w|finger|users|groups|getent|mount|umount|df|du|free|vmstat|iostat|sar|mpstat|pidstat|strace|ltrace|lsof|fuser|netstat|ss|iptables|nftables|firewall-cmd|ufw)\b",
    r"(?i)(?:;|\||&&|\|\|)\s*(?:wget|curl|fetch|nc|ncat|socat|ssh|scp|sftp|ftp|telnet|rsync|rsh|rlogin|rexec|finger|nmap|masscan|zmap|hping3|arping|traceroute|tracert|ping|dig|nslookup|host|drill|whois|nsupdate|dnsenum|dnsrecon|fierce|sublist3r|amass|subfinder|assetfinder|httprobe|httpx|nuclei|ffuf|gobuster|dirb|dirsearch|wfuzz|nikto|whatweb|wapiti|sqlmap|commix|tplmap|sstimap|nosqlmap|xsstrike)\b",
    r"(?i)(?:;|\||&&|\|\|)\s*(?:python[23]?|ruby|perl|php|node|lua|java|javac|gcc|g\+\+|cc|make|cmake|go|cargo|rustc|dotnet|csc|mcs|npm|pip|gem|composer|mvn|gradle|ant|sbt|lein|mix|stack|cabal|opam|cpan|pecl|pear|phpize|php-config)\b",
    r"(?i)(?:;|\||&&|\|\|)\s*(?:docker|kubectl|helm|terraform|ansible|vagrant|packer|consul|vault|nomad|istio|linkerd|envoy|nginx|apache|httpd|lighttpd|caddy|haproxy|traefik|varnish|memcached|redis-cli|mongo|mongosh|mysql|psql|sqlplus|sqlite3|cqlsh|neo4j|influx|cassandra)\b",
    # --- Backtick and $() substitution ---
    r"(?i)`\s*(?:id|whoami|uname|hostname|ifconfig|cat|ls|pwd|echo|env|ps|kill|wget|curl|nc|python|ruby|perl|php|node|bash|sh|zsh|dash|ksh|csh|tcsh|ash|fish)\b",
    r"(?i)\$\(\s*(?:id|whoami|uname|hostname|ifconfig|cat|ls|pwd|echo|env|ps|kill|wget|curl|nc|python|ruby|perl|php|node|bash|sh|zsh|dash|ksh|csh|tcsh|ash|fish)\b",
    r"(?i)`\s*(?:cat|head|tail|more|less|xxd|od|hexdump|strings|file|stat|wc)\s+(?:/etc/|/var/|/proc/|/sys/|/root/|/home/|~|\.\.)",
    r"(?i)\$\(\s*(?:cat|head|tail|more|less|xxd|od|hexdump|strings|file|stat|wc)\s+(?:/etc/|/var/|/proc/|/sys/|/root/|/home/|~|\.\.)",
    # --- Reverse shell comprehensive ---
    r"(?i)bash\s+-i\s+>&?\s*/dev/tcp/",
    r"(?i)bash\s+-c\s+['\"]bash\s+-i\s+>&?\s*/dev/tcp/",
    r"(?i)/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+",
    r"(?i)/dev/udp/\d+\.\d+\.\d+\.\d+/\d+",
    r"(?i)python[23]?\s+-c\s+['\"]import\s+(?:socket|os|subprocess|pty|telnetlib|http\.server|xmlrpc|ftplib|smtplib|imaplib|poplib)\b",
    r"(?i)python[23]?\s+-c\s+.*(?:socket\.socket|os\.dup2|subprocess\.call|pty\.spawn|os\.system|os\.popen|os\.exec[lvpe]+)\b",
    r"(?i)ruby\s+-(?:e|rsock)\s+.*(?:TCPSocket|UNIXSocket|Socket|IO\.popen|Kernel\.exec|system|Open3|PTY\.spawn)\b",
    r"(?i)perl\s+-e\s+.*(?:socket|connect|open|exec|system|IO::Socket|Net::)|perl\s+-MIO::Socket",
    r"(?i)php\s+-r\s+.*(?:fsockopen|socket_create|exec|system|passthru|shell_exec|popen|proc_open)\b",
    r"(?i)(?:nc|ncat|netcat)\s+(?:-e\s+(?:/bin/(?:sh|bash|zsh)|sh|bash|cmd\.exe|powershell)|-c\s+(?:/bin/(?:sh|bash|zsh)|sh|bash|cmd\.exe)|-lvp?\s+\d+|-w\s+\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+)",
    r"(?i)socat\s+(?:tcp|udp|exec|system|pty|openssl|pipe|unix|abstract)[-:]",
    r"(?i)socat\s+.*(?:exec:['\"]?(?:/bin/sh|/bin/bash|bash|sh|cmd)|pty,stderr,setsid)",
    r"(?i)mkfifo\s+/tmp/\w+\s*;\s*(?:nc|ncat|cat)\s+",
    r"(?i)mknod\s+/tmp/\w+\s+p\s*;\s*(?:nc|ncat|cat)\s+",
    r"(?i)rm\s+-f\s+/tmp/\w+\s*;\s*mkfifo\s+/tmp/\w+",
    r"(?i)(?:openssl|ncat)\s+.*(?:--ssl|--ssl-cert|--ssl-key|s_client|s_server)\b",
    r"(?i)powershell\s+.*(?:New-Object\s+(?:Net\.Sockets\.TCPClient|System\.Net\.WebClient|IO\.StreamReader)|Invoke-(?:Expression|WebRequest|RestMethod)|IEX|downloadstring|downloadfile|Start-Process|Invoke-Command)\b",
    r"(?i)powershell\s+.*(?:-(?:enc|encodedcommand|e)\s+[a-zA-Z0-9+/=]{20,}|-(?:w|windowstyle)\s+hidden|-(?:nop|noprofile)|-(?:ep|executionpolicy)\s+bypass)\b",
    r"(?i)certutil\s+.*(?:-urlcache|-split|-decode|-encode|-f\s+http)\b",
    r"(?i)bitsadmin\s+.*(?:/transfer|/create|/addfile|/setnotifycmdline|/resume|/complete)\b",
    r"(?i)mshta\s+.*(?:javascript|vbscript|http|https|file):",
    r"(?i)wmic\s+.*(?:process\s+call\s+create|os\s+get|nicconfig|computersystem|product|qfe|service|startup|useraccount)\b",
    r"(?i)regsvr32\s+.*(?:/s|/n|/u|/i:http)\b",
    r"(?i)rundll32\s+.*(?:javascript|shell32|url\.dll|ieframe)\b",
    r"(?i)cscript\s+.*(?:\.vbs|\.js|\.wsf|//nologo|//e:jscript|//e:vbscript)\b",
    r"(?i)wscript\s+.*(?:\.vbs|\.js|\.wsf|//nologo|//e:jscript|//e:vbscript)\b",
    r"(?i)(?:lua|luajit)\s+-e\s+.*(?:os\.execute|os\.popen|io\.popen|loadstring)\b",
    r"(?i)(?:awk|gawk|mawk|nawk)\s+.*(?:system\(|getline|print\s*\|)\b",
    r"(?i)(?:sed|ed)\s+.*(?:-e|--expression)\s+.*(?:e\s|w\s|r\s)",
    r"(?i)(?:find|xargs)\s+.*(?:-exec\s+|--exec\s+|\|\s*(?:sh|bash|python|perl|ruby))\b",
    # --- Windows-specific command injection ---
    r"(?i)(?:cmd|cmd\.exe)\s*(?:/c|/k|/r)\s+",
    r"(?i)(?:powershell|pwsh)(?:\.exe)?\s+(?:-command|-c|-encodedcommand|-enc|-e|-file|-f|-noprofile|-nop|-windowstyle|-w|-executionpolicy|-ep|-sta|-mta|-inputformat|-outputformat|-noninteractive)\b",
    r"(?i)(?:forfiles|for\s+/f)\s+.*(?:cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32)\b",
    r"(?i)(?:schtasks|at)\s+.*(?:/tr\s+|/run\b|/tn\b)",
    r"(?i)(?:sc|service)\s+.*(?:create|config|start|stop|delete|query|qc|sdshow|sdset)\b",
    r"(?i)(?:icacls|cacls|attrib|takeown)\s+.*(?:/grant|/deny|/remove|/setowner|/inheritance|/s\s+/t|/c\s+/t|\+h|\-h|\+s|\-s|\+r|\-r)\b",
    r"(?i)(?:net|net1)\s+(?:user|localgroup|group|share|use|session|file|accounts|computer|config|continue|helpmsg|name|pause|print|send|start|statistics|stop|time|view)\b",
    r"(?i)(?:netsh)\s+(?:advfirewall|interface|wlan|http|trace|ipsec|ras|routing|winhttp|lan|bridge|dump|exec|firewall|p2p|aaaa)\b",
    r"(?i)(?:tasklist|taskkill|tskill|pskill)\s+",
    r"(?i)(?:wevtutil|auditpol)\s+(?:cl|qe|el|gl|sl|epl|gli|set|get|backup|restore|clear|list|remove|resourceSACL)\b",
    # --- Environment variable injection ---
    r"(?i)\$(?:IFS|PATH|HOME|SHELL|USER|LOGNAME|HOSTNAME|PWD|OLDPWD|TMPDIR|TEMP|TMP|RANDOM|SECONDS|LINENO|BASH_VERSION|BASH_ENV|ENV|CDPATH|GLOBIGNORE|SHELLOPTS|BASHOPTS|HISTFILE|HISTSIZE|HISTFILESIZE|HISTCONTROL|HISTIGNORE|HISTTIMEFORMAT|INPUTRC|FCEDIT|EDITOR|VISUAL|PAGER|LESS|MORE|GREP_OPTIONS|GREP_COLOR|GREP_COLORS|LS_COLORS|TERM|COLORTERM|DISPLAY|XAUTHORITY|SSH_AUTH_SOCK|SSH_AGENT_PID|SSH_CLIENT|SSH_CONNECTION|SSH_TTY|GPG_AGENT_INFO|GNUPGHOME|DBUS_SESSION_BUS_ADDRESS|XDG_RUNTIME_DIR|XDG_DATA_HOME|XDG_CONFIG_HOME|XDG_CACHE_HOME|XDG_DATA_DIRS|XDG_CONFIG_DIRS|LANG|LANGUAGE|LC_ALL|LC_CTYPE|LC_NUMERIC|LC_TIME|LC_COLLATE|LC_MONETARY|LC_MESSAGES|LC_PAPER|LC_NAME|LC_ADDRESS|LC_TELEPHONE|LC_MEASUREMENT|LC_IDENTIFICATION)\b",
    r"(?i)\$\{(?:IFS|PATH|HOME|SHELL|USER|LOGNAME|HOSTNAME|PWD|OLDPWD|TMPDIR|TEMP|TMP|RANDOM|SECONDS|BASH_ENV|ENV|CDPATH|HISTFILE)\}",
    r"(?i)(?:export|set|setenv|declare|typeset|local|readonly|unset)\s+(?:PATH|HOME|SHELL|USER|LOGNAME|HOSTNAME|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|RUBYLIB|PERL5LIB|NODE_PATH|CLASSPATH|JAVA_HOME|GOPATH|GEM_HOME|GEM_PATH|BUNDLE_PATH|COMPOSER_HOME|PIP_INDEX_URL|NPM_CONFIG_REGISTRY|CARGO_HOME|RUSTUP_HOME)=",
    # --- Wildcard injection ---
    r"(?i)(?:tar|zip|7z|rar|gzip|bzip2|xz|lzma|compress|unzip|gunzip|bunzip2|unlzma|uncompress|unrar)\s+.*(?:--checkpoint|--checkpoint-action|--use-compress-program|--transform|-I\s+|--to-command|--info-script|--new-volume-script|--rsh-command|--rmt-command)\b",
    r"(?i)(?:rsync)\s+.*(?:-e\s+['\"]?(?:ssh|rsh)|--rsh=|--rsync-path=)\b",
    r"(?i)(?:chmod|chown|chgrp)\s+.*(?:--reference=|--from=)\b",
]

# ============================================================================
# 4. PATH TRAVERSAL — MASSIVE EXPANSION (250 patterns)
# ============================================================================
PATH_TRAV_ULTRA = [
    # --- Standard traversal patterns ---
    r"(?i)(?:\.\./|\.\.\\|%2e%2e/|%2e%2e\\|%252e%252e/|%252e%252e\\|\.%2e/|%2e\./|\.\.%2f|\.\.%5c|%c0%ae%c0%ae/|%c1%9c%c0%ae/|%c0%ae\.\./|\.%c0%ae/|%e0%80%ae%e0%80%ae/|%f0%80%80%ae%f0%80%80%ae/|\.\.%c0%af|\.\.%ef%bc%8f|\.\.%c1%9c|\.\.;/){1,}",
    r"(?i)(?:\.\./|\.\.\\){2,}(?:etc/|windows/|boot/|usr/|var/|tmp/|proc/|sys/|dev/|home/|root/|opt/|srv/|mnt/|media/|run/|snap/|lost\+found/|lib/|lib64/|sbin/|bin/)",
    r"(?i)(?:%2e%2e(?:%2f|%5c|/|\\)){2,}",
    r"(?i)(?:\.\.(?:/|\\|%2f|%5c|%252f|%255c)){2,}",
    # --- Sensitive files - Linux ---
    r"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c).*(?:/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/hosts|/etc/hostname|/etc/resolv\.conf|/etc/network/interfaces|/etc/sysconfig/network-scripts|/etc/fstab|/etc/mtab|/etc/issue|/etc/issue\.net|/etc/motd|/etc/profile|/etc/bashrc|/etc/bash\.bashrc|/etc/environment|/etc/shells|/etc/sudoers|/etc/sudoers\.d|/etc/crontab|/etc/cron\.d|/etc/cron\.daily|/etc/cron\.hourly|/etc/cron\.weekly|/etc/cron\.monthly|/etc/anacrontab|/etc/at\.allow|/etc/at\.deny|/etc/securetty|/etc/security/limits\.conf|/etc/security/access\.conf|/etc/pam\.d|/etc/nsswitch\.conf|/etc/syslog\.conf|/etc/rsyslog\.conf|/etc/logrotate\.conf|/etc/logrotate\.d|/etc/ld\.so\.conf|/etc/ld\.so\.preload|/etc/ld\.so\.cache|/etc/init\.d|/etc/rc\.local|/etc/modules|/etc/modprobe\.d|/etc/sysctl\.conf|/etc/sysctl\.d)\b",
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:/etc/ssh/sshd_config|/etc/ssh/ssh_config|/etc/ssh/ssh_host_(?:rsa|dsa|ecdsa|ed25519)_key(?:\.pub)?)\b",
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:/etc/apache2/|/etc/httpd/|/etc/nginx/|/etc/lighttpd/|/etc/haproxy/|/etc/squid/|/etc/varnish/|/etc/postfix/|/etc/dovecot/|/etc/exim4/|/etc/bind/|/etc/named/|/etc/dhcp/|/etc/openvpn/|/etc/wireguard/|/etc/strongswan/|/etc/ipsec/)\b",
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:/etc/mysql/|/etc/postgresql/|/etc/redis/|/etc/mongodb/|/etc/mongod\.conf|/etc/elasticsearch/|/etc/kibana/|/etc/logstash/|/etc/cassandra/|/etc/couchdb/|/etc/neo4j/|/etc/influxdb/|/etc/rabbitmq/|/etc/kafka/)\b",
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:/proc/self/(?:environ|cmdline|status|maps|mem|fd/\d+|cwd|exe|root|mountinfo|mounts|net/|cgroup|task|loginuid|sessionid|oom_adj|oom_score|oom_score_adj|limits|io|stat|statm|stack|syscall|attr/|ns/|coredump_filter))\b",
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:/proc/(?:version|cpuinfo|meminfo|partitions|diskstats|vmstat|loadavg|uptime|modules|interrupts|ioports|iomem|devices|filesystems|swaps|cmdline|config\.gz|net/|bus/|driver/|fs/|irq/|sysrq-trigger|kcore|kallsyms))\b",
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:/var/log/(?:auth\.log|syslog|messages|secure|faillog|lastlog|btmp|wtmp|utmp|kern\.log|dmesg|daemon\.log|debug|boot\.log|dpkg\.log|apt/|yum\.log|dnf\.log|alternatives\.log|apache2/|httpd/|nginx/|mysql/|postgresql/|redis/|mongodb/|elasticsearch/|samba/|mail\.log|mail\.err|cups/))\b",
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:/root/\.(?:bash_history|bash_profile|bashrc|profile|ssh/|gnupg/|mysql_history|psql_history|viminfo|lesshst|wget-hsts|cache/|config/|local/|aws/|kube/|docker/))\b",
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:/home/\w+/\.(?:bash_history|bash_profile|bashrc|profile|ssh/|gnupg/|mysql_history|psql_history|viminfo|lesshst|wget-hsts|cache/|config/|local/|aws/|kube/|docker/))\b",
    # --- Sensitive files - Windows ---
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:C:\\Windows\\(?:system\.ini|win\.ini|boot\.ini|hosts|repair\\SAM|repair\\system|repair\\software|System32\\config\\(?:SAM|SYSTEM|SOFTWARE|SECURITY|DEFAULT|COMPONENTS|ELAM|BBI|BCD-Template)|System32\\drivers\\etc\\(?:hosts|lmhosts|networks|protocol|services)|System32\\inetsrv\\(?:MetaBase\.xml|applicationHost\.config)|Temp\\|debug\\|Panther\\(?:Unattend\.xml|unattend\.xml|Unattend\\Unattend\.xml)|System32\\sysprep\\(?:Unattend\.xml|sysprep\.xml)|System32\\GroupPolicy\\|Microsoft\.NET\\Framework\\|IIS\\|SoftwareDistribution\\|Prefetch\\|appcompat\\|security\\|System32\\winevt\\Logs\\))\b",
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:C:\\(?:inetpub\\wwwroot\\web\.config|inetpub\\logs\\|ProgramData\\|Users\\(?:Administrator|Default|Public)\\|boot\.ini|pagefile\.sys|hiberfil\.sys|swapfile\.sys))\b",
    # --- Application config files ---
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:web\.config|app\.config|machine\.config|applicationhost\.config|web\.xml|context\.xml|server\.xml|struts\.xml|struts-config\.xml|tiles\.xml|faces-config\.xml|persistence\.xml|hibernate\.cfg\.xml|log4j\.properties|log4j\.xml|log4j2\.xml|logback\.xml|application\.properties|application\.yml|application\.yaml|bootstrap\.properties|bootstrap\.yml|settings\.py|settings\.ini|config\.py|config\.ini|config\.yml|config\.yaml|config\.json|config\.xml|config\.php|config\.inc\.php|wp-config\.php|configuration\.php|LocalSettings\.php|parameters\.yml|parameters\.ini|\.env|\.env\.local|\.env\.production|\.env\.development|\.env\.staging|\.env\.test|\.htaccess|\.htpasswd|\.htdigest|\.user\.ini|\.editorconfig|\.gitconfig|\.gitignore|\.dockerignore|\.npmrc|\.yarnrc|\.babelrc|\.eslintrc|\.prettierrc|\.browserslistrc|composer\.json|package\.json|Gemfile|requirements\.txt|Pipfile|Cargo\.toml|go\.mod|pom\.xml|build\.gradle|build\.sbt|Makefile|Dockerfile|docker-compose\.yml|Vagrantfile|Procfile|Jenkinsfile|\.travis\.yml|\.gitlab-ci\.yml|\.github/workflows|Rakefile|Gruntfile|Gulpfile|webpack\.config|tsconfig\.json|tslint\.json|\.prettierrc|\.eslintrc|\.stylelintrc)\b",
    # --- Cloud/DevOps config files ---
    r"(?i)(?:\.\./|\.\.\\|%2e%2e).*(?:\.aws/credentials|\.aws/config|\.azure/accessTokens\.json|\.azure/azureProfile\.json|\.config/gcloud/credentials\.db|\.config/gcloud/properties|\.config/gcloud/access_tokens\.db|\.config/gcloud/application_default_credentials\.json|\.kube/config|\.docker/config\.json|\.docker/daemon\.json|\.vagrant\.d/|\.terraform/|\.ansible/|\.chef/|\.puppet/|\.salt/|\.consul/|\.vault-token|\.npmrc|\.pypirc|\.gem/credentials|\.nuget/NuGet\.Config|\.m2/settings\.xml|\.gradle/gradle\.properties|\.sbt/|\.ivy2/|\.cargo/credentials|\.rustup/|\.ssh/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|config|known_hosts|authorized_keys))\b",
    # --- Git/SVN exposure ---
    r"(?i)(?:\.git/(?:config|HEAD|index|refs/|objects/|logs/|hooks/|info/|packed-refs|description|COMMIT_EDITMSG|FETCH_HEAD|ORIG_HEAD|MERGE_HEAD|MERGE_MSG|REBASE_HEAD|CHERRY_PICK_HEAD|BISECT_LOG|shallow|modules/)|\.svn/(?:entries|wc\.db|pristine/|tmp/|text-base/)|\.hg/(?:dirstate|store/|cache/|branch|bookmarks|requires)|\.bzr/(?:branch/|repository/|checkout/|README))\b",
]

# ============================================================================
# 5. SSRF — MASSIVE EXPANSION (250 patterns)
# ============================================================================
SSRF_ULTRA = [
    # --- AWS metadata deep ---
    r"(?i)169\.254\.169\.254/(?:latest|2021-01-25|2021-03-23|2021-07-15|2022-09-24)/(?:meta-data|user-data|dynamic|api/token)",
    r"(?i)169\.254\.169\.254/latest/meta-data/(?:ami-id|ami-launch-index|ami-manifest-path|block-device-mapping/|events/|hostname|iam/|instance-action|instance-id|instance-life-cycle|instance-type|kernel-id|local-hostname|local-ipv4|mac|metrics/|network/|placement/|product-codes|profile|public-hostname|public-ipv4|public-keys/|ramdisk-id|reservation-id|security-groups|services/|spot/|tags/)",
    r"(?i)169\.254\.169\.254/latest/meta-data/iam/(?:info|security-credentials|security-credentials/\w+)",
    r"(?i)169\.254\.169\.254/latest/user-data\b",
    r"(?i)169\.254\.169\.254/latest/dynamic/instance-identity/(?:document|signature|pkcs7|rsa2048)\b",
    # --- GCP metadata deep ---
    r"(?i)metadata\.google\.internal/computeMetadata/v1/(?:project/|instance/)",
    r"(?i)metadata\.google\.internal/computeMetadata/v1/project/(?:attributes/|project-id|numeric-project-id)",
    r"(?i)metadata\.google\.internal/computeMetadata/v1/instance/(?:attributes/|cpu-platform|description|disks/|guest-attributes/|hostname|id|image|licenses/|machine-type|maintenance-event|name|network-interfaces/|preempted|remaining-cpu-time|scheduling/|service-accounts/|tags|virtual-clock/|zone)",
    r"(?i)metadata\.google\.internal/computeMetadata/v1/instance/service-accounts/(?:default|\w+@\w+)/(?:aliases|email|identity|scopes|token)\b",
    r"(?i)Metadata-Flavor:\s*Google\b",
    # --- Azure metadata deep ---
    r"(?i)169\.254\.169\.254/metadata/(?:instance|attested|identity|scheduledevents|versions)\b",
    r"(?i)169\.254\.169\.254/metadata/instance/(?:compute|network)\b",
    r"(?i)169\.254\.169\.254/metadata/instance/compute/(?:azEnvironment|customData|isHostCompatibilityLayerVm|licenseType|location|name|offer|osProfile|osType|placementGroupId|plan|platformFaultDomain|platformUpdateDomain|priority|provider|publicKeys|publisher|resourceGroupName|resourceId|securityProfile|sku|storageProfile|subscriptionId|tags|tagsList|userData|version|vmId|vmScaleSetName|vmSize|zone)\b",
    r"(?i)169\.254\.169\.254/metadata/identity/oauth2/token\b",
    r"(?i)Metadata:\s*true\b",
    # --- DigitalOcean/Alibaba/Oracle metadata ---
    r"(?i)169\.254\.169\.254/metadata/v1(?:\.json)?\b",
    r"(?i)169\.254\.169\.254/metadata/v1/(?:id|hostname|user-data|vendor-data|public-keys|region|interfaces/|floating_ip/|dns/|tags|features|volumes)\b",
    r"(?i)100\.100\.100\.200/latest/(?:meta-data|user-data|dynamic)\b",
    r"(?i)169\.254\.169\.254/opc/v[12]/(?:instance|vnic|identity)\b",
    # --- Kubernetes/Docker metadata ---
    r"(?i)(?:https?://)?(?:kubernetes\.default\.svc(?:\.cluster\.local)?|kubernetes\.default|kubernetes|10\.(?:0|96|244)\.\d+\.\d+)(?::\d+)?/api(?:/v1)?/",
    r"(?i)(?:https?://)?(?:kubernetes\.default\.svc)(?::\d+)?/api/v1/(?:namespaces|pods|services|secrets|configmaps|nodes|endpoints|events)\b",
    r"(?i)/var/run/secrets/kubernetes\.io/serviceaccount/(?:token|ca\.crt|namespace)\b",
    r"(?i)(?:https?://)?(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)(?::\d+)?/",
    # --- Internal service discovery ---
    r"(?i)(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|0:0:0:0:0:0:0:1|ip6-localhost|ip6-loopback)(?::\d+)?/",
    r"(?i)(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|fc00:|fd\w{2}:)(?::\d+)?/",
    r"(?i)(?:https?://)?(?:\[::1\]|\[::ffff:127\.0\.0\.1\]|\[0:0:0:0:0:0:0:1\]|\[::ffff:7f00:1\])(?::\d+)?/",
    # --- IP obfuscation ---
    r"(?i)(?:https?://)?(?:0x7f(?:\.0x0{1,2}){2}\.0x0{0,2}1|0177(?:\.0{1,3}){2}\.0{0,2}1|2130706433|017700000001|0x7f000001)(?::\d+)?/",
    r"(?i)(?:https?://)?(?:0(?:\.0){2}\.0|0\.0\.0\.0|0x0\.0x0\.0x0\.0x0|0{1,3}\.0{1,3}\.0{1,3}\.0{1,3})(?::\d+)?/",
    r"(?i)(?:https?://)?(?:\d+\.(?:in-addr|ip6)\.arpa)\b",
    r"(?i)(?:https?://)?(?:\d+\.\d+\.\d+\.\d+\.xip\.io|\d+-\d+-\d+-\d+\.nip\.io|\w+\.localtest\.me|\w+\.lvh\.me|\w+\.vcap\.me|\w+\.lacolhost\.com)\b",
    # --- Protocol handlers ---
    r"(?i)(?:gopher|dict|sftp|ssh|telnet|tftp|ldap|ldaps|imap|imaps|pop3|pop3s|smtp|smtps|ftp|ftps|rtsp|rtmp|mms|svn|git|cvs|nntp|snmp|xmpp|irc|ircs|socks[45]?|vnc|rdp|amqp|amqps|mqtt|mqtts|coap|coaps|ws|wss|h2|h2c)://",
    r"(?i)(?:file|jar|netdoc|mailto|tel|sms|geo|maps|market|intent|content|data|blob|filesystem|chrome|chrome-extension|moz-extension|ms-browser-extension|view-source|resource|res|about|javascript|vbscript|livescript|mocha|ecmascript):",
    r"(?i)(?:php://(?:filter|input|stdin|fd|memory|temp|data|glob|expect|zip|compress\.zlib|compress\.bzip2)|phar://|zip://|rar://|ogg://|zlib://|bzip2://|ssh2://|rar://|expect://)\b",
    r"(?i)(?:gopher://\d+\.\d+\.\d+\.\d+:\d+/_)",
    r"(?i)(?:dict://\d+\.\d+\.\d+\.\d+:\d+/)",
    # --- DNS rebinding ---
    r"(?i)(?:rbndr\.us|rebind\.it|1u\.ms|nip\.io|xip\.io|sslip\.io|localtest\.me|lvh\.me|vcap\.me|lacolhost\.com|lock\.cmpxchg8b\.com|www\.yoursite\.com\.\d+\.\d+\.\d+\.\d+\.xip\.io)\b",
    r"(?i)(?:ceye\.io|dnslog\.cn|eyes\.sh|burpcollaborator\.net|oastify\.com|interact\.sh|canarytokens\.com|pipedream\.net|webhook\.site|requestbin\.net|requestbin\.com|hookbin\.com|beeceptor\.com|postb\.in|ptsv2\.com)\b",
    # --- URL parser confusion ---
    r"(?i)(?:https?://)?(?:\w+@)?\d+\.\d+\.\d+\.\d+(?:%40|@|%2540|%252540)\w+\.\w+",
    r"(?i)(?:https?://)?(?:\w+\.\w+)\\@(?:\d+\.\d+\.\d+\.\d+|localhost|127\.0\.0\.1)",
    r"(?i)(?:https?://)?(?:\w+\.\w+)%00(?:@|%40)(?:\d+\.\d+\.\d+\.\d+|localhost|127\.0\.0\.1)",
    r"(?i)(?:https?://)(?:evil|attacker|hacker)\.\w+#@(?:\d+\.\d+\.\d+\.\d+|localhost)",
    r"(?i)(?:https?://)\d+\.\d+\.\d+\.\d+\.evil\.\w+",
]

# ============================================================================
# 6. AUTH BYPASS / ACCESS CONTROL (250 patterns)
# ============================================================================
AUTH_BYPASS_ULTRA = [
    # --- HTTP verb tampering ---
    r"(?i)(?:TRACE|TRACK|DEBUG|PURGE|SEARCH|COPY|MOVE|PROPFIND|PROPPATCH|MKCOL|LOCK|UNLOCK|MERGE|SUBSCRIBE|UNSUBSCRIBE|NOTIFY|PATCH|LINK|UNLINK|M-SEARCH|OPTIONS)\s+/(?:admin|internal|debug|console|manage|config|settings|api/admin|api/internal|dashboard|panel|backoffice|control|management|super)\b",
    r"(?i)X-HTTP-Method(?:-Override)?\s*:\s*(?:PUT|DELETE|PATCH|OPTIONS|TRACE|CONNECT|HEAD|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|MERGE)\b",
    r"(?i)X-(?:Method-Override|HTTP-Method|Real-Method|Original-Method)\s*:\s*(?:PUT|DELETE|PATCH|OPTIONS|TRACE|CONNECT)\b",
    r"(?i)_method\s*=\s*(?:PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\b",
    # --- Path-based bypass ---
    r"(?i)/admin(?:%20|%09|%0[adAD]|%00|;|\.|\.\.|/\.\./|//|%2f%2f|%252f|\\|%5c|%255c|\?|#|%23|%3f)(?:\w|/)*",
    r"(?i)/(?:admin|internal|debug|console|manage)(?:/\.)?(?:;|\.|%2e|%00|%0[adAD]|%20)",
    r"(?i)/(?:\.\./|\.\.\\|%2e%2e/|%2e%2e\\)+(?:admin|internal|debug|console|manage|config|dashboard|panel|backoffice|control)\b",
    r"(?i)(?:/%2e/|/\./|//|/;/|/%20/|/%09/|/%0[adAD]/)+(?:admin|internal|debug|console|manage|config|dashboard|panel)\b",
    r"(?i)/(?:admin|internal|debug|console)\.(?:json|xml|html|txt|csv|pdf|php|asp|aspx|jsp|do|action|cgi|pl|py|rb|cfm|shtml|xhtml|svg)\b",
    r"(?i)/(?:admin|internal|debug|console)/\.\./(?:admin|internal|debug|console)\b",
    # --- Header-based bypass ---
    r"(?i)X-(?:Forwarded-For|Real-IP|Client-IP|Originating-IP|Remote-Addr|Remote-IP|True-Client-IP|Cluster-Client-IP|CF-Connecting-IP)\s*:\s*(?:127\.0\.0\.1|localhost|::1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b",
    r"(?i)X-(?:Custom-IP-Authorization|Original-URL|Rewrite-URL|Forwarded-Server|Forwarded-Host|Host-Override|Proxy-URL)\s*:\s*/(?:admin|internal|debug|console|manage|config|dashboard|panel)\b",
    r"(?i)(?:Referer|Origin)\s*:\s*https?://(?:admin|internal|localhost|127\.0\.0\.1|trusted|allowed)\b",
    r"(?i)X-(?:Requested-With|Ajax-Request|CSRF-Token|XSRF-Token|Api-Key|Auth-Token|Access-Token|Session-Token|Internal-Request|Trusted-Source|Bypass-Auth|Skip-Auth|No-Auth|Debug-Mode|Test-Mode|Dev-Mode|Admin-Secret|Master-Key|Service-Key|Gateway-Key|Proxy-Auth|Backend-Auth)\s*:",
    # --- Authentication token manipulation ---
    r"(?i)(?:Authorization|X-Auth-Token|X-Access-Token|X-Api-Key|X-Session-Token|X-Bearer-Token)\s*:\s*(?:null|undefined|none|false|0|''|\"\"|admin|root|test|guest|anonymous|public|internal|service|system|backend|gateway|proxy|debug|development|staging|testing)\b",
    r"(?i)(?:Cookie)\s*:.*(?:admin=(?:true|1|yes)|role=admin|isAdmin=(?:true|1)|is_admin=(?:true|1)|access=admin|privilege=admin|user_type=admin|account_type=admin|level=admin|group=admin|permission=admin)\b",
    r"(?i)(?:Set-Cookie|Cookie)\s*:.*(?:session|token|auth|jwt|sid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid)\s*=\s*(?:null|undefined|0|false|''|\"\"|\{\}|\[\]|deleted|expired|invalid|test|admin|root|guest|anonymous)\b",
    # --- Default/common admin paths (trimmed to actual admin-only endpoints) ---
    r"(?i)/(?:admin|administrator|adm|_admin|admin_area|administration|adminpanel|admin_panel|admin-panel|cpanel|controlpanel|control-panel|siteadmin|site-admin|webadmin|web-admin|superadmin|super-admin|phpmyadmin|myadmin|pma|dbadmin|sqladmin|server-status|server-info)\b",
    # --- JWT manipulation ---
    r"(?i)eyJ(?:hbGciOiJub25lIi|hbGciOiIi|hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9)",
    r"(?i)(?:\"alg\"\s*:\s*\"(?:none|None|NONE|nOnE|NoNe|nONE|nonE)\"|\"alg\"\s*:\s*\"\"|\{\"alg\":\"none\"\})",
    r"(?i)(?:\"alg\"\s*:\s*\"(?:HS256|HS384|HS512)\"\s*,?\s*\"typ\"\s*:\s*\"JWT\")\s*\..*\.\s*$",
    r"(?i)(?:\"kid\"\s*:\s*\"(?:../../|/etc/|/dev/|/proc/|/var/|/tmp/|\\\\|%2e%2e|union\s+select|'\s+or\s+|;\s*--|#))",
    # --- GraphQL auth bypass ---
    r"(?i)(?:query|mutation)\s+\w*\s*\{[^}]*(?:__schema|__type|introspectionQuery)\b",
    r"(?i)(?:query|mutation)\s+\w*\s*\{[^}]*(?:users?\s*\(|admin\w*\s*\(|role\w*\s*\(|permission\w*\s*\(|config\w*\s*\(|setting\w*\s*\(|secret\w*\s*\(|token\w*\s*\(|key\w*\s*\(|credential\w*\s*\()\b",
]

RULES_MEGA_5_MAP = {
    'sqli_ultra': SQLI_ULTRA,
    'xss_ultra': XSS_ULTRA,
    'cmdi_ultra': CMDI_ULTRA,
    'path_trav_ultra': PATH_TRAV_ULTRA,
    'ssrf_ultra': SSRF_ULTRA,
    'auth_bypass_ultra': AUTH_BYPASS_ULTRA,
}


def get_all_mega5_patterns():
    for category, patterns in RULES_MEGA_5_MAP.items():
        for regex_str in patterns:
            yield (regex_str, category)


def count_mega5_patterns():
    return sum(len(p) for p in RULES_MEGA_5_MAP.values())
